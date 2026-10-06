// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"errors"
	"maps"
	"sync"
	"time"

	"go.uber.org/zap"
)

// maxPendingRoundTrips bounds the round trips awaiting the server's reply. When it is reached the
// client is not read until the server catches up, so no query goes unrecorded.
const maxPendingRoundTrips = 1024

var errAuditClosed = errors.New("audit tracker closed")

// sessionContext carries session-level PostgreSQL metadata for audit logging.
type sessionContext struct {
	id       string
	target   string
	database string
	dbUser   string
}

func (s *sessionContext) fields(extra map[string]any) map[string]any {
	m := map[string]any{
		"session_id": s.id,
		"target":     s.target,
	}

	// The database and user are unknown until the client's startup message is accepted.
	if s.database != "" {
		m["database"] = s.database
	}

	if s.dbUser != "" {
		m["user"] = s.dbUser
	}

	maps.Copy(m, extra)

	return m
}

// roundTrip is the client's work between two ReadyForQuery messages from the server: one simple
// query, function call, or batch of extended-protocol messages ended by Sync.
type roundTrip struct {
	start       time.Time
	statements  []string
	truncated   bool
	commandTags []string
	err         map[string]any
}

// auditTracker pairs the statements the client sends with the server's results, and logs one
// audit record per round trip when the server reports it is ready for the next one. Because the
// server answers in order, the replies always belong to the oldest pending round trip.
//
// Methods that start round trips are called only by the goroutine reading from the client;
// methods that record results only by the goroutine reading from the server.
type auditTracker struct {
	mu     sync.Mutex
	cond   *sync.Cond
	closed bool

	pending []*roundTrip

	// open is the extended-protocol round trip still accepting statements, until the client's
	// Sync; it is also the newest element of pending.
	open *roundTrip

	// flushServer sends the client's buffered messages to the server before waiting for the
	// server to catch up, which it cannot do until it has them.
	flushServer func() error

	logged  int
	session *sessionContext
	logger  *zap.Logger
	now     func() time.Time
}

func newAuditTracker(session *sessionContext, logger *zap.Logger, flushServer func() error) *auditTracker {
	a := &auditTracker{
		flushServer: flushServer,
		session:     session,
		logger:      logger,
		now:         time.Now,
	}
	a.cond = sync.NewCond(&a.mu)

	return a
}

// simpleQuery starts the round trip for a simple Query message.
func (a *auditTracker) simpleQuery(text string, truncated bool) error {
	return a.push(&roundTrip{statements: []string{text}, truncated: truncated})
}

// functionCall starts the round trip for a FunctionCall message.
func (a *auditTracker) functionCall(text string) error {
	return a.push(&roundTrip{statements: []string{text}})
}

// extendedMessage notes an extended-protocol message, opening a round trip if none is open so the
// server's replies to it are attributed correctly.
func (a *auditTracker) extendedMessage() error {
	_, err := a.openRoundTrip()

	return err
}

func (a *auditTracker) openRoundTrip() (*roundTrip, error) {
	a.mu.Lock()
	open := a.open
	a.mu.Unlock()

	if open != nil {
		return open, nil
	}

	rt := &roundTrip{}
	if err := a.push(rt); err != nil {
		return nil, err
	}

	a.mu.Lock()
	a.open = rt
	a.mu.Unlock()

	return rt, nil
}

// extendedStatement records a statement the client executes in the open round trip.
func (a *auditTracker) extendedStatement(text string, truncated bool) error {
	rt, err := a.openRoundTrip()
	if err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	rt.statements = append(rt.statements, text)
	rt.truncated = rt.truncated || truncated

	return nil
}

// sync ends the open round trip, or starts an empty one: the server replies to every Sync with
// ReadyForQuery.
func (a *auditTracker) sync() error {
	if err := a.extendedMessage(); err != nil {
		return err
	}

	a.mu.Lock()
	a.open = nil
	a.mu.Unlock()

	return nil
}

func (a *auditTracker) push(rt *roundTrip) error {
	a.mu.Lock()
	full := len(a.pending) >= maxPendingRoundTrips
	a.mu.Unlock()

	if full {
		if err := a.flushServer(); err != nil {
			return err
		}
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	for len(a.pending) >= maxPendingRoundTrips && !a.closed {
		a.cond.Wait()
	}

	if a.closed {
		return errAuditClosed
	}

	rt.start = a.now()
	a.pending = append(a.pending, rt)

	return nil
}

// commandComplete records a statement's completion tag, e.g. "SELECT 5".
func (a *auditTracker) commandComplete(tag string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.pending) > 0 {
		a.pending[0].commandTags = append(a.pending[0].commandTags, tag)
	}
}

// errorResponse records the error the server reported for the current round trip.
func (a *auditTracker) errorResponse(fields map[string]any) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.pending) > 0 && a.pending[0].err == nil {
		a.pending[0].err = fields
	}
}

// readyForQuery ends the oldest round trip and logs it.
func (a *auditTracker) readyForQuery(txStatus byte) {
	a.mu.Lock()

	if a.closed {
		// The session is over and its unanswered round trips were already logged.
		a.mu.Unlock()

		return
	}

	if len(a.pending) == 0 {
		a.mu.Unlock()
		a.logger.Warn("Postgres ReadyForQuery without a pending round trip", zap.Any("postgres", a.session.fields(nil)))

		return
	}

	rt := a.pending[0]
	a.pending[0] = nil
	a.pending = a.pending[1:]

	if rt == a.open {
		a.open = nil
	}

	a.cond.Broadcast()
	a.mu.Unlock()

	// Nothing ran: e.g. a Sync after only Parse and Describe.
	if len(rt.statements) == 0 && rt.err == nil {
		return
	}

	a.log(rt, txStatus)
}

// log records a round trip. A zero txStatus means the server never answered it.
func (a *auditTracker) log(rt *roundTrip, txStatus byte) {
	extra := map[string]any{
		"statements":   rt.statements,
		"command_tags": rt.commandTags,
		"duration_ms":  float64(a.now().Sub(rt.start).Microseconds()) / 1000,
	}

	if txStatus == 0 {
		extra["unanswered"] = true
	} else {
		extra["tx_status"] = string(txStatus)
	}

	if rt.truncated {
		extra["truncated"] = true
	}

	if rt.err != nil {
		extra["error"] = rt.err
	}

	a.mu.Lock()
	a.logged++
	a.mu.Unlock()

	a.logger.Info("Postgres query", zap.Any("postgres", a.session.fields(extra)))
}

// close logs the round trips the server never answered and releases a client reader waiting for
// space.
func (a *auditTracker) close() {
	a.mu.Lock()
	a.closed = true
	unanswered := a.pending
	a.pending = nil
	a.open = nil
	a.cond.Broadcast()
	a.mu.Unlock()

	// The session ended before the server finished these, so their outcome is unknown.
	for _, rt := range unanswered {
		if len(rt.statements) > 0 {
			a.log(rt, 0)
		}
	}
}

// queriesLogged returns how many round trips have been logged.
func (a *auditTracker) queriesLogged() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.logged
}

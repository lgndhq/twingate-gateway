// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Message types the relay inspects. Every message is forwarded byte for byte; the relay reads only
// enough of these to audit the session.
const (
	// Client to server.
	msgQuery        = 'Q'
	msgParse        = 'P'
	msgBind         = 'B'
	msgExecute      = 'E'
	msgDescribe     = 'D'
	msgClose        = 'C'
	msgSync         = 'S'
	msgFunctionCall = 'F'
	msgTerminate    = 'X'

	// Server to client.
	msgCommandComplete = 'C'
	msgErrorResponse   = 'E'
	msgReadyForQuery   = 'Z'
)

const (
	messageHeaderLen = 5

	// maxNameLen bounds how much of a statement or portal name the relay reads, well above the
	// server's 63-byte limit on identifiers.
	maxNameLen = 256

	// maxErrorResponseLen bounds how much of an ErrorResponse the relay reads for the audit log.
	maxErrorResponseLen = 4096

	// maxPreparedStatements bounds the named statements remembered per session, so a statement
	// executed by name can be logged with its text.
	maxPreparedStatements = 1024

	unknownStatementText = "<unknown prepared statement>"
)

// statement is the recorded text of a prepared statement.
type statement struct {
	text      string
	truncated bool
}

var unknownStatement = statement{text: unknownStatementText}

var errInvalidMessageLength = errors.New("invalid message length")

// readHeader reads a message's type and the length of its body.
func readHeader(r io.Reader) (byte, int64, error) {
	var header [messageHeaderLen]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, 0, err
	}

	// The length includes itself but not the type byte.
	length := binary.BigEndian.Uint32(header[1:])
	if length < 4 {
		return 0, 0, fmt.Errorf("%w: %d", errInvalidMessageLength, length)
	}

	return header[0], int64(length) - 4, nil
}

// message is a message being relayed: its header, plus the start of its body read for
// inspection.
type message struct {
	typ     byte
	bodyLen int64
	prefix  []byte
}

// readMessageStart reads a message's header and up to prefixLen bytes of its body. The rest of the
// body is left unread for forward to stream.
func readMessageStart(r io.Reader, prefixLen int) (*message, error) {
	typ, bodyLen, err := readHeader(r)
	if err != nil {
		return nil, err
	}

	prefix := make([]byte, min(int64(prefixLen), bodyLen))
	if _, err := io.ReadFull(r, prefix); err != nil {
		return nil, err
	}

	return &message{typ: typ, bodyLen: bodyLen, prefix: prefix}, nil
}

// complete reports whether the prefix holds the whole body.
func (m *message) complete() bool {
	return int64(len(m.prefix)) == m.bodyLen
}

// forward writes the message to w, streaming the unread rest of its body from r.
func (m *message) forward(r io.Reader, w io.Writer) error {
	var header [messageHeaderLen]byte

	header[0] = m.typ
	binary.BigEndian.PutUint32(header[1:], uint32(m.bodyLen+4)) //nolint:gosec // bodyLen was read from a uint32 length

	if _, err := w.Write(header[:]); err != nil {
		return err
	}

	if _, err := w.Write(m.prefix); err != nil {
		return err
	}

	_, err := io.CopyN(w, r, m.bodyLen-int64(len(m.prefix)))

	return err
}

// statementText returns a statement's text from b, cut to maxLen bytes, and whether it was cut.
// partial means b is only the start of the message, so text without a terminator was cut.
func statementText(b []byte, partial bool, maxLen int) (string, bool) {
	text, _, terminated := bytes.Cut(b, []byte{0})

	truncated := partial && !terminated
	if len(text) > maxLen {
		text, truncated = text[:maxLen], true
	}

	if truncated {
		// Don't end on a partial UTF-8 sequence.
		for len(text) > 0 && !utf8.Valid(text) {
			text = text[:len(text)-1]
		}
	}

	return strings.ToValidUTF8(string(text), "�"), truncated
}

// cString splits a NUL-terminated string off the front of b, returning ok false if b has no
// terminator.
func cString(b []byte) (string, []byte, bool) {
	s, rest, ok := bytes.Cut(b, []byte{0})
	if !ok {
		return "", nil, false
	}

	return string(s), rest, true
}

// clientRelay forwards the client's messages to the server, recording the statements it runs.
type clientRelay struct {
	r      *bufio.Reader
	w      *bufio.Writer
	audit  *auditTracker
	maxLen int

	// prepared maps statement names to their text, and portals maps portal names to the statement
	// bound to them. The unnamed statement and portal use the empty name.
	prepared map[string]statement
	portals  map[string]statement
}

func newClientRelay(r *bufio.Reader, w *bufio.Writer, audit *auditTracker, maxLen int) *clientRelay {
	return &clientRelay{
		r:        r,
		w:        w,
		audit:    audit,
		maxLen:   maxLen,
		prepared: make(map[string]statement),
		portals:  make(map[string]statement),
	}
}

// run relays until the client terminates the session or either side fails.
func (c *clientRelay) run() error {
	for {
		typ, err := c.r.Peek(1)
		if err != nil {
			return err
		}

		msg, err := readMessageStart(c.r, c.prefixLen(typ[0]))
		if err != nil {
			return err
		}

		// Record the message before forwarding it, so it is pending before the server can reply.
		if err := c.record(msg); err != nil {
			return err
		}

		if err := msg.forward(c.r, c.w); err != nil {
			return err
		}

		if msg.typ == msgTerminate {
			return c.w.Flush()
		}

		// Flush once the client has nothing more buffered, batching its pipelined messages.
		if c.r.Buffered() == 0 {
			if err := c.w.Flush(); err != nil {
				return err
			}
		}
	}
}

func (c *clientRelay) prefixLen(typ byte) int {
	switch typ {
	case msgQuery:
		return c.maxLen + 1
	case msgParse:
		return maxNameLen + c.maxLen + 1
	case msgBind:
		return 2 * maxNameLen
	case msgExecute, msgDescribe, msgClose:
		return maxNameLen + 1
	case msgFunctionCall:
		return 4
	default:
		return 0
	}
}

func (c *clientRelay) record(msg *message) error {
	partial := !msg.complete()

	switch msg.typ {
	case msgQuery:
		text, truncated := statementText(msg.prefix, partial, c.maxLen)

		return c.audit.simpleQuery(text, truncated)
	case msgParse:
		if name, rest, ok := cString(msg.prefix); ok {
			text, truncated := statementText(rest, partial, c.maxLen)
			c.remember(name, statement{text: text, truncated: truncated})
		}

		return c.audit.extendedMessage()
	case msgBind:
		portal, rest, portalOK := cString(msg.prefix)
		stmtName, _, stmtNameOK := cString(rest)

		if portalOK && stmtNameOK {
			c.portals[portal] = c.preparedStatement(stmtName)
		}

		return c.audit.extendedMessage()
	case msgExecute:
		stmt := unknownStatement

		if portal, _, ok := cString(msg.prefix); ok {
			if bound, found := c.portals[portal]; found {
				stmt = bound
			}
		}

		return c.audit.extendedStatement(stmt.text, stmt.truncated)
	case msgClose:
		if len(msg.prefix) > 0 {
			if name, _, ok := cString(msg.prefix[1:]); ok {
				c.forget(msg.prefix[0], name)
			}
		}

		return c.audit.extendedMessage()
	case msgDescribe:
		return c.audit.extendedMessage()
	case msgSync:
		return c.audit.sync()
	case msgFunctionCall:
		text := "<function call>"
		if len(msg.prefix) == 4 {
			text = "<function call " + strconv.FormatUint(uint64(binary.BigEndian.Uint32(msg.prefix)), 10) + ">"
		}

		return c.audit.functionCall(text)
	default:
		return nil
	}
}

func (c *clientRelay) preparedStatement(name string) statement {
	if stmt, ok := c.prepared[name]; ok {
		return stmt
	}

	return unknownStatement
}

func (c *clientRelay) remember(name string, stmt statement) {
	if _, exists := c.prepared[name]; !exists && name != "" && len(c.prepared) >= maxPreparedStatements {
		// Executions of this statement are logged as unknown rather than growing without bound.
		return
	}

	c.prepared[name] = stmt
}

// forget drops a closed statement ('S') or portal ('P').
func (c *clientRelay) forget(kind byte, name string) {
	switch kind {
	case 'S':
		delete(c.prepared, name)
	case 'P':
		delete(c.portals, name)
	default:
		// The server rejects any other kind.
	}
}

// serverRelay forwards the server's messages to the client, recording each round trip's outcome.
type serverRelay struct {
	r     *bufio.Reader
	w     *bufio.Writer
	audit *auditTracker
}

// run relays until either side fails or closes.
func (s *serverRelay) run() error {
	for {
		typ, err := s.r.Peek(1)
		if err != nil {
			return err
		}

		msg, err := readMessageStart(s.r, serverPrefixLen(typ[0]))
		if err != nil {
			return err
		}

		if err := msg.forward(s.r, s.w); err != nil {
			return err
		}

		s.record(msg)

		if s.r.Buffered() == 0 {
			if err := s.w.Flush(); err != nil {
				return err
			}
		}
	}
}

func serverPrefixLen(typ byte) int {
	switch typ {
	case msgCommandComplete:
		return maxNameLen
	case msgErrorResponse:
		return maxErrorResponseLen
	case msgReadyForQuery:
		return 1
	default:
		return 0
	}
}

func (s *serverRelay) record(msg *message) {
	switch msg.typ {
	case msgCommandComplete:
		if tag, _, ok := cString(msg.prefix); ok {
			s.audit.commandComplete(tag)
		}
	case msgErrorResponse:
		s.audit.errorResponse(parseErrorFields(msg.prefix))
	case msgReadyForQuery:
		if len(msg.prefix) == 1 {
			s.audit.readyForQuery(msg.prefix[0])
		}
	default:
		// Rows, notices, and other messages pass through unrecorded.
	}
}

// parseErrorFields extracts the audited fields of an ErrorResponse body.
func parseErrorFields(b []byte) map[string]any {
	fields := make(map[string]any)

	for len(b) > 0 && b[0] != 0 {
		code := b[0]

		value, rest, ok := cString(b[1:])
		if !ok {
			break
		}

		switch code {
		case 'V':
			fields["severity"] = value
		case 'C':
			fields["code"] = value
		case 'M':
			fields["message"] = value
		default:
			// Detail, hint, and position fields are not audited.
		}

		b = rest
	}

	return fields
}

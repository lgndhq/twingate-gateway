// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func newTestAuditTracker(t *testing.T, flushServer func() error) (*auditTracker, *observer.ObservedLogs) {
	t.Helper()

	core, logs := observer.New(zapcore.DebugLevel)
	session := &sessionContext{id: "session-1", target: "db:5432", database: testDatabase, dbUser: testUser}

	if flushServer == nil {
		flushServer = func() error { return nil }
	}

	return newAuditTracker(session, zap.New(core), flushServer), logs
}

func TestAuditTracker_PairsRepliesWithRoundTrips(t *testing.T) {
	audit, logs := newTestAuditTracker(t, nil)

	// The client pipelines a simple query and an extended batch before the server replies.
	require.NoError(t, audit.simpleQuery("select 1; select 2", false))
	require.NoError(t, audit.extendedMessage()) // Parse
	require.NoError(t, audit.extendedMessage()) // Bind
	require.NoError(t, audit.extendedStatement("insert into t values ($1)", false))
	require.NoError(t, audit.extendedStatement("update t set x = 1", true))
	require.NoError(t, audit.sync())

	audit.commandComplete("SELECT 1")
	audit.commandComplete("SELECT 1")
	audit.readyForQuery('I')

	audit.commandComplete("INSERT 0 1")
	audit.errorResponse(map[string]any{"code": "23505"})
	audit.readyForQuery('E')

	records := queryLogs(logs)
	require.Len(t, records, 2)

	assert.Equal(t, []string{"select 1; select 2"}, records[0]["statements"])
	assert.Equal(t, []string{"SELECT 1", "SELECT 1"}, records[0]["command_tags"])
	assert.Equal(t, "I", records[0]["tx_status"])
	assert.NotContains(t, records[0], "truncated")
	assert.Equal(t, "session-1", records[0]["session_id"])

	assert.Equal(t, []string{"insert into t values ($1)", "update t set x = 1"}, records[1]["statements"])
	assert.Equal(t, []string{"INSERT 0 1"}, records[1]["command_tags"])
	assert.Equal(t, map[string]any{"code": "23505"}, records[1]["error"])
	assert.Equal(t, "E", records[1]["tx_status"])
	assert.Equal(t, true, records[1]["truncated"])

	assert.Equal(t, 2, audit.queriesLogged())
}

func TestAuditTracker_SkipsRoundTripsThatRunNothing(t *testing.T) {
	audit, logs := newTestAuditTracker(t, nil)

	// Prepare: Parse, Describe, Sync.
	require.NoError(t, audit.extendedMessage())
	require.NoError(t, audit.extendedMessage())
	require.NoError(t, audit.sync())

	// A Sync on its own.
	require.NoError(t, audit.sync())

	audit.readyForQuery('I')
	audit.readyForQuery('I')

	assert.Empty(t, queryLogs(logs))
}

func TestAuditTracker_ResultsBeforeSyncAttachToOpenRoundTrip(t *testing.T) {
	audit, logs := newTestAuditTracker(t, nil)

	// The client executes then sends Flush, so the server replies before the Sync.
	require.NoError(t, audit.extendedStatement("select 1", false))
	audit.commandComplete("SELECT 1")
	require.NoError(t, audit.extendedStatement("select 2", false))
	audit.commandComplete("SELECT 1")
	require.NoError(t, audit.sync())
	audit.readyForQuery('I')

	records := queryLogs(logs)
	require.Len(t, records, 1)
	assert.Equal(t, []string{"select 1", "select 2"}, records[0]["statements"])
	assert.Equal(t, []string{"SELECT 1", "SELECT 1"}, records[0]["command_tags"])
}

func TestAuditTracker_UnexpectedReadyForQuery(t *testing.T) {
	audit, logs := newTestAuditTracker(t, nil)

	audit.readyForQuery('I')

	assert.Equal(t, 1, logs.FilterMessage("Postgres ReadyForQuery without a pending round trip").Len())
}

func TestAuditTracker_CloseLogsUnansweredRoundTrips(t *testing.T) {
	audit, logs := newTestAuditTracker(t, nil)

	require.NoError(t, audit.simpleQuery("select pg_sleep(60)", false))
	require.NoError(t, audit.sync())

	audit.close()

	// Replies after the session ends are ignored, and no more round trips start.
	audit.readyForQuery('I')
	require.ErrorIs(t, audit.simpleQuery("select 1", false), errAuditClosed)

	records := queryLogs(logs)
	require.Len(t, records, 1)
	assert.Equal(t, []string{"select pg_sleep(60)"}, records[0]["statements"])
	assert.Equal(t, true, records[0]["unanswered"])
	assert.NotContains(t, records[0], "tx_status")
}

func TestAuditTracker_Backpressure(t *testing.T) {
	flushes := make(chan struct{}, 1)
	audit, logs := newTestAuditTracker(t, func() error {
		flushes <- struct{}{}

		return nil
	})

	for range maxPendingRoundTrips {
		require.NoError(t, audit.simpleQuery("select 1", false))
	}

	pushed := make(chan error, 1)

	go func() {
		pushed <- audit.simpleQuery("select 2", false)
	}()

	// The tracker sends the client's messages to the server before waiting for its replies.
	select {
	case <-flushes:
	case <-time.After(testTimeout):
		t.Fatal("the server was not flushed before waiting")
	}

	select {
	case err := <-pushed:
		t.Fatalf("round trip started while the tracker was full: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	audit.readyForQuery('I')

	select {
	case err := <-pushed:
		require.NoError(t, err)
	case <-time.After(testTimeout):
		t.Fatal("round trip did not start once the server replied")
	}

	assert.Len(t, queryLogs(logs), 1)
}

func TestAuditTracker_CloseReleasesWaitingClient(t *testing.T) {
	audit, _ := newTestAuditTracker(t, nil)

	for range maxPendingRoundTrips {
		require.NoError(t, audit.simpleQuery("select 1", false))
	}

	pushed := make(chan error, 1)

	go func() {
		pushed <- audit.simpleQuery("select 2", false)
	}()

	time.Sleep(10 * time.Millisecond)
	audit.close()

	select {
	case err := <-pushed:
		require.ErrorIs(t, err, errAuditClosed)
	case <-time.After(testTimeout):
		t.Fatal("close did not release the waiting client")
	}
}

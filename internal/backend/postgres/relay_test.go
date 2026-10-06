// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStatementText(t *testing.T) {
	tests := []struct {
		name          string
		b             []byte
		partial       bool
		maxLen        int
		wantText      string
		wantTruncated bool
	}{
		{name: "whole statement", b: []byte("select 1\x00"), maxLen: 100, wantText: "select 1"},
		{name: "longer than max", b: []byte("select 12345\x00"), maxLen: 6, wantText: "select", wantTruncated: true},
		{name: "cut message", b: []byte("select 12"), partial: true, maxLen: 100, wantText: "select 12", wantTruncated: true},
		{name: "unterminated whole message", b: []byte("select 1"), maxLen: 100, wantText: "select 1"},
		{name: "cut inside a UTF-8 sequence", b: []byte("select 'é'\x00"), maxLen: 9, wantText: "select '", wantTruncated: true},
		{name: "invalid UTF-8 is replaced", b: []byte("select '\xff'\x00"), maxLen: 100, wantText: "select '�'"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text, truncated := statementText(tt.b, tt.partial, tt.maxLen)
			assert.Equal(t, tt.wantText, text)
			assert.Equal(t, tt.wantTruncated, truncated)
		})
	}
}

func TestReadHeader_InvalidLength(t *testing.T) {
	_, _, err := readHeader(bytes.NewReader([]byte{'Q', 0, 0, 0, 3}))
	assert.ErrorIs(t, err, errInvalidMessageLength)
}

func TestParseErrorFields(t *testing.T) {
	body, err := (&pgproto3.ErrorResponse{
		Severity:            "ERROR",
		SeverityUnlocalized: "ERROR",
		Code:                "42P01",
		Message:             `relation "missing" does not exist`,
		Detail:              "detail is not audited",
	}).Encode(nil)
	require.NoError(t, err)

	assert.Equal(t, map[string]any{
		"severity": "ERROR",
		"code":     "42P01",
		"message":  `relation "missing" does not exist`,
	}, parseErrorFields(body[messageHeaderLen:]))

	// A body cut short keeps the fields read so far.
	assert.Equal(t, map[string]any{"severity": "ERROR"}, parseErrorFields([]byte("VERROR\x00C42P")))
}

// encodeFrontend encodes client messages.
func encodeFrontend(t *testing.T, msgs ...pgproto3.FrontendMessage) []byte {
	t.Helper()

	var buf []byte

	for _, msg := range msgs {
		var err error

		buf, err = msg.Encode(buf)
		require.NoError(t, err)
	}

	return buf
}

func TestClientRelay_ForwardsAndRecords(t *testing.T) {
	const maxLen = 16

	longQuery := "select " + strings.Repeat("x", 100)

	input := encodeFrontend(t,
		&pgproto3.Query{String: longQuery},
		&pgproto3.Parse{Name: "s1", Query: "select $1"},
		&pgproto3.Bind{DestinationPortal: "p1", PreparedStatement: "s1", Parameters: [][]byte{[]byte("secret")}},
		&pgproto3.Execute{Portal: "p1"},
		&pgproto3.Close{ObjectType: 'S', Name: "s1"},
		&pgproto3.Bind{DestinationPortal: "", PreparedStatement: "s1"},
		&pgproto3.Execute{Portal: ""},
		&pgproto3.Sync{},
		&pgproto3.CopyData{Data: bytes.Repeat([]byte("row\n"), 20000)},
		&pgproto3.FunctionCall{Function: 1234},
		&pgproto3.Terminate{},
	)

	audit, logs := newTestAuditTracker(t, nil)

	var forwarded bytes.Buffer

	writer := bufio.NewWriter(&forwarded)
	relay := newClientRelay(bufio.NewReader(bytes.NewReader(input)), writer, audit, maxLen)

	require.NoError(t, relay.run())

	// Every byte is forwarded unchanged, including bodies longer than what was inspected.
	assert.Equal(t, input, forwarded.Bytes())

	audit.readyForQuery('I')
	audit.readyForQuery('I')
	audit.readyForQuery('I')

	records := queryLogs(logs)
	require.Len(t, records, 3)

	assert.Equal(t, []string{longQuery[:maxLen]}, records[0]["statements"])
	assert.Equal(t, true, records[0]["truncated"])

	// The second execution follows the statement's Close, so its text is no longer known.
	assert.Equal(t, []string{"select $1", unknownStatementText}, records[1]["statements"])

	assert.Equal(t, []string{"<function call 1234>"}, records[2]["statements"])
}

func TestClientRelay_RemembersBoundedStatements(t *testing.T) {
	audit, _ := newTestAuditTracker(t, nil)
	relay := newClientRelay(nil, nil, audit, defaultMaxQueryLength)

	for i := range maxPreparedStatements {
		relay.remember("s"+string(rune('a'+i%26))+strings.Repeat("x", i), statement{text: "select 1"})
	}

	relay.remember("one-too-many", statement{text: "select 2"})
	assert.Equal(t, unknownStatement, relay.preparedStatement("one-too-many"))

	// The unnamed statement is always remembered.
	relay.remember("", statement{text: "select 3"})
	assert.Equal(t, statement{text: "select 3"}, relay.preparedStatement(""))
}

func TestServerRelay_ForwardsAndRecords(t *testing.T) {
	var input []byte

	for _, msg := range []pgproto3.BackendMessage{
		&pgproto3.DataRow{Values: [][]byte{bytes.Repeat([]byte("v"), 100000)}},
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
		&pgproto3.ErrorResponse{Severity: "ERROR", SeverityUnlocalized: "ERROR", Code: "XX000", Message: strings.Repeat("m", 2*maxErrorResponseLen)},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	} {
		var err error

		input, err = msg.Encode(input)
		require.NoError(t, err)
	}

	audit, logs := newTestAuditTracker(t, nil)
	require.NoError(t, audit.simpleQuery("select v", false))

	var forwarded bytes.Buffer

	writer := bufio.NewWriter(&forwarded)
	relay := &serverRelay{r: bufio.NewReader(bytes.NewReader(input)), w: writer, audit: audit}

	require.ErrorIs(t, relay.run(), io.EOF)
	require.NoError(t, writer.Flush())
	assert.Equal(t, input, forwarded.Bytes())

	records := queryLogs(logs)
	require.Len(t, records, 1)
	assert.Equal(t, []string{"SELECT 1"}, records[0]["command_tags"])
	assert.Equal(t, "XX000", records[0]["error"].(map[string]any)["code"])
}

func TestMessageForward_StreamsUnreadBody(t *testing.T) {
	const bodyLen = 1000

	body := bytes.Repeat([]byte("b"), bodyLen)
	raw := append([]byte{'d'}, binary.BigEndian.AppendUint32(nil, bodyLen+4)...)
	raw = append(raw, body...)

	r := bytes.NewReader(raw)

	msg, err := readMessageStart(r, 10)
	require.NoError(t, err)
	assert.Len(t, msg.prefix, 10)
	assert.False(t, msg.complete())

	var out bytes.Buffer
	require.NoError(t, msg.forward(r, &out))
	assert.Equal(t, raw, out.Bytes())
}

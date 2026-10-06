// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"gateway/internal/config"
	"gateway/internal/token"
)

func TestHandler_SessionAuditsQueries(t *testing.T) {
	pki := newTestPKI(t, testServerName)
	server := newFakeServer(t, pki)
	core, logs := observer.New(zapcore.DebugLevel)
	dialer := newTunnelDialer(t, newTestHandler(t, server, pki, validCredentials()), zap.New(core))

	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()

	// sslmode=prefer first asks for TLS, which the Gateway refuses, then retries in plaintext;
	// max_protocol_version=3.2 is negotiated down to 3.0.
	conn, err := dialer.connect(ctx, t,
		"dbname=app sslmode=prefer application_name=beekeeper search_path=public options='-c role=admin' max_protocol_version=3.2")
	require.NoError(t, err)

	assert.Equal(t, uint32(testProcessID), conn.PID())
	assert.Equal(t, testServerVersion, conn.ParameterStatus("server_version"))
	assert.Equal(t, "twingate:"+testUser, conn.ParameterStatus("application_name"))

	_, err = conn.Exec(ctx, "select 1").ReadAll()
	require.NoError(t, err)

	_, err = conn.Exec(ctx, testQueryFail).ReadAll()
	requirePgError(t, err, "42601", "syntax error")

	result := conn.ExecParams(ctx, "insert into t values ($1)", [][]byte{[]byte("secret-value")}, nil, nil, nil).Read()
	require.NoError(t, result.Err)

	_, err = conn.Prepare(ctx, "ins", "insert into u values ($1)", nil)
	require.NoError(t, err)

	result = conn.ExecPrepared(ctx, "ins", [][]byte{[]byte("other-secret")}, nil, nil).Read()
	require.NoError(t, result.Err)

	require.NoError(t, conn.Close(ctx))
	dialer.wg.Wait()

	// The Gateway logged in as the Twingate user, to the requested database, passing on only the
	// allowed client parameters.
	startups := server.startupParams()
	require.Len(t, startups, 1)
	assert.Equal(t, testUser, startups[0]["user"])
	assert.Equal(t, testDatabase, startups[0]["database"])
	assert.Equal(t, "twingate:"+testUser, startups[0]["application_name"])
	assert.Equal(t, "public", startups[0]["search_path"])
	assert.NotContains(t, startups[0], "options")

	records := queryLogs(logs)
	require.Len(t, records, 4, "Prepare runs nothing, so it is not logged")

	assert.Equal(t, []string{"select 1"}, records[0]["statements"])
	assert.Equal(t, []string{"SELECT 1"}, records[0]["command_tags"])
	assert.Equal(t, "I", records[0]["tx_status"])
	assert.Equal(t, testUser, records[0]["user"])
	assert.Equal(t, testDatabase, records[0]["database"])
	assert.Equal(t, server.addr, records[0]["target"])
	assert.NotEmpty(t, records[0]["session_id"])

	assert.Equal(t, []string{testQueryFail}, records[1]["statements"])
	assert.Equal(t, map[string]any{"severity": "ERROR", "code": "42601", "message": "syntax error"}, records[1]["error"])

	assert.Equal(t, []string{"insert into t values ($1)"}, records[2]["statements"])
	assert.Equal(t, []string{"INSERT 0 1"}, records[2]["command_tags"])

	assert.Equal(t, []string{"insert into u values ($1)"}, records[3]["statements"])

	// Bound parameter values are never logged.
	for _, entry := range logs.All() {
		logged := fmt.Sprint(entry.ContextMap())
		assert.NotContains(t, logged, "secret-value")
		assert.NotContains(t, logged, "other-secret")
	}

	started := logs.FilterMessage("Postgres session started").All()
	require.Len(t, started, 1)
	assert.Equal(t, testServerVersion, started[0].ContextMap()["postgres"].(map[string]any)["server_version"])

	ended := logs.FilterMessage("Postgres session ended").All()
	require.Len(t, ended, 1)
	assert.Equal(t, 4, ended[0].ContextMap()["postgres"].(map[string]any)["queries"])

	for _, err := range dialer.errs {
		assert.NoError(t, err)
	}
}

func TestHandler_DefaultsToFirstDatabase(t *testing.T) {
	pki := newTestPKI(t, testServerName)
	server := newFakeServer(t, pki)
	dialer := newTunnelDialer(t, newTestHandler(t, server, pki, validCredentials()), zap.NewNop())

	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()

	conn, err := dialer.connect(ctx, t, "sslmode=disable")
	require.NoError(t, err)
	require.NoError(t, conn.Close(ctx))
	dialer.wg.Wait()

	startups := server.startupParams()
	require.Len(t, startups, 1)
	assert.Equal(t, testDatabase, startups[0]["database"])
}

func TestHandler_RejectsSessions(t *testing.T) {
	pki := newTestPKI(t, testServerName)
	server := newFakeServer(t, pki)

	tests := []struct {
		name        string
		creds       credentialSource
		pki         *testPKI
		connString  string
		wantCode    string
		wantMessage string
	}{
		{
			name:        "database not allowed",
			creds:       validCredentials(),
			connString:  "dbname=postgres",
			wantCode:    sqlStateInvalidCatalogName,
			wantMessage: `database "postgres" is not available`,
		},
		{
			name:        "user not allowed",
			creds:       fakeCredentials{err: errUserNotAllowed},
			connString:  "dbname=app",
			wantCode:    sqlStateInvalidAuthorization,
			wantMessage: "user is not allowed",
		},
		{
			name:        "credentials unavailable",
			creds:       fakeCredentials{err: errors.New("token endpoint unavailable")},
			connString:  "dbname=app",
			wantCode:    sqlStateInvalidAuthorization,
			wantMessage: "could not obtain database credentials",
		},
		{
			name:        "server rejects the login",
			creds:       fakeCredentials{creds: credentials{user: testUser, password: "wrong"}},
			connString:  "dbname=app",
			wantCode:    "28P01",
			wantMessage: "password authentication failed",
		},
		{
			name:        "server certificate not trusted",
			creds:       validCredentials(),
			pki:         newTestPKI(t, testServerName),
			connString:  "dbname=app",
			wantCode:    sqlStateConnectionFailure,
			wantMessage: "could not connect to the database server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handlerPKI := pki
			if tt.pki != nil {
				handlerPKI = tt.pki
			}

			core, logs := observer.New(zapcore.DebugLevel)
			dialer := newTunnelDialer(t, newTestHandler(t, server, handlerPKI, tt.creds), zap.New(core))

			ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
			defer cancel()

			_, err := dialer.connect(ctx, t, "sslmode=disable "+tt.connString)
			requirePgError(t, err, tt.wantCode, tt.wantMessage)

			dialer.wg.Wait()
			assert.Equal(t, 1, logs.FilterMessage("Postgres session rejected").Len())
		})
	}
}

func TestHandler_TLSVerification(t *testing.T) {
	// The server certificate names a different host, as Cloud SQL certificates do not name the
	// instance's IP address.
	pki := newTestPKI(t, "other.name")
	server := newFakeServer(t, pki)

	tests := []struct {
		name    string
		mode    string
		wantErr bool
	}{
		{name: "verifyFull checks the name", mode: config.PostgresTLSModeVerifyFull, wantErr: true},
		{name: "verifyCA checks only the chain", mode: config.PostgresTLSModeVerifyCA},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream, err := newUpstream(server.addr, config.PostgresTLSConfig{Mode: tt.mode, CAFile: pki.caFile, ServerName: testServerName})
			require.NoError(t, err)

			handler := newHandlerWithCredentials(upstream, &config.PostgresTargetConfig{Databases: []string{testDatabase}}, validCredentials())
			dialer := newTunnelDialer(t, handler, zap.NewNop())

			ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
			defer cancel()

			conn, err := dialer.connect(ctx, t, "sslmode=disable")
			if tt.wantErr {
				requirePgError(t, err, sqlStateConnectionFailure, "could not connect")

				return
			}

			require.NoError(t, err)
			require.NoError(t, conn.Close(ctx))
		})
	}
}

func TestHandler_CancelRequest(t *testing.T) {
	pki := newTestPKI(t, testServerName)
	server := newFakeServer(t, pki)
	core, logs := observer.New(zapcore.DebugLevel)
	handler := newTestHandler(t, server, pki, validCredentials())
	dialer := newTunnelDialer(t, handler, zap.New(core))

	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()

	conn, err := dialer.connect(ctx, t, "sslmode=disable")
	require.NoError(t, err)

	t.Run("another session's key is not forwarded", func(t *testing.T) {
		sendCancel(t, handler, token.User{Username: "mallory@example.com"}, zap.New(core), testProcessID, testSecretKey)
		sendCancel(t, handler, token.User{Username: testUser}, zap.New(core), testProcessID, []byte{9, 9, 9, 9})

		select {
		case req := <-server.cancels:
			t.Fatalf("cancel request forwarded: %+v", req)
		case <-time.After(100 * time.Millisecond):
		}

		assert.Equal(t, 2, logs.FilterMessage("Postgres cancel request rejected: no matching session for this user").Len())
	})

	t.Run("the session owner's request is forwarded", func(t *testing.T) {
		require.NoError(t, conn.CancelRequest(ctx))

		select {
		case req := <-server.cancels:
			assert.Equal(t, uint32(testProcessID), req.ProcessID)
			assert.Equal(t, testSecretKey, req.SecretKey)
		case <-ctx.Done():
			t.Fatal("cancel request was not forwarded")
		}
	})

	require.NoError(t, conn.Close(ctx))

	t.Run("a closed session's key is not forwarded", func(t *testing.T) {
		dialer.wg.Wait()
		sendCancel(t, handler, token.User{Username: testUser}, zap.New(core), testProcessID, testSecretKey)

		select {
		case req := <-server.cancels:
			t.Fatalf("cancel request forwarded: %+v", req)
		case <-time.After(100 * time.Millisecond):
		}
	})
}

// sendCancel sends a raw cancel request through the handler as user.
func sendCancel(t *testing.T, handler *Handler, user token.User, logger *zap.Logger, processID uint32, secretKey []byte) {
	t.Helper()

	client, server := net.Pipe()
	done := make(chan error, 1)

	go func() {
		done <- handler.ServeTunnel(t.Context(), server, user, logger)
	}()

	_, err := client.Write(encodeCancelRequest(&cancelRequest{processID: processID, secretKey: secretKey}))
	require.NoError(t, err)
	require.NoError(t, <-done)
	require.NoError(t, client.Close())
}

func TestHandler_RejectsInvalidStartup(t *testing.T) {
	pki := newTestPKI(t, testServerName)
	server := newFakeServer(t, pki)
	handler := newTestHandler(t, server, pki, validCredentials())

	startupPacket := func(code uint32) []byte {
		buf := binary.BigEndian.AppendUint32(nil, 9)
		buf = binary.BigEndian.AppendUint32(buf, code)

		return append(buf, 0)
	}

	sslRequest := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 8), sslRequestCode)

	tests := []struct {
		name     string
		packets  []byte
		wantCode string
	}{
		{name: "protocol 2", packets: startupPacket(2 << 16), wantCode: sqlStateFeatureNotSupported},
		{name: "length too short", packets: []byte{0, 0, 0, 4, 0, 3, 0, 0}, wantCode: sqlStateProtocolViolation},
		{name: "too many encryption requests", packets: append(append(append([]byte{}, sslRequest...), sslRequest...), sslRequest...), wantCode: sqlStateProtocolViolation},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, serverEnd := net.Pipe()
			done := make(chan error, 1)

			go func() {
				done <- handler.ServeTunnel(t.Context(), serverEnd, token.User{Username: testUser}, zap.NewNop())
			}()

			go func() {
				_, _ = client.Write(tt.packets)
			}()

			// Skip the refusals of any encryption requests, then expect the error.
			var reply [1]byte
			for {
				_, err := client.Read(reply[:])
				require.NoError(t, err)

				if reply[0] != encryptionRefused {
					break
				}
			}

			frontend := pgproto3.NewFrontend(&prefixedReader{prefix: reply[:], r: client}, client)
			msg, err := frontend.Receive()
			require.NoError(t, err)

			errResp, ok := msg.(*pgproto3.ErrorResponse)
			require.True(t, ok, "want ErrorResponse, got %T", msg)
			assert.Equal(t, tt.wantCode, errResp.Code)
			assert.Equal(t, severityFatal, errResp.Severity)

			require.NoError(t, <-done)
		})
	}
}

// prefixedReader reads prefix, then r.
type prefixedReader struct {
	prefix []byte
	r      net.Conn
}

func (p *prefixedReader) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]

		return n, nil
	}

	return p.r.Read(b)
}

func TestSessionParams(t *testing.T) {
	params := sessionParams(map[string]string{
		"DateStyle":        "ISO, MDY",
		"client_encoding":  "UTF8",
		"application_name": "beekeeper",
		"options":          "-c role=admin",
		"replication":      "database",
		"user":             "postgres",
		"database":         "postgres",
	}, testUser)

	assert.Equal(t, map[string]string{
		"DateStyle":        "ISO, MDY",
		"client_encoding":  "UTF8",
		"application_name": "twingate:" + testUser,
	}, params)
}

func TestStartSession_NegotiatesProtocolVersion(t *testing.T) {
	server := &pgconn.HijackedConn{PID: testProcessID, SecretKey: testSecretKey, TxStatus: 'I'}

	var out bytes.Buffer
	require.NoError(t, (&Handler{}).startSession(&out, &startupMessage{minorVersion: 2, pqOptions: []string{"_pq_.x"}}, server))

	frontend := pgproto3.NewFrontend(&out, io.Discard)

	msg, err := frontend.Receive()
	require.NoError(t, err)

	npv, ok := msg.(*pgproto3.NegotiateProtocolVersion)
	require.True(t, ok, "want NegotiateProtocolVersion, got %T", msg)

	// libpq reads this field as a full protocol version, and rejects anything below 3.0.
	assert.Equal(t, protocolVersion30, npv.NewestMinorProtocol)
	assert.Equal(t, []string{"_pq_.x"}, npv.UnrecognizedOptions)

	msg, err = frontend.Receive()
	require.NoError(t, err)
	assert.IsType(t, &pgproto3.AuthenticationOk{}, msg)
}

// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"gateway/internal/config"
	"gateway/internal/token"
)

const (
	testTimeout       = 5 * time.Second
	testServerName    = "db.test"
	testUser          = "alice@example.com"
	testPassword      = "access-token"
	testDatabase      = "app"
	testProcessID     = 42
	testQueryFail     = "select fail"
	testServerVersion = "18.0"
)

var testSecretKey = []byte{1, 2, 3, 4}

// testPKI is a CA and a server certificate it signs, valid for testServerName.
type testPKI struct {
	caFile     string
	serverCert tls.Certificate
}

func newTestPKI(t *testing.T, dnsNames ...string) *testPKI {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Server CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-project:test-instance"},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	require.NoError(t, err)

	caFile := filepath.Join(t.TempDir(), "server-ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600))

	return &testPKI{
		caFile:     caFile,
		serverCert: tls.Certificate{Certificate: [][]byte{serverDER}, PrivateKey: serverKey},
	}
}

// fakeServer is a minimal PostgreSQL server: it requires TLS and a cleartext password login, then
// answers queries with canned results. Query testQueryFail fails; every other query succeeds.
type fakeServer struct {
	addr      string
	tlsConfig *tls.Config

	mu       sync.Mutex
	startups []map[string]string

	cancels chan *pgproto3.CancelRequest
}

func newFakeServer(t *testing.T, pki *testPKI) *fakeServer {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	t.Cleanup(func() { _ = listener.Close() })

	server := &fakeServer{
		addr:      listener.Addr().String(),
		tlsConfig: &tls.Config{Certificates: []tls.Certificate{pki.serverCert}, MinVersion: tls.VersionTLS12},
		cancels:   make(chan *pgproto3.CancelRequest, 1),
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func() {
				defer conn.Close()

				server.serve(conn)
			}()
		}
	}()

	return server
}

func (s *fakeServer) startupParams() []map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]map[string]string(nil), s.startups...)
}

func (s *fakeServer) serve(conn net.Conn) {
	backend := pgproto3.NewBackend(conn, conn)

	msg, err := backend.ReceiveStartupMessage()
	if err != nil {
		return
	}

	if _, ok := msg.(*pgproto3.SSLRequest); !ok {
		// The server requires TLS.
		return
	}

	if _, err := conn.Write([]byte{'S'}); err != nil {
		return
	}

	tlsConn := tls.Server(conn, s.tlsConfig)
	backend = pgproto3.NewBackend(tlsConn, tlsConn)

	msg, err = backend.ReceiveStartupMessage()
	if err != nil {
		return
	}

	switch msg := msg.(type) {
	case *pgproto3.CancelRequest:
		s.cancels <- msg
	case *pgproto3.StartupMessage:
		s.serveSession(backend, msg)
	default:
		// Anything else ends the connection.
	}
}

func (s *fakeServer) serveSession(backend *pgproto3.Backend, startup *pgproto3.StartupMessage) {
	s.mu.Lock()
	s.startups = append(s.startups, startup.Parameters)
	s.mu.Unlock()

	backend.Send(&pgproto3.AuthenticationCleartextPassword{})

	if backend.Flush() != nil || backend.SetAuthType(pgproto3.AuthTypeCleartextPassword) != nil {
		return
	}

	msg, err := backend.Receive()
	if err != nil {
		return
	}

	password, ok := msg.(*pgproto3.PasswordMessage)
	if !ok || startup.Parameters["user"] != testUser || password.Password != testPassword {
		backend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28P01", Message: "password authentication failed"})
		_ = backend.Flush()

		return
	}

	backend.Send(&pgproto3.AuthenticationOk{})
	backend.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: testServerVersion})
	backend.Send(&pgproto3.ParameterStatus{Name: "application_name", Value: startup.Parameters["application_name"]})
	backend.Send(&pgproto3.BackendKeyData{ProcessID: testProcessID, SecretKey: testSecretKey})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})

	if backend.Flush() != nil {
		return
	}

	for {
		msg, err := backend.Receive()
		if err != nil {
			return
		}

		switch msg := msg.(type) {
		case *pgproto3.Query:
			if msg.String == testQueryFail {
				backend.Send(&pgproto3.ErrorResponse{Severity: "ERROR", SeverityUnlocalized: "ERROR", Code: "42601", Message: "syntax error"})
			} else {
				backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
			}

			backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		case *pgproto3.Parse:
			backend.Send(&pgproto3.ParseComplete{})
		case *pgproto3.Bind:
			backend.Send(&pgproto3.BindComplete{})
		case *pgproto3.Describe:
			if msg.ObjectType == 'S' {
				backend.Send(&pgproto3.ParameterDescription{})
			}

			backend.Send(&pgproto3.NoData{})
		case *pgproto3.Execute:
			backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("INSERT 0 1")})
		case *pgproto3.Sync:
			backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		case *pgproto3.Terminate:
			return
		default:
			// The fake ignores other messages.
		}

		if backend.Flush() != nil {
			return
		}
	}
}

// fakeCredentials returns fixed credentials, or err.
type fakeCredentials struct {
	creds credentials
	err   error
}

func (f fakeCredentials) credentials(context.Context, string) (credentials, error) {
	return f.creds, f.err
}

// newTestHandler returns a Handler for server whose certificate pki signs, logging in with creds.
func newTestHandler(t *testing.T, server *fakeServer, pki *testPKI, creds credentialSource) *Handler {
	t.Helper()

	upstream, err := newUpstream(server.addr, config.PostgresTLSConfig{CAFile: pki.caFile, ServerName: testServerName})
	require.NoError(t, err)

	return newHandlerWithCredentials(upstream, &config.PostgresTargetConfig{Databases: []string{testDatabase, "other"}}, creds)
}

func validCredentials() fakeCredentials {
	return fakeCredentials{creds: credentials{user: testUser, password: testPassword}}
}

// tunnelDialer serves each connection a client dials with handler, as the SSH tunnel would, and
// records what each ServeTunnel call returned.
type tunnelDialer struct {
	handler *Handler
	logger  *zap.Logger

	mu   sync.Mutex
	errs []error
	wg   sync.WaitGroup
}

func newTunnelDialer(t *testing.T, handler *Handler, logger *zap.Logger) *tunnelDialer {
	t.Helper()

	d := &tunnelDialer{handler: handler, logger: logger}
	t.Cleanup(d.wg.Wait)

	return d
}

func (d *tunnelDialer) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	client, server := net.Pipe()

	d.wg.Go(func() {
		// The session outlives the dial.
		err := d.handler.ServeTunnel(context.WithoutCancel(ctx), server, token.User{Username: testUser}, d.logger)

		d.mu.Lock()
		d.errs = append(d.errs, err)
		d.mu.Unlock()
	})

	return client, nil
}

// connect opens a client session through the handler with the given connection string settings.
func (d *tunnelDialer) connect(ctx context.Context, t *testing.T, connString string) (*pgconn.PgConn, error) {
	t.Helper()

	cfg, err := pgconn.ParseConfig("host=" + testServerName + " port=5432 user=beekeeper password=ignored " + connString)
	require.NoError(t, err)

	cfg.DialFunc = d.dial
	cfg.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }

	return pgconn.ConnectConfig(ctx, cfg)
}

// queryLogs returns the "postgres" field of each audit record for a query.
func queryLogs(logs *observer.ObservedLogs) []map[string]any {
	var records []map[string]any

	for _, entry := range logs.FilterMessage("Postgres query").All() {
		if fields, ok := entry.ContextMap()["postgres"].(map[string]any); ok {
			records = append(records, fields)
		}
	}

	return records
}

// requirePgError asserts err is a PostgreSQL error with the given SQLSTATE, and a message
// containing wantMessage.
func requirePgError(t *testing.T, err error, code, wantMessage string) {
	t.Helper()

	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	assert.Equal(t, code, pgErr.Code)
	assert.Contains(t, pgErr.Message, wantMessage)
}

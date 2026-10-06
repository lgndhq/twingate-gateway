// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"gateway/internal/config"
)

// upstreamConnectTimeout bounds dialing, TLS, and login to the PostgreSQL server.
const upstreamConnectTimeout = 15 * time.Second

// requireAuth limits the login methods the Gateway accepts from the server to ones that send the
// credentials over the verified TLS connection: a cleartext password (Cloud SQL IAM) or SCRAM.
const requireAuth = "password,scram-sha-256"

var (
	errInvalidCACert       = errors.New("no certificates found in CA file")
	errNoPeerCertificate   = errors.New("server presented no certificate")
	errServerRefusedTLS    = errors.New("server refused TLS")
	errInvalidTargetFormat = errors.New("invalid target address")
)

type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// upstream is the PostgreSQL server behind a tunnel target.
type upstream struct {
	address   string
	host      string
	port      uint16
	tlsConfig *tls.Config
	dial      dialFunc
}

func newUpstream(address string, tlsCfg config.PostgresTLSConfig) (*upstream, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalidTargetFormat, err)
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("%w: port %q", errInvalidTargetFormat, portStr)
	}

	tlsConfig, err := newTLSConfig(tlsCfg, host)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: upstreamConnectTimeout}

	return &upstream{
		address:   address,
		host:      host,
		port:      uint16(port),
		tlsConfig: tlsConfig,
		dial:      dialer.DialContext,
	}, nil
}

// newTLSConfig returns the TLS client config for the server: certificates are always verified,
// against CAFile when set or the system pool otherwise.
func newTLSConfig(cfg config.PostgresTLSConfig, host string) (*tls.Config, error) {
	rootCAs, err := loadRootCAs(cfg.CAFile)
	if err != nil {
		return nil, err
	}

	if cfg.Mode == config.PostgresTLSModeVerifyCA {
		// Disable the built-in verification, which always checks the hostname, and verify only the
		// certificate chain in VerifyConnection. Cloud SQL server certificates do not name the
		// instance's IP address.
		return &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, // #nosec G402 -- The certificate chain is verified in VerifyConnection
			VerifyConnection:   verifyCertificateChain(rootCAs),
		}, nil
	}

	serverName := cfg.ServerName
	if serverName == "" {
		serverName = host
	}

	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCAs,
		ServerName: serverName,
	}, nil
}

func loadRootCAs(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system cert pool: %w", err)
		}

		return pool, nil
	}

	pem, err := os.ReadFile(caFile) //nolint:gosec // The CA file is provided by the operator
	if err != nil {
		return nil, fmt.Errorf("ca %q: %w", caFile, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("ca %q: %w", caFile, errInvalidCACert)
	}

	return pool, nil
}

// verifyCertificateChain returns a VerifyConnection callback that verifies the server's
// certificate chain against rootCAs without checking the hostname.
func verifyCertificateChain(rootCAs *x509.CertPool) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errNoPeerCertificate
		}

		opts := x509.VerifyOptions{
			Roots:         rootCAs,
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}

		if _, err := cs.PeerCertificates[0].Verify(opts); err != nil {
			return fmt.Errorf("verify server certificate: %w", err)
		}

		return nil
	}
}

// connect logs in to the server and returns the raw connection, ready for the client's first
// query.
func (u *upstream) connect(ctx context.Context, creds credentials, database string, params map[string]string) (*pgconn.HijackedConn, error) {
	ctx, cancel := context.WithTimeout(ctx, upstreamConnectTimeout)
	defer cancel()

	// Every field ParseConfig may fill from PG* environment variables or service files is set
	// explicitly below, so only this configuration reaches the server.
	pgConfig, err := pgconn.ParseConfig("sslmode=disable")
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	pgConfig.Host = u.host
	pgConfig.Port = u.port
	pgConfig.Database = database
	pgConfig.User = creds.user
	pgConfig.Password = creds.password
	pgConfig.TLSConfig = u.tlsConfig.Clone()
	pgConfig.Fallbacks = nil
	pgConfig.ConnectTimeout = upstreamConnectTimeout
	pgConfig.DialFunc = pgconn.DialFunc(u.dial)
	pgConfig.RuntimeParams = params
	pgConfig.KerberosSrvName = ""
	pgConfig.KerberosSpn = ""
	pgConfig.SSLNegotiation = ""
	pgConfig.AfterNetConnect = nil
	pgConfig.ValidateConnect = nil
	pgConfig.AfterConnect = nil
	pgConfig.OnNotice = nil
	pgConfig.OnNotification = nil
	pgConfig.OAuthTokenProvider = nil
	pgConfig.MinProtocolVersion = "3.0"
	pgConfig.MaxProtocolVersion = "3.0"
	pgConfig.RequireAuth = requireAuth

	conn, err := pgconn.ConnectConfig(ctx, pgConfig)
	if err != nil {
		return nil, err
	}

	if err := conn.SyncConn(ctx); err != nil {
		_ = conn.Close(ctx)

		return nil, err
	}

	hijacked, err := conn.Hijack()
	if err != nil {
		_ = conn.Close(ctx)

		return nil, fmt.Errorf("hijack connection: %w", err)
	}

	return hijacked, nil
}

// cancel forwards a cancel request to the server over a new TLS connection.
func (u *upstream) cancel(ctx context.Context, req *cancelRequest) error {
	ctx, cancel := context.WithTimeout(ctx, upstreamConnectTimeout)
	defer cancel()

	conn, err := u.dial(ctx, "tcp", u.address)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	var sslRequest [8]byte
	binary.BigEndian.PutUint32(sslRequest[0:4], uint32(len(sslRequest)))
	binary.BigEndian.PutUint32(sslRequest[4:8], sslRequestCode)

	if _, err := conn.Write(sslRequest[:]); err != nil {
		return fmt.Errorf("send SSL request: %w", err)
	}

	var response [1]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return fmt.Errorf("read SSL response: %w", err)
	}

	if response[0] != 'S' {
		return errServerRefusedTLS
	}

	tlsConn := tls.Client(conn, u.tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("TLS handshake: %w", err)
	}

	if _, err := tlsConn.Write(encodeCancelRequest(req)); err != nil {
		return fmt.Errorf("send cancel request: %w", err)
	}

	// The server closes the connection once it has read the request.
	_, _ = io.Copy(io.Discard, tlsConn)

	return nil
}

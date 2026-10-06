// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/crypto/ssh"

	"gateway/internal/token"
)

const testTunnelUser = "alice@example.com"

// echoTunnelHandler echoes each stream back, recording the user each was served for.
type echoTunnelHandler struct {
	mu    sync.Mutex
	users []string
}

func (e *echoTunnelHandler) ServeTunnel(_ context.Context, stream io.ReadWriteCloser, user token.User, _ *zap.Logger) error {
	defer stream.Close()

	e.mu.Lock()
	e.users = append(e.users, user.Username)
	e.mu.Unlock()

	_, err := io.Copy(stream, stream)

	return err
}

func (e *echoTunnelHandler) servedUsers() []string {
	e.mu.Lock()
	defer e.mu.Unlock()

	return append([]string(nil), e.users...)
}

// tunnelConnTest is a downstream connection being served to a tunnel-only resource.
type tunnelConnTest struct {
	proxy   *Proxy
	handler *echoTunnelHandler
	client  *ssh.Client
	served  <-chan error
}

// startTunnelConn serves one downstream connection to a tunnel-only resource whose targets are
// db.internal:5432 and its alias ix-prod.example.dev:5432, with a connected SSH client.
func startTunnelConn(t *testing.T, logger *zap.Logger) *tunnelConnTest {
	t.Helper()

	sshProxy := newTestProxyWithLogger(t, logger)
	handler := &echoTunnelHandler{}
	sshProxy.config.tunnels = map[string]*tunnel{
		testResourceAddress: {targets: map[string]TunnelHandler{
			tunnelTargetKey("db.internal", 5432):         handler,
			tunnelTargetKey("ix-prod.example.dev", 5432): handler,
		}},
	}

	// The upstream address is never dialed: a tunnel has no upstream SSH server.
	clientConn, serverConn := newDownstreamConn(t, "127.0.0.1:1")
	serverConn.Claims.User = token.User{Username: testTunnelUser}

	served := make(chan error, 1)

	go func() {
		served <- sshProxy.serveConn(t.Context(), serverConn)
	}()

	client, err := dialDownstream(t, sshProxy, clientConn)
	require.NoError(t, err)

	t.Cleanup(func() { _ = client.Close() })

	return &tunnelConnTest{proxy: sshProxy, handler: handler, client: client, served: served}
}

func TestTunnel_ForwardsToTargets(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	tc := startTunnelConn(t, zap.New(core))
	sshProxy, handler, client, served := tc.proxy, tc.handler, tc.client, tc.served

	// The target's address and its alias both reach the handler; host names match
	// case-insensitively.
	for _, destination := range []string{"db.internal:5432", "IX-PROD.example.dev:5432"} {
		stream, err := client.Dial("tcp", destination)
		require.NoError(t, err, destination)

		_, err = stream.Write([]byte("ping"))
		require.NoError(t, err)
		assert.Equal(t, "ping", string(readInFull(t, stream, len("ping"))))
		require.NoError(t, stream.Close())
	}

	require.Eventually(t, func() bool {
		return len(handler.servedUsers()) == 2
	}, testTimeout, 10*time.Millisecond)
	assert.Equal(t, []string{testTunnelUser, testTunnelUser}, handler.servedUsers())

	assert.Equal(t, 1, connCount(sshProxy))

	require.NoError(t, client.Close())
	require.NoError(t, waitErr(t, served))
	assert.Equal(t, 0, connCount(sshProxy))

	assert.Equal(t, 1, logs.FilterMessage("SSH tunnel connection established").Len())
	assert.Equal(t, 2, logs.FilterMessage("SSH channel opened").Len())

	closed := logs.FilterMessage("SSH connection closed").All()
	require.Len(t, closed, 1)
	assert.Equal(t, 2, closed[0].ContextMap()["ssh"].(map[string]any)["channels_opened"])
}

func TestTunnel_RejectsEverythingElse(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	tc := startTunnelConn(t, zap.New(core))
	handler, client := tc.handler, tc.client

	t.Run("other destinations", func(t *testing.T) {
		for _, destination := range []string{"db.internal:5433", "10.0.0.1:5432", "metadata.google.internal:80"} {
			_, err := client.Dial("tcp", destination)
			require.Error(t, err, destination)
			assert.Contains(t, err.Error(), "destination not allowed")
		}

		assert.Equal(t, 3, logs.FilterMessage("SSH channel rejected: destination is not a tunnel target").Len())
	})

	t.Run("sessions", func(t *testing.T) {
		_, err := client.NewSession()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only port forwarding is allowed")
	})

	t.Run("remote forwarding", func(t *testing.T) {
		_, err := client.Listen("tcp", "127.0.0.1:0")
		require.Error(t, err)

		assert.Equal(t, 1, logs.FilterMessage("SSH global request rejected").Len())
	})

	assert.Empty(t, handler.servedUsers())
}

// dialPlainHostKey completes an SSH handshake over conn as a client that cannot verify host
// certificates, returning the host key the server presented.
func dialPlainHostKey(t *testing.T, conn net.Conn) (ssh.PublicKey, error) {
	t.Helper()

	var hostKey ssh.PublicKey

	clientConfig := &ssh.ClientConfig{
		User:              "beekeeper",
		HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			hostKey = key

			return nil
		},
		Timeout: testTimeout,
	}

	sshConn, channels, requests, err := ssh.NewClientConn(conn, net.JoinHostPort(testRequestedHost, "22"), clientConfig)
	if err != nil {
		return nil, err
	}

	client := ssh.NewClient(sshConn, channels, requests)

	t.Cleanup(func() { _ = client.Close() })

	return hostKey, nil
}

func TestTunnel_OffersPlainHostKey(t *testing.T) {
	sshProxy := newTestProxy(t)
	sshProxy.config.tunnels = map[string]*tunnel{
		testResourceAddress: {targets: map[string]TunnelHandler{}},
	}

	clientConn, serverConn := newDownstreamConn(t, "127.0.0.1:1")

	go func() {
		_ = sshProxy.serveConn(t.Context(), serverConn)
	}()

	// A client that cannot verify host certificates still connects, and is shown the Gateway's
	// own host key: the key the certificates certify.
	hostKey, err := dialPlainHostKey(t, clientConn)
	require.NoError(t, err)
	assert.True(t, keysEqual(sshProxy.config.hostCerts.publicKey, hostKey))
}

func TestSSHResource_OffersOnlyHostCertificate(t *testing.T) {
	sshProxy := newTestProxy(t)
	clientConn, serverConn := newDownstreamConn(t, "127.0.0.1:1")

	go func() {
		_ = sshProxy.serveConn(t.Context(), serverConn)
	}()

	_, err := dialPlainHostKey(t, clientConn)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no common algorithm for host key")
}

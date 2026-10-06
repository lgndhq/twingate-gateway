// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	"gateway/internal/token"
)

// globalRequestKeepalive is the global request OpenSSH-compatible clients send to check that the
// connection is alive.
const globalRequestKeepalive = "keepalive@openssh.com"

// TunnelHandler serves one forwarded stream of a tunnel-only SSH resource. It closes the stream
// before returning.
type TunnelHandler interface {
	ServeTunnel(ctx context.Context, stream io.ReadWriteCloser, user token.User, logger *zap.Logger) error
}

// tunnel is a tunnel-only SSH resource: the Gateway serves the SSH connection itself and accepts
// only direct-tcpip channels to its targets, each served by the target's handler.
type tunnel struct {
	// targets maps a normalized host:port to the handler for streams forwarded to it.
	targets map[string]TunnelHandler
}

func tunnelTargetKey(host string, port uint32) string {
	return net.JoinHostPort(strings.ToLower(host), strconv.FormatUint(uint64(port), 10))
}

// tunnelConn serves an SSH connection to a tunnel-only resource.
type tunnelConn struct {
	logger *zap.Logger
	sshCtx *sshContext
	user   token.User

	downstream connection
	tunnel     *tunnel

	channelCount atomic.Int32
	wg           sync.WaitGroup
}

func newTunnelConn(logger *zap.Logger, sshCtx *sshContext, user token.User, downstream connection, t *tunnel) *tunnelConn {
	return &tunnelConn{
		logger:     logger,
		sshCtx:     sshCtx,
		user:       user,
		downstream: downstream,
		tunnel:     t,
	}
}

func (t *tunnelConn) ChannelsOpened() int {
	return int(t.channelCount.Load())
}

// serve handles the connection's global requests and channels until it closes, then waits for
// every stream to finish.
func (t *tunnelConn) serve(ctx context.Context) {
	t.wg.Go(func() {
		defer closeOnPanic(t.logger, t.close)

		for req := range t.downstream.requests {
			t.rejectGlobalRequest(req)
		}
	})

	t.wg.Go(func() {
		defer closeOnPanic(t.logger, t.close)

		for newChannel := range t.downstream.channels {
			t.handleChannel(ctx, newChannel)
		}
	})

	t.wg.Wait()
}

// rejectGlobalRequest refuses a global request: a tunnel has no upstream server to forward it to,
// and accepting remote forwarding (tcpip-forward) would open a path into the client.
func (t *tunnelConn) rejectGlobalRequest(req *ssh.Request) {
	extra, _ := globalRequestLogFields(req.Type, req.Payload)
	logger := t.logger.With(zap.Any("ssh", t.sshCtx.withGlobalRequest(req.Type, labelDownstream, labelUpstream, extra)))

	if req.Type == globalRequestKeepalive {
		// Clients send these periodically; any reply, including this refusal, shows the connection
		// is alive. Refusing is what OpenSSH servers do too.
		logger.Debug("SSH keepalive")
	} else {
		logger.Warn("SSH global request rejected")
	}

	if err := req.Reply(false, nil); err != nil {
		logger.Error("Failed to reply to global request", zap.Error(err))
	}
}

func (t *tunnelConn) handleChannel(ctx context.Context, newChannel ssh.NewChannel) {
	channelType := newChannel.ChannelType()

	extra, parseErr := channelOpenExtra(channelType, newChannel.ExtraData())
	chCtx := newSSHChannelContext(t.sshCtx, channelType, labelDownstream, labelUpstream, extra)
	logger := t.logger.With(zap.Any("ssh", chCtx.baseFields()))

	if channelType != channelTypeDirectTCPIP {
		logger.Warn("SSH channel rejected: tunnel resources accept only port forwarding")
		rejectChannel(logger, newChannel, ssh.Prohibited, "only port forwarding is allowed")

		return
	}

	var open tcpipChannelOpen
	if parseErr != nil || ssh.Unmarshal(newChannel.ExtraData(), &open) != nil {
		logger.Error("Failed to parse channel open", zap.Error(parseErr))
		rejectChannel(logger, newChannel, ssh.ConnectionFailed, "invalid channel open")

		return
	}

	handler, ok := t.tunnel.targets[tunnelTargetKey(open.DestAddr, open.DestPort)]
	if !ok {
		logger.Warn("SSH channel rejected: destination is not a tunnel target")
		rejectChannel(logger, newChannel, ssh.Prohibited, "destination not allowed")

		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		logger.Error("Failed to accept channel", zap.Error(err))

		return
	}

	// direct-tcpip channels carry no requests; refuse any that arrive.
	go ssh.DiscardRequests(requests)

	t.channelCount.Add(1)
	logger.Info("SSH channel opened")

	t.wg.Go(func() {
		defer closeOnPanic(t.logger, func() { _ = channel.Close() })

		if err := handler.ServeTunnel(ctx, channel, t.user, logger); err != nil {
			logger.Warn("Tunnel stream ended with error", zap.Error(err))
		}

		logger.Info("SSH channel closed")
	})
}

func rejectChannel(logger *zap.Logger, newChannel ssh.NewChannel, reason ssh.RejectionReason, message string) {
	if err := newChannel.Reject(reason, message); err != nil {
		logger.Error("Failed to reject channel", zap.Error(err))
	}
}

func (t *tunnelConn) close() {
	if err := t.downstream.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.logger.Error("Failed to close downstream connection", zap.Error(err))
	}
}

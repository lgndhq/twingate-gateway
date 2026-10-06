// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

// Package postgres proxies PostgreSQL sessions that reach the Gateway through an SSH tunnel. The
// Gateway logs in to the server as the Twingate user, so clients need no database credentials,
// and records every statement the session runs in the audit log.
package postgres

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"go.uber.org/zap"

	"gateway/internal/config"
	"gateway/internal/token"
)

const (
	defaultMaxQueryLength = 4096

	// startupTimeout bounds how long a client may take to send its startup message.
	startupTimeout = 30 * time.Second

	// maxStartupRequests bounds the encryption requests a client may send before its startup
	// message: one SSL and one GSSAPI request.
	maxStartupRequests = 3

	relayBufferSize = 32 * 1024

	applicationNamePrefix = "twingate:"
)

// forwardedParams are the startup parameters passed from the client to the server, by lowercase
// name. Others are dropped: the Gateway chooses the user and database, and parameters such as
// "replication" and "options" would change what the session may do.
var forwardedParams = map[string]struct{}{
	"client_encoding":                     {},
	"datestyle":                           {},
	"timezone":                            {},
	"intervalstyle":                       {},
	"extra_float_digits":                  {},
	"search_path":                         {},
	"bytea_output":                        {},
	"statement_timeout":                   {},
	"lock_timeout":                        {},
	"idle_in_transaction_session_timeout": {},
}

var errTooManyStartupRequests = errors.New("too many encryption requests before startup")

// Handler serves PostgreSQL sessions for one tunnel target.
type Handler struct {
	upstream       *upstream
	databases      []string
	credentials    credentialSource
	cancels        *cancelRegistry
	maxQueryLength int
}

// NewHandler returns a Handler for the PostgreSQL server at address.
func NewHandler(address string, cfg *config.PostgresTargetConfig) (*Handler, error) {
	upstream, err := newUpstream(address, cfg.TLS)
	if err != nil {
		return nil, err
	}

	credentials, err := newGCPIAMCredentials(cfg.Auth.GCPIAM)
	if err != nil {
		return nil, err
	}

	return newHandlerWithCredentials(upstream, cfg, credentials), nil
}

func newHandlerWithCredentials(upstream *upstream, cfg *config.PostgresTargetConfig, credentials credentialSource) *Handler {
	maxQueryLength := cfg.MaxQueryLength
	if maxQueryLength == 0 {
		maxQueryLength = defaultMaxQueryLength
	}

	return &Handler{
		upstream:       upstream,
		databases:      slices.Clone(cfg.Databases),
		credentials:    credentials,
		cancels:        newCancelRegistry(),
		maxQueryLength: maxQueryLength,
	}
}

// ServeTunnel serves one PostgreSQL session, or cancel request, from a forwarded stream for user.
// The stream is closed when it returns.
func (h *Handler) ServeTunnel(ctx context.Context, stream io.ReadWriteCloser, user token.User, logger *zap.Logger) error {
	defer stream.Close()

	session := &sessionContext{id: uuid.New().String(), target: h.upstream.address}

	// Closing the stream unblocks the read if the client stalls before starting.
	startupTimer := time.AfterFunc(startupTimeout, func() { _ = stream.Close() })
	startup, cancelReq, err := readStartup(stream)

	startupTimer.Stop()

	if cancelReq != nil {
		h.forwardCancel(ctx, cancelReq, user.Username, session, logger)

		return nil
	}

	if err != nil {
		return h.rejectStartup(stream, err, session, logger)
	}

	session.database = startup.params["database"]
	if session.database == "" {
		session.database = h.databases[0]
	}

	if !slices.Contains(h.databases, session.database) {
		h.reject(stream, session, logger, sqlStateInvalidCatalogName,
			fmt.Sprintf("database %q is not available through the Twingate Gateway", session.database), nil)

		return nil
	}

	creds, err := h.credentials.credentials(ctx, user.Username)
	if err != nil {
		message := "the Twingate Gateway could not obtain database credentials"
		if errors.Is(err, errUserNotAllowed) {
			message = "user is not allowed to log in through the Twingate Gateway"
		}

		h.reject(stream, session, logger, sqlStateInvalidAuthorization, message, err)

		return nil
	}

	session.dbUser = creds.user

	server, err := h.upstream.connect(ctx, creds, session.database, sessionParams(startup.params, user.Username))
	if err != nil {
		h.rejectConnect(stream, session, logger, err)

		return nil
	}
	defer server.Conn.Close()

	if err := h.startSession(stream, startup, server); err != nil {
		return fmt.Errorf("start session: %w", err)
	}

	unregister := h.cancels.register(server.PID, server.SecretKey, user.Username)
	defer unregister()

	logger.Info("Postgres session started", zap.Any("postgres", session.fields(map[string]any{
		"server_version": server.ParameterStatuses["server_version"],
	})))

	start := time.Now()
	queries, err := h.relay(stream, server.Conn, session, logger)

	logger.Info("Postgres session ended", zap.Any("postgres", session.fields(map[string]any{
		"queries":     queries,
		"duration_ms": time.Since(start).Milliseconds(),
	})))

	return err
}

// readStartup reads the client's startup message, refusing any encryption requests before it, or
// a cancel request.
func readStartup(stream io.ReadWriter) (*startupMessage, *cancelRequest, error) {
	for range maxStartupRequests {
		code, body, err := readStartupPacket(stream)
		if err != nil {
			return nil, nil, err
		}

		switch code {
		case sslRequestCode, gssEncRequestCode:
			if len(body) != 0 {
				return nil, nil, fmt.Errorf("%w: encryption request with a body", errInvalidStartupPacket)
			}

			if _, err := stream.Write([]byte{encryptionRefused}); err != nil {
				return nil, nil, err
			}
		case cancelRequestCode:
			req, err := parseCancelRequest(body)
			if err != nil {
				return nil, nil, err
			}

			return nil, req, nil
		default:
			msg, err := parseStartupMessage(code, body)
			if err != nil {
				return nil, nil, err
			}

			return msg, nil, nil
		}
	}

	return nil, nil, errTooManyStartupRequests
}

// sessionParams returns the startup parameters sent to the server: the client's allowed ones, and
// an application name identifying the Twingate user.
func sessionParams(clientParams map[string]string, username string) map[string]string {
	params := make(map[string]string)

	for name, value := range clientParams {
		if _, ok := forwardedParams[strings.ToLower(name)]; ok {
			params[name] = value
		}
	}

	params["application_name"] = applicationNamePrefix + username

	return params
}

// startSession tells the client it is logged in, passing on the server's session details.
func (h *Handler) startSession(stream io.Writer, startup *startupMessage, server *pgconn.HijackedConn) error {
	var msgs []pgproto3.BackendMessage

	// The Gateway speaks protocol 3.0 to the server, so it negotiates the client down too. Servers
	// send the full version number in this field, and libpq rejects anything below 3.0.
	if startup.minorVersion > 0 || len(startup.pqOptions) > 0 {
		msgs = append(msgs, &pgproto3.NegotiateProtocolVersion{
			NewestMinorProtocol: protocolVersion30,
			UnrecognizedOptions: startup.pqOptions,
		})
	}

	msgs = append(msgs, &pgproto3.AuthenticationOk{})

	for _, name := range slices.Sorted(maps.Keys(server.ParameterStatuses)) {
		msgs = append(msgs, &pgproto3.ParameterStatus{Name: name, Value: server.ParameterStatuses[name]})
	}

	msgs = append(msgs,
		&pgproto3.BackendKeyData{ProcessID: server.PID, SecretKey: server.SecretKey},
		&pgproto3.ReadyForQuery{TxStatus: server.TxStatus},
	)

	return writeMessages(stream, msgs...)
}

// relay passes messages between the client and server until either side ends the session,
// returning how many queries were logged.
func (h *Handler) relay(client io.ReadWriteCloser, server net.Conn, session *sessionContext, logger *zap.Logger) (int, error) {
	serverWriter := bufio.NewWriterSize(server, relayBufferSize)
	clientWriter := bufio.NewWriterSize(client, relayBufferSize)

	audit := newAuditTracker(session, logger, serverWriter.Flush)

	clientSide := newClientRelay(bufio.NewReaderSize(client, relayBufferSize), serverWriter, audit, h.maxQueryLength)
	serverSide := &serverRelay{r: bufio.NewReaderSize(server, relayBufferSize), w: clientWriter, audit: audit}

	var (
		wg      sync.WaitGroup
		errs    [2]error
		closeFn sync.Once
	)

	// When either direction ends, closing both connections ends the other, and closing the audit
	// tracker releases the client side if it is waiting for the server to catch up.
	closeBoth := func() {
		closeFn.Do(func() {
			_ = client.Close()
			_ = server.Close()

			audit.close()
		})
	}

	wg.Go(func() {
		defer closeBoth()

		errs[0] = clientSide.run()
	})
	wg.Go(func() {
		defer closeBoth()

		errs[1] = serverSide.run()
	})
	wg.Wait()

	for _, err := range errs {
		if err != nil && !isClosedErr(err) && !errors.Is(err, errAuditClosed) {
			return audit.queriesLogged(), err
		}
	}

	return audit.queriesLogged(), nil
}

// isClosedErr reports whether err only means a connection was closed.
func isClosedErr(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}

func (h *Handler) forwardCancel(ctx context.Context, req *cancelRequest, username string, session *sessionContext, logger *zap.Logger) {
	fields := session.fields(map[string]any{"process_id": req.processID})

	// The server sends no reply to a cancel request, so the client learns nothing either way.
	if !h.cancels.ownedBy(req, username) {
		logger.Warn("Postgres cancel request rejected: no matching session for this user", zap.Any("postgres", fields))

		return
	}

	if err := h.upstream.cancel(ctx, req); err != nil {
		logger.Warn("Postgres cancel request failed", zap.Any("postgres", fields), zap.Error(err))

		return
	}

	logger.Info("Postgres cancel request forwarded", zap.Any("postgres", fields))
}

func (h *Handler) rejectStartup(stream io.Writer, err error, session *sessionContext, logger *zap.Logger) error {
	switch {
	case errors.Is(err, errUnsupportedProtocol):
		h.reject(stream, session, logger, sqlStateFeatureNotSupported, err.Error(), nil)
	case errors.Is(err, errInvalidStartupPacket), errors.Is(err, errTooManyStartupRequests):
		h.reject(stream, session, logger, sqlStateProtocolViolation, err.Error(), nil)
	default:
		// The client went away or stalled; there is no one to tell.
		logger.Debug("Postgres client closed before startup", zap.Any("postgres", session.fields(nil)), zap.Error(err))
	}

	return nil
}

// rejectConnect reports a failure to log in to the server. The server's own error, such as an IAM
// permission failure, is passed on so the user can act on it.
func (h *Handler) rejectConnect(stream io.Writer, session *sessionContext, logger *zap.Logger, err error) {
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
		h.reject(stream, session, logger, pgErr.Code, pgErr.Message, err)

		return
	}

	h.reject(stream, session, logger, sqlStateConnectionFailure, "the Twingate Gateway could not connect to the database server", err)
}

func (h *Handler) reject(stream io.Writer, session *sessionContext, logger *zap.Logger, code, message string, cause error) {
	fields := []zap.Field{zap.Any("postgres", session.fields(map[string]any{
		"error": map[string]any{"code": code, "message": message},
	}))}
	if cause != nil {
		fields = append(fields, zap.Error(cause))
	}

	logger.Warn("Postgres session rejected", fields...)

	if err := writeFatal(stream, code, message); err != nil {
		logger.Debug("Failed to send error to Postgres client", zap.Error(err))
	}
}

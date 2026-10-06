// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/jackc/pgx/v5/pgproto3"
)

// Startup packet request codes, from the PostgreSQL frontend/backend protocol.
const (
	protocolVersion30 uint32 = 3 << 16
	sslRequestCode    uint32 = 80877103
	gssEncRequestCode uint32 = 80877104
	cancelRequestCode uint32 = 80877102
)

// maxStartupPacketLen matches the PostgreSQL server's limit on a startup packet.
const maxStartupPacketLen = 10000

// pqOptionPrefix marks protocol extension options in a startup message, which the Gateway does not
// support and reports back to the client as unrecognized.
const pqOptionPrefix = "_pq_."

// SQLSTATE codes the Gateway reports to clients.
const (
	sqlStateProtocolViolation    = "08P01"
	sqlStateConnectionFailure    = "08006"
	sqlStateInvalidAuthorization = "28000"
	sqlStateInvalidCatalogName   = "3D000"
	sqlStateFeatureNotSupported  = "0A000"
)

const severityFatal = "FATAL"

// encryptionRefused is the reply to an SSL or GSSAPI encryption request. The client's stream is
// already encrypted by SSH inside Twingate's TLS tunnel.
const encryptionRefused = 'N'

var (
	errInvalidStartupPacket = errors.New("invalid startup packet")
	errUnsupportedProtocol  = errors.New("unsupported protocol version")
)

// startupMessage is the client's request to open a session.
type startupMessage struct {
	minorVersion uint32
	params       map[string]string

	// pqOptions are the protocol extension options the client asked for.
	pqOptions []string
}

// cancelRequest asks the server to cancel the query running in another session.
type cancelRequest struct {
	processID uint32
	secretKey []byte
}

// readStartupPacket reads one length-prefixed startup packet, returning its request code and the
// bytes after it.
func readStartupPacket(r io.Reader) (uint32, []byte, error) {
	var header [8]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}

	length := binary.BigEndian.Uint32(header[:4])
	if length < uint32(len(header)) || length > maxStartupPacketLen {
		return 0, nil, fmt.Errorf("%w: length %d", errInvalidStartupPacket, length)
	}

	body := make([]byte, length-uint32(len(header)))
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}

	return binary.BigEndian.Uint32(header[4:]), body, nil
}

func parseStartupMessage(code uint32, body []byte) (*startupMessage, error) {
	if code>>16 != protocolVersion30>>16 {
		return nil, fmt.Errorf("%w: %d.%d", errUnsupportedProtocol, code>>16, code&0xFFFF)
	}

	msg := &startupMessage{
		minorVersion: code & 0xFFFF,
		params:       make(map[string]string),
	}

	for {
		key, rest, err := readCString(body)
		if err != nil {
			return nil, err
		}

		if key == "" {
			// The parameter list ends with an empty name.
			return msg, nil
		}

		value, rest, err := readCString(rest)
		if err != nil {
			return nil, err
		}

		if strings.HasPrefix(key, pqOptionPrefix) {
			msg.pqOptions = append(msg.pqOptions, key)
		} else {
			msg.params[key] = value
		}

		body = rest
	}
}

func parseCancelRequest(body []byte) (*cancelRequest, error) {
	// The process ID is followed by a secret key of 4 bytes (protocol 3.0) or up to 256 (3.2).
	if len(body) < 8 || len(body) > 4+256 {
		return nil, fmt.Errorf("%w: cancel request length %d", errInvalidStartupPacket, len(body))
	}

	return &cancelRequest{
		processID: binary.BigEndian.Uint32(body[:4]),
		secretKey: bytes.Clone(body[4:]),
	}, nil
}

// encodeCancelRequest encodes a cancel request startup packet.
func encodeCancelRequest(req *cancelRequest) []byte {
	buf := make([]byte, 12, 12+len(req.secretKey))
	binary.BigEndian.PutUint32(buf[0:4], uint32(12+len(req.secretKey))) //nolint:gosec // The secret key is at most 256 bytes
	binary.BigEndian.PutUint32(buf[4:8], cancelRequestCode)
	binary.BigEndian.PutUint32(buf[8:12], req.processID)

	return append(buf, req.secretKey...)
}

// readCString splits a NUL-terminated string off the front of b.
func readCString(b []byte) (string, []byte, error) {
	s, rest, ok := cString(b)
	if !ok {
		return "", nil, fmt.Errorf("%w: unterminated string", errInvalidStartupPacket)
	}

	return s, rest, nil
}

// writeMessages encodes msgs and writes them to w in one write.
func writeMessages(w io.Writer, msgs ...pgproto3.BackendMessage) error {
	var buf []byte

	for _, msg := range msgs {
		var err error

		buf, err = msg.Encode(buf)
		if err != nil {
			return fmt.Errorf("encode %T: %w", msg, err)
		}
	}

	_, err := w.Write(buf)

	return err
}

// writeFatal sends the client a FATAL error, after which the session ends.
func writeFatal(w io.Writer, code, message string) error {
	return writeMessages(w, &pgproto3.ErrorResponse{
		Severity:            severityFatal,
		SeverityUnlocalized: severityFatal,
		Code:                code,
		Message:             message,
	})
}

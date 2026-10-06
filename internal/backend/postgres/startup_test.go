// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseStartupMessage(t *testing.T) {
	body := []byte("user\x00beekeeper\x00database\x00app\x00_pq_.feature\x00on\x00\x00")

	msg, err := parseStartupMessage(protocolVersion30|2, body)
	require.NoError(t, err)

	assert.Equal(t, uint32(2), msg.minorVersion)
	assert.Equal(t, map[string]string{"user": "beekeeper", "database": "app"}, msg.params)
	assert.Equal(t, []string{"_pq_.feature"}, msg.pqOptions)
}

func TestParseStartupMessage_Errors(t *testing.T) {
	tests := []struct {
		name    string
		code    uint32
		body    []byte
		wantErr error
	}{
		{name: "protocol 2", code: 2 << 16, body: []byte{0}, wantErr: errUnsupportedProtocol},
		{name: "unterminated name", code: protocolVersion30, body: []byte("user"), wantErr: errInvalidStartupPacket},
		{name: "missing value", code: protocolVersion30, body: []byte("user\x00"), wantErr: errInvalidStartupPacket},
		{name: "missing list terminator", code: protocolVersion30, body: []byte("user\x00alice\x00"), wantErr: errInvalidStartupPacket},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseStartupMessage(tt.code, tt.body)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestReadStartupPacket_Length(t *testing.T) {
	packet := func(length uint32) []byte {
		buf := binary.BigEndian.AppendUint32(nil, length)

		return binary.BigEndian.AppendUint32(buf, protocolVersion30)
	}

	_, _, err := readStartupPacket(bytes.NewReader(packet(7)))
	require.ErrorIs(t, err, errInvalidStartupPacket)

	_, _, err = readStartupPacket(bytes.NewReader(packet(maxStartupPacketLen + 1)))
	require.ErrorIs(t, err, errInvalidStartupPacket)

	code, body, err := readStartupPacket(bytes.NewReader(append(packet(9), 0)))
	require.NoError(t, err)
	assert.Equal(t, protocolVersion30, code)
	assert.Equal(t, []byte{0}, body)
}

func TestCancelRequest_RoundTrip(t *testing.T) {
	for _, secretKey := range [][]byte{{1, 2, 3, 4}, bytes.Repeat([]byte{7}, 32)} {
		req := &cancelRequest{processID: 42, secretKey: secretKey}

		code, body, err := readStartupPacket(bytes.NewReader(encodeCancelRequest(req)))
		require.NoError(t, err)
		assert.Equal(t, cancelRequestCode, code)

		parsed, err := parseCancelRequest(body)
		require.NoError(t, err)
		assert.Equal(t, req, parsed)
	}
}

func TestParseCancelRequest_InvalidLength(t *testing.T) {
	_, err := parseCancelRequest(make([]byte, 7))
	require.ErrorIs(t, err, errInvalidStartupPacket)

	_, err = parseCancelRequest(make([]byte, 4+257))
	require.ErrorIs(t, err, errInvalidStartupPacket)
}

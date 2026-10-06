// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// countingTokenSource returns a fixed token after an optional delay, counting calls.
type countingTokenSource struct {
	token string
	err   error
	delay time.Duration
	calls atomic.Int32
}

func (c *countingTokenSource) Token() (*oauth2.Token, error) {
	c.calls.Add(1)
	time.Sleep(c.delay)

	if c.err != nil {
		return nil, c.err
	}

	return &oauth2.Token{AccessToken: c.token}, nil
}

func TestGCPIAMCredentials_Credentials(t *testing.T) {
	var subjects []string

	tokenSource := &countingTokenSource{token: "user-token"}
	creds, err := newGCPIAMCredentialsWithTokenSource([]string{"Example.com"}, func(subject string) (oauth2.TokenSource, error) {
		subjects = append(subjects, subject)

		return tokenSource, nil
	})
	require.NoError(t, err)

	got, err := creds.credentials(t.Context(), " Alice@Example.COM ")
	require.NoError(t, err)

	// Cloud SQL IAM users are the lowercase email; the password is the user's access token.
	assert.Equal(t, credentials{user: "alice@example.com", password: "user-token"}, got)

	_, err = creds.credentials(t.Context(), "alice@example.com")
	require.NoError(t, err)

	assert.Equal(t, []string{"alice@example.com"}, subjects, "the token source is created once per user and reused")
	assert.Equal(t, int32(2), tokenSource.calls.Load())
}

func TestGCPIAMCredentials_RejectsUsers(t *testing.T) {
	creds, err := newGCPIAMCredentialsWithTokenSource([]string{"example.com"}, func(string) (oauth2.TokenSource, error) {
		t.Fatal("no token may be requested for a rejected user")

		return nil, nil //nolint:nilnil // unreachable
	})
	require.NoError(t, err)

	for _, username := range []string{
		"",
		"alice",
		"@example.com",
		"alice@other.com",
		"alice@sub.example.com",
		"alice@example.com@other.com",
	} {
		t.Run(username, func(t *testing.T) {
			_, err := creds.credentials(t.Context(), username)
			assert.ErrorIs(t, err, errUserNotAllowed)
		})
	}
}

func TestGCPIAMCredentials_Errors(t *testing.T) {
	errTokenSource := errors.New("token source failed")

	t.Run("token source creation fails", func(t *testing.T) {
		creds, err := newGCPIAMCredentialsWithTokenSource([]string{"example.com"}, func(string) (oauth2.TokenSource, error) {
			return nil, errTokenSource
		})
		require.NoError(t, err)

		_, err = creds.credentials(t.Context(), testUser)
		assert.ErrorIs(t, err, errTokenSource)
	})

	t.Run("token request fails", func(t *testing.T) {
		creds, err := newGCPIAMCredentialsWithTokenSource([]string{"example.com"}, func(string) (oauth2.TokenSource, error) {
			return &countingTokenSource{err: errTokenSource}, nil
		})
		require.NoError(t, err)

		_, err = creds.credentials(t.Context(), testUser)
		assert.ErrorIs(t, err, errTokenSource)
	})

	t.Run("token request outlives the context", func(t *testing.T) {
		creds, err := newGCPIAMCredentialsWithTokenSource([]string{"example.com"}, func(string) (oauth2.TokenSource, error) {
			return &countingTokenSource{token: "late", delay: time.Second}, nil
		})
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
		defer cancel()

		_, err = creds.credentials(ctx, testUser)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	})
}

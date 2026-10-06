// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/oauth2"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"

	lru "github.com/hashicorp/golang-lru/v2"

	"gateway/internal/config"
)

// sqlLoginScope is the only OAuth scope Cloud SQL IAM database authentication needs.
const sqlLoginScope = "https://www.googleapis.com/auth/sqlservice.login"

// tokenSourceCacheSize bounds the per-user token sources kept for reuse between connections.
const tokenSourceCacheSize = 1024

var errUserNotAllowed = errors.New("user is not allowed to log in")

// credentials are what the Gateway presents to the PostgreSQL server to log in.
type credentials struct {
	user     string
	password string
}

// credentialSource returns the PostgreSQL credentials for a Twingate user.
type credentialSource interface {
	credentials(ctx context.Context, username string) (credentials, error)
}

// gcpIAMCredentials logs in to Cloud SQL as the Twingate user through IAM database authentication.
// The user's access token comes from a service account with Google Workspace domain-wide
// delegation, impersonating the user with only the sqlservice.login scope.
type gcpIAMCredentials struct {
	allowedDomains map[string]struct{}

	// tokenSources caches a token source per user, so a token is reused until it expires.
	tokenSources *lru.Cache[string, oauth2.TokenSource]

	newTokenSource func(subject string) (oauth2.TokenSource, error)
}

func newGCPIAMCredentials(cfg *config.PostgresGCPIAMAuthConfig) (*gcpIAMCredentials, error) {
	var opts []option.ClientOption
	if cfg.CredentialsFile != "" {
		opts = append(opts, option.WithAuthCredentialsFile(option.ServiceAccount, cfg.CredentialsFile))
	}

	newTokenSource := func(subject string) (oauth2.TokenSource, error) {
		// The token source refreshes with this context, so it must outlive any one connection.
		return impersonate.CredentialsTokenSource(context.Background(), impersonate.CredentialsConfig{
			TargetPrincipal: cfg.ServiceAccount,
			Scopes:          []string{sqlLoginScope},
			Subject:         subject,
		}, opts...)
	}

	return newGCPIAMCredentialsWithTokenSource(cfg.AllowedDomains, newTokenSource)
}

func newGCPIAMCredentialsWithTokenSource(allowedDomains []string, newTokenSource func(subject string) (oauth2.TokenSource, error)) (*gcpIAMCredentials, error) {
	domains := make(map[string]struct{}, len(allowedDomains))
	for _, domain := range allowedDomains {
		domains[strings.ToLower(domain)] = struct{}{}
	}

	cache, err := lru.New[string, oauth2.TokenSource](tokenSourceCacheSize)
	if err != nil {
		return nil, fmt.Errorf("create token source cache: %w", err)
	}

	return &gcpIAMCredentials{
		allowedDomains: domains,
		tokenSources:   cache,
		newTokenSource: newTokenSource,
	}, nil
}

func (g *gcpIAMCredentials) credentials(ctx context.Context, username string) (credentials, error) {
	email, err := g.allowedEmail(username)
	if err != nil {
		return credentials{}, err
	}

	tokenSource, ok := g.tokenSources.Get(email)
	if !ok {
		tokenSource, err = g.newTokenSource(email)
		if err != nil {
			return credentials{}, fmt.Errorf("create token source: %w", err)
		}

		g.tokenSources.Add(email, tokenSource)
	}

	tok, err := tokenWithContext(ctx, tokenSource)
	if err != nil {
		return credentials{}, fmt.Errorf("get access token: %w", err)
	}

	// Cloud SQL names a PostgreSQL IAM user by its full email address.
	return credentials{user: email, password: tok.AccessToken}, nil
}

// allowedEmail normalizes username to the lowercase email Cloud SQL expects, and checks that its
// domain is allowed, so the Gateway never requests a token for any other identity.
func (g *gcpIAMCredentials) allowedEmail(username string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(username))

	local, domain, found := strings.Cut(email, "@")
	if !found || local == "" || strings.Contains(domain, "@") {
		return "", fmt.Errorf("%w: %q is not an email address", errUserNotAllowed, username)
	}

	if _, ok := g.allowedDomains[domain]; !ok {
		return "", fmt.Errorf("%w: domain %q is not allowed", errUserNotAllowed, domain)
	}

	return email, nil
}

// tokenWithContext fetches a token, giving up when ctx is done. oauth2.TokenSource takes no
// context, so a request that outlives ctx finishes in the background and is discarded.
func tokenWithContext(ctx context.Context, tokenSource oauth2.TokenSource) (*oauth2.Token, error) {
	type result struct {
		tok *oauth2.Token
		err error
	}

	done := make(chan result, 1)

	go func() {
		tok, err := tokenSource.Token()
		done <- result{tok: tok, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-done:
		return res.tok, res.err
	}
}

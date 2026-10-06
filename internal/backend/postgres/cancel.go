// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import "sync"

// cancelKey identifies a server session for a cancel request.
type cancelKey struct {
	processID uint32
	secretKey string
}

// cancelRegistry records the sessions the Gateway opened and who owns them, so a cancel request is
// forwarded only for a live session belonging to the requesting user.
type cancelRegistry struct {
	mu     sync.Mutex
	owners map[cancelKey]string
}

func newCancelRegistry() *cancelRegistry {
	return &cancelRegistry{owners: make(map[cancelKey]string)}
}

// register records a session owned by owner, returning a function that removes it.
func (r *cancelRegistry) register(processID uint32, secretKey []byte, owner string) func() {
	key := cancelKey{processID: processID, secretKey: string(secretKey)}

	r.mu.Lock()
	r.owners[key] = owner
	r.mu.Unlock()

	return func() {
		r.mu.Lock()
		delete(r.owners, key)
		r.mu.Unlock()
	}
}

// ownedBy reports whether req targets a live session owned by owner.
func (r *cancelRegistry) ownedBy(req *cancelRequest, owner string) bool {
	key := cancelKey{processID: req.processID, secretKey: string(req.secretKey)}

	r.mu.Lock()
	defer r.mu.Unlock()

	registered, ok := r.owners[key]

	return ok && registered == owner
}

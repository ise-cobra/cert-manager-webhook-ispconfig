// Package ddnstest provides test doubles of the ISPConfig DDNS remote side: a stateful
// RecordStore and an httptest server that replicates the documented semantics of
// /ddns/update.php (ispconfig-ddns-module v1.4.2).
//
// # Why regular files instead of _test.go
//
// Test doubles must not end up in the release binary. These doubles are needed by several
// packages — internal/solver for the round-trip test, e2e for the conformance suite — and Go
// cannot import _test.go files across packages. They therefore live in regular files of a
// dedicated package that is imported exclusively by tests. No production path refers to
// ddnstest, so the compiler never links it into cmd/webhook.
package ddnstest

import (
	"sort"
	"sync"

	"github.com/miekg/dns"
)

// RecordStore is an in-memory zone: several TXT values per name.
//
// CAUTION — this is the one assumption of this double that is not backed by the module's
// response matrix. The service requires it (wildcard certificates create two challenges with
// the same record name, both of which must exist at the same time; see the conformance test
// "DeletingOneRecordRetainsOthers"), but the documented matrix only covers the case of an
// *identical* name **and** value. Whether `add` on an existing TXT name with a different value
// creates a second value in the real module or runs into the update branch forbidden for TXT
// cannot be proven here.
//
// If the module does not support it, exactly the core case of the service fails in production
// while the test suite stays green. It has to be verified against a real ISPConfig server
// (wildcard certificate against the ACME staging directory) — until then it is an open risk,
// not documented behavior.
//
// It is also the link between several fakes — the fake DDNS server writes, a fake name server
// can read. Only this way does a test check the result of a DDNS call and not merely that the
// call returns without an error.
//
// The key is always the canonical name (lowercase, with trailing dot). This is the only place
// of normalization: the DDNS API works with FQDNs *without* trailing dot, DNS questions come
// *with* a dot and in arbitrary case.
type RecordStore struct {
	mu     sync.Mutex
	values map[string][]string
}

// NewRecordStore returns an empty store. It is safe for concurrent use.
func NewRecordStore() *RecordStore {
	return &RecordStore{values: make(map[string][]string)}
}

// Add creates a TXT value. The return value is false if the combination of name and value
// already exists — the ISPConfig case "ERROR: ... is already set ...".
func (s *RecordStore) Add(name, value string) bool {
	key := dns.CanonicalName(name)

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, existing := range s.values[key] {
		if existing == value {
			return false
		}
	}
	s.values[key] = append(s.values[key], value)

	return true
}

// Remove deletes exactly that one value and leaves all other values of the same name in place.
// The return value is false if the value does not exist — the ISPConfig case "404 Could not
// find record".
func (s *RecordStore) Remove(name, value string) bool {
	key := dns.CanonicalName(name)

	s.mu.Lock()
	defer s.mu.Unlock()

	for i, existing := range s.values[key] {
		if existing != value {
			continue
		}
		s.values[key] = append(s.values[key][:i], s.values[key][i+1:]...)
		if len(s.values[key]) == 0 {
			delete(s.values, key)
		}

		return true
	}

	return false
}

// Lookup returns the TXT values of a name in stable order.
func (s *RecordStore) Lookup(name string) []string {
	key := dns.CanonicalName(name)

	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]string, len(s.values[key]))
	copy(out, s.values[key])
	sort.Strings(out)

	return out
}

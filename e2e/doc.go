//go:build e2e

// Package e2e contains the cert-manager conformance suite for the DNS01 solver.
//
// # Why the `e2e` build tag
//
// Via `envtest`, the suite starts real `etcd` and `kube-apiserver` binaries and calls
// `kubectl`. cert-manager already panics in the `init()` of `test/apiserver` when
// `TEST_ASSET_ETCD`, `TEST_ASSET_KUBE_APISERVER` and `TEST_ASSET_KUBECTL` are not set —
// `KUBEBUILDER_ASSETS` alone is not enough. `setup-envtest` does not provide these assets for
// `windows/amd64`. Without the build tag, `go test ./...` would fail on every machine without
// these assets. The suite therefore only runs explicitly:
//
//	go test -tags e2e -v ./e2e/...
//
// See e2e/README.md for details.
//
// # Layout
//
// This file is the only non-test file of the package; it exists so that
// `go build -tags e2e ./e2e/...` finds a package. The fake DDNS server and the shared in-memory
// zone live in `internal/ispconfig/ddnstest` because the round-trip test in `internal/solver`
// needs them as well; the fake name server stays here as `_test.go`, since only the
// conformance suite queries via DNS. None of this is shipped.
package e2e

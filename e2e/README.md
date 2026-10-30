# e2e — cert-manager conformance suite

Runs cert-manager's official DNS01 conformance suite
(`github.com/cert-manager/cert-manager/test/acme`) against `internal/solver`.

## What the suite checks

| Test case | Content |
|---|---|
| `Conformance/Basic/PresentRecord` | `Present` creates the TXT record, it can be queried via DNS, `CleanUp` removes it again |
| `Conformance/Extended/DeletingOneRecordRetainsOthers` | Two TXT values on the same record name; deleting one leaves the other in place — the wildcard case (`example.com` plus `*.example.com`) |

The second test only runs with `acmetest.SetStrict(true)`; without it the suite calls `t.Skip`.

## The double fake

This test uses **no** real ISPConfig installation and no real token: a run against a real
server would not be reproducible and would need a real zone. Instead:

```
Solver --HTTP--> fake DDNS (httptest)  --writes--> RecordStore
                                                       |
conformance suite --DNS/UDP--> fake DNS (miekg/dns) <--+ reads
```

- **`internal/ispconfig/ddnstest`** (`ddnstest.Server`) speaks the semantics of
  `/ddns/update.php` (`ispconfig-ddns-module` v1.4.2, `DefaultDdnsResponseWriter`): status codes,
  bodies, token filtering (`[^0-9a-f^]` is silently removed), `403` for foreign record types,
  `403` when `zone` is sent, `200` with `ERROR: ... is already set ...` on a duplicate `add`,
  `404` on `delete` of a value that does not exist.
- **`internal/ispconfig/ddnstest`** (`ddnstest.RecordStore`) is the shared in-memory zone. It is
  the only place where names are normalized (`dns.CanonicalName`) — the DDNS API works with
  FQDNs *without* trailing dot, DNS questions arrive *with* the dot.
- **`fakedns_test.go`** is an authoritative UDP name server on `127.0.0.1:<free port>` that
  builds TXT answers exclusively from the `RecordStore`. It stays here because only the
  conformance suite queries via DNS.

Server and store live in their own package `ddnstest` because
`internal/solver/roundtrip_test.go` needs them as well — the same round trip without build tag,
but without `envtest` and without DNS queries.

Because both fakes use the same store, the suite actually checks the result of the DDNS call,
not merely that `Present` returned without error.

The fake DDNS deliberately runs as **HTTP** (`httptest.NewServer`, not `NewTLSServer`); the test
sets `AllowInsecureEndpoint: true` for that. Reason: the `httptest` self-signed certificate
would otherwise have to reach the solver's HTTP client as CA bundle, and `solver.Defaults` offers
no hook for that. Apart from the TLS layer, the client code exercised is identical.

The 60 s cron delay of a real ISPConfig installation is not reproduced — the fake propagates
immediately. `SetPollInterval(200ms)` and `SetPropagationLimit(30s)` therefore keep the run
short.

## Configuration: `SetConfig` instead of `config.json`

`testdata/ispconfig-solver/` contains two files:

- **`secret.yaml`** — the token Secret. The suite's `setupNamespace()` applies all
  `.json`/`.yaml`/`.yml` files from the `SetManifestPath` directory via `kubectl apply` in the
  test namespace. That is why `SetManifestPath` is still required. The token is a
  **synthetic** lowercase hex value and must match `testToken` in `conformance_test.go`
  verbatim.
- **`config.json`** — documents the field names of the `config` block. The file is
  **inactive** during the run, for two reasons: `setupNamespace()` skips it during
  `kubectl apply`, and `applyDefaults()` in `fixture.go` only reads it while
  `jsonConfig == nil` — which is never the case because of `acmetest.SetConfig(...)`. Its
  `endpoint` therefore deliberately points to `http://127.0.0.1:1`: should `SetConfig` ever be
  dropped, the test fails immediately and loudly instead of silently running against a real
  host.

The address of the `httptest` server is only known at runtime — hence `SetConfig`.

## `acmetest` options used

| Option | Value | Why |
|---|---|---|
| `SetResolvedZone` | `example.com.` | zone for which the fake DNS answers authoritatively |
| `SetResolvedFQDN` | `_acme-challenge.example.com.` | `validate()` requires a trailing dot |
| `SetDNSName` | `example.com` | domain in the `ChallengeRequest` |
| `SetConfig` | `endpoint`, `tokenSecretRef`, `httpTimeout`, `tokenAuthMode` | endpoint only known at runtime; strict decoding in the solver turns naming drift into a test failure |
| `SetManifestPath` | `testdata/ispconfig-solver` | for `secret.yaml` |
| `SetDNSServer` | `127.0.0.1:<port>` | the fake name server |
| `SetUseAuthoritative` | `false` | otherwise the suite determines the zone's real NS and queries them |
| `SetStrict` | `true` | without it the wildcard test is skipped |
| `SetAllowAmbientCredentials` | `false` | the solver has no ambient credentials |
| `SetPollInterval` | `200ms` | the fake propagates immediately |
| `SetPropagationLimit` | `30s` | the default of 2 min is unnecessarily long |

`RunConformance` calls `setup(t)` and within it `RunBasic`/`RunExtended`, which call `setup(t)`
**again**: the control plane starts three times, `Initialize` is called three times.
`Initialize` is idempotent accordingly.

## Why the `e2e` build tag

Via `envtest`, the suite starts real `etcd` and `kube-apiserver` binaries and calls `kubectl`.
cert-manager already panics in the `init()` of `test/apiserver` when `TEST_ASSET_ETCD`,
`TEST_ASSET_KUBE_APISERVER` and `TEST_ASSET_KUBECTL` are not set — `KUBEBUILDER_ASSETS` alone is
**not** enough.

The package carries the build constraint `e2e`: a plain `go test ./...` skips it, so it does
not fail on machines without these assets. Run it explicitly with `-tags e2e`.

## Running

`setup-envtest` provides the assets only for `linux/*` and `darwin/*` — on Windows, use WSL2.

`setup-envtest` belongs to `sigs.k8s.io/controller-runtime`; this module's version is `v0.23.1`
(`go list -m sigs.k8s.io/controller-runtime`), so the matching branch is `release-0.23`. The
Kubernetes version follows from `k8s.io/api v0.35.2`, i.e. `1.35`.

```shell
go install sigs.k8s.io/controller-runtime/tools/setup-envtest@release-0.23

ASSETS=$(setup-envtest use 1.35 --bin-dir ./_out/envtest -p path)   # ./_out/ is in .gitignore
export TEST_ASSET_ETCD="$ASSETS/etcd"
export TEST_ASSET_KUBE_APISERVER="$ASSETS/kube-apiserver"
export TEST_ASSET_KUBECTL="$ASSETS/kubectl"

go test -tags e2e -v ./e2e/...
```

If `1.35` is not yet available, `setup-envtest list --remote` lists the available versions;
the closest one is sufficient, as the suite only uses namespaces and Secrets.

## Static check without running

The build tag keeps the package out of `go test ./...` — compile errors therefore do not
surface there. Run additionally:

```shell
go vet -tags e2e ./e2e/...
go build -tags e2e ./e2e/...
golangci-lint run ./e2e/...
```

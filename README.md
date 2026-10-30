# cert-manager-webhook-ispconfig

[![CI](https://github.com/ise-cobra/cert-manager-webhook-ispconfig/actions/workflows/ci.yml/badge.svg)](https://github.com/ise-cobra/cert-manager-webhook-ispconfig/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A [cert-manager](https://cert-manager.io) DNS01 solver webhook for domains whose DNS is managed
by [ISPConfig](https://www.ispconfig.org). It lets cert-manager issue **wildcard certificates**
automatically, which the HTTP01 solver cannot do.

The webhook talks to the ISPConfig **DDNS token API**
([ispconfig-ddns-module](https://github.com/mhofer117/ispconfig-ddns-module)), not to the
ISPConfig remote API. That is the key difference to other ISPConfig webhooks: a DDNS token can be
restricted to the record type `TXT` and to the name `_acme-challenge`. If it leaks, the damage is
limited to exactly these records, whereas a remote API user with a password grants full DNS
access.

## How it works

```text
cert-manager  ──(APIService, TLS)──▶  webhook  ──(HTTPS)──▶  ISPConfig DDNS API
                                         │
                                         └──▶ Secret with the DDNS token
```

1. For each challenge, cert-manager creates a `ChallengeRequest` and calls the webhook through
   the Kubernetes aggregation layer.
2. The webhook reads the DDNS token from the secret referenced by the issuer.
3. It creates or removes the TXT record via `POST`/`DELETE` on `<endpoint>/ddns/update.php`.
4. cert-manager checks DNS propagation itself and completes the challenge.

## Prerequisites

- A Kubernetes cluster with the aggregation layer enabled (the default), Kubernetes ≥ 1.30
- cert-manager ≥ 1.12 (the chart only uses `cert-manager.io/v1` and the stable `v1alpha1`
  webhook API)
- An ISPConfig server with the
  [ispconfig-ddns-module](https://github.com/mhofer117/ispconfig-ddns-module) installed, and a
  DDNS token created under **DNS → Tokens**:
  - **Allowed DNS types**: `TXT`
  - **Limit records** (recommended): `_acme-challenge`
  - Only add **non-overlapping** zones to one token. Overlapping zones (`example.com` *and*
    `sub.example.com`) make the module fail.

## Installation

```shell
helm install cert-manager-webhook-ispconfig \
  oci://ghcr.io/ise-cobra/charts/cert-manager-webhook-ispconfig \
  --namespace cert-manager \
  --set groupName=acme.example.com \
  --set webhook.endpoint=https://ispconfig.example.com \
  --set 'rbac.secretResourceNames[0]=ispconfig-ddns-token'
```

`groupName` and `webhook.endpoint` are required and have no default: a deployment without them
must fail instead of talking to an unconfigured address. Choose a `groupName` under a domain you
control; it must match the `groupName` in your issuer.

All values are documented in the
[chart README](charts/cert-manager-webhook-ispconfig/README.md). After installation, the
`APIService` must report `Available`. That is the first check:

```shell
kubectl get apiservice v1alpha1.acme.example.com
```

## Configuration

### Token secret

```shell
kubectl create secret generic ispconfig-ddns-token \
  --namespace cert-manager \
  --from-literal=token=<your-ddns-token>
```

Use `--from-literal` rather than `--from-file`: with `--from-file` the trailing newline of the
file ends up in the value. The webhook trims surrounding whitespace, but a visible error beats a
silent correction.

The token must be lowercase hex (`0`–`9`, `a`–`f`). The DDNS module silently strips other
characters and then answers `401`, so the webhook validates the format up front and reports a
clear configuration error instead.

### ClusterIssuer

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-ispconfig
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: hostmaster@example.com
    privateKeySecretRef:
      name: letsencrypt-ispconfig-account
    solvers:
      - dns01:
          webhook:
            groupName: acme.example.com
            solverName: ispconfig
            config:
              tokenSecretRef:
                name: ispconfig-ddns-token
                key: token
```

For a `ClusterIssuer`, the secret is looked up in cert-manager's **cluster resource namespace**
(`--cluster-resource-namespace`; the cert-manager Helm chart sets it to its own namespace,
usually `cert-manager`); for an `Issuer`, in the issuer's namespace.

#### Configuration fields

| Field | Required | Default | Meaning |
|-------|----------|---------|---------|
| `tokenSecretRef.name` | yes | — | Name of the secret holding the DDNS token |
| `tokenSecretRef.key` | no | `token` | Key within the secret |
| `endpoint` | no | service default (`webhook.endpoint` in the chart) | Base URL of the DDNS API |
| `httpTimeout` | no | `30s` | Timeout per DDNS call, capped at `50s` |
| `tokenAuthMode` | no | `basic` | `basic` or `query`, see below |

Unknown fields are **rejected**, so a typo does not silently fall back to a default.

`tokenAuthMode` controls how the token is transmitted. `basic` (default) sends it as the HTTP
basic auth password of the user `anonymous`; it never appears in the URL and therefore never in
network errors, access logs or traces. `query` is the documented fallback for reverse proxies
that do not pass the `Authorization` header on to PHP, recognisable by a `401` despite a correct
token.

### Wildcard certificate

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-wildcard
  namespace: default
spec:
  secretName: example-wildcard-tls
  issuerRef:
    name: letsencrypt-ispconfig
    kind: ClusterIssuer
  dnsNames:
    - "example.com"
    - "*.example.com"
```

This example covers the interesting case: apex and wildcard create **two** challenges with the
same record name `_acme-challenge.example.com` and different values. The webhook creates both
TXT records and, on cleanup, removes only its own value.

> **Not yet verified against a live ISPConfig server:** that the DDNS module adds a second
> value to an existing TXT name instead of rejecting or replacing it. The test suite assumes it
> does. Please report your result for apex plus wildcard certificates in an issue.

Test against the Let's Encrypt **staging** directory
(`https://acme-staging-v02.api.letsencrypt.org/directory`) before requesting a production
certificate; Let's Encrypt enforces strict rate limits.

### Regular certificates and subdomains

The webhook is not limited to wildcards; every entry in `dnsNames` works. Whether the **token
restriction** applies depends on how deep the name sits below the zone.

The DDNS module derives the **relative** record name from the requested FQDN and compares it
*exactly* with the token's list of allowed records:

| Certificate | Challenge FQDN | Relative name | With `limit_records=_acme-challenge` |
|-------------|----------------|---------------|--------------------------------------|
| `example.com` (apex) | `_acme-challenge.example.com` | `_acme-challenge` | works |
| `*.example.com` (wildcard) | `_acme-challenge.example.com` | `_acme-challenge` | works |
| `www.example.com` (subdomain) | `_acme-challenge.www.example.com` | `_acme-challenge.www` | **403 Permission denied for record** |

Apex and wildcard certificates work out of the box. For **subdomain** certificates there are three
options, none of which require changes to the webhook:

1. **Add `_acme-challenge.www` as an allowed record to the token.** Explicit and narrow, but has
   to be maintained per subdomain.
2. **Leave the record restriction of the token empty.** The token may then write any TXT record
   in its zones; the record type stays restricted to `TXT`. Convenient, but a larger blast radius
   if the token leaks.
3. **CNAME delegation**, the cleanest option for many subdomains. Create once in DNS:

   ```dns
   _acme-challenge.www.example.com.  CNAME  _acme-challenge.example.com.
   ```

   and enable CNAME following in the issuer:

   ```yaml
   solvers:
     - dns01:
         cnameStrategy: Follow
         webhook:
           groupName: acme.example.com
           solverName: ispconfig
           config:
             tokenSecretRef:
               name: ispconfig-ddns-token
   ```

   cert-manager follows the CNAME and hands the resolved name `_acme-challenge.example.com` to
   the webhook. The narrow token restriction to `_acme-challenge` stays intact even though the
   certificate is for a subdomain.

Note for option 3: `cnameStrategy` defaults to `None`, so the CNAME is **not** followed on its
own. Without the CNAME in DNS, the challenge still targets `_acme-challenge.www.example.com` and
fails the restriction.

## Propagation time

The DDNS module first writes the record to the ISPConfig datalog; a **cron job running every
minute** then writes it into the zone. It takes up to 60 seconds **plus** DNS propagation until
the record is visible. An `HTTP 200` means "scheduled", not "live".

cert-manager runs its own self-check against the zone's authoritative nameservers and retries
with backoff, so the first attempts are expected to fail. Only if the authoritative nameservers
are not reachable from the cluster (egress restrictions, split-horizon DNS), point the check at
recursive resolvers instead:

```text
--dns01-recursive-nameservers-only
--dns01-recursive-nameservers=1.1.1.1:53,8.8.8.8:53
```

Recursive resolvers cache the negative answer of an early check, which can delay issuance by the
zone's negative TTL; prefer the default where possible.

## Troubleshooting

The webhook passes errors from the DDNS API through, with the token redacted and the response body
truncated to 512 characters; they show up in the status of the `Challenge` resource:

```shell
kubectl describe challenge -A
kubectl logs -n cert-manager -l app.kubernetes.io/name=cert-manager-webhook-ispconfig
```

| Symptom | Cause |
|---------|-------|
| `401 Missing or invalid token.` | Token wrong, inactive, or not lowercase hex. With a correct token, try `tokenAuthMode: query`. |
| `403 Permission denied for record type TXT` | The token does not allow `TXT` |
| `403 Permission denied for record _acme-challenge` | The token's record restriction does not match the zone |
| `403 Permission denied for record _acme-challenge.<sub>` | Certificate for a **subdomain** while the token is limited to `_acme-challenge`, see [Regular certificates and subdomains](#regular-certificates-and-subdomains) |
| `403 Permission denied for zone` (empty) | Overlapping zones in the token |
| `404 Could not find zone` | The zone is not assigned to the token |
| `429` | More than five failed attempts per minute and IP |
| `APIService` not `Available` | Check the webhook's TLS certificate and RBAC |

Verbose logging:

```shell
helm upgrade ... --set webhook.log.level=debug
```

At `debug`, the response body of the DDNS API is logged as well, which is the best source for
diagnosis. The token never appears; it is replaced by `[REDACTED]` on every output path.

## Development

```shell
go build ./...
go test -race -cover ./...
golangci-lint run
```

`-race` needs cgo and therefore a C compiler; without one, run the tests without `-race`. The
end-to-end tests (cert-manager conformance suite) need `etcd` and `kube-apiserver` binaries; see
[e2e/README.md](e2e/README.md).

Architecture, coupled dependency versions and design decisions are described in
[AGENTS.md](AGENTS.md); the specification lives under [openspec/](openspec/). Contributions are
welcome, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Releases

Pushing a tag `vX.Y.Z` publishes:

- the multi-arch image `ghcr.io/ise-cobra/cert-manager-webhook-ispconfig` with the tags `X.Y.Z`
  and `X.Y` (amd64, arm64; no `latest`), with SBOM and build provenance,
- the Helm chart `oci://ghcr.io/ise-cobra/charts/cert-manager-webhook-ispconfig` version `X.Y.Z`,
- a GitHub release with generated notes.

## License

[Apache License 2.0](LICENSE)

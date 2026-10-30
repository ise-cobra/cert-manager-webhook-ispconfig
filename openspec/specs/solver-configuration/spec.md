# solver-configuration Specification

## Purpose
Per-issuer configuration of the solver: DDNS endpoint, token secret reference, token transport mode and timeout.

## Requirements

### Requirement: Configuration per issuer

The solver SHALL read its configuration from the `config` block of the DNS01 webhook
configuration of the respective ACME issuer. Unknown fields MUST be rejected, so that typos do
not silently lead to default values.

#### Scenario: Complete configuration

- **WHEN** the `config` block contains `endpoint`, `tokenSecretRef` and `httpTimeout`
- **THEN** the solver uses all three values for processing this challenge

#### Scenario: Unknown field

- **WHEN** the `config` block contains a field that is not specified
- **THEN** the solver rejects the challenge with a configuration error naming the unknown field

#### Scenario: Missing config block

- **WHEN** the DNS01 webhook configuration contains no `config` block
- **THEN** the solver rejects the challenge with a configuration error, because `tokenSecretRef`
  is mandatory

### Requirement: Endpoint with default

The field `endpoint` SHALL define the base URL of the ISPConfig DDNS API and be optional.

#### Scenario: Default endpoint

- **WHEN** `endpoint` is not set
- **THEN** the solver uses the default endpoint configured at service start

#### Scenario: Endpoint overrides default

- **WHEN** `endpoint` is set to `https://ddns.example.net`
- **THEN** the solver sends its calls to this base URL

#### Scenario: Disallowed scheme

- **WHEN** `endpoint` uses a scheme other than `https` and the service was not started with
  plain-text HTTP explicitly allowed
- **THEN** the solver rejects the challenge with a configuration error

### Requirement: Token from a secret

The DDNS token SHALL be obtained exclusively from a Kubernetes secret via `tokenSecretRef`. The
token MUST NOT be part of the issuer configuration, a flag or an environment variable of the
service.

#### Scenario: Token is resolved

- **WHEN** `tokenSecretRef` refers to secret `ispconfig-ddns-token` with key `token` and that
  secret exists in the challenge's namespace
- **THEN** the solver reads the token value from this secret and uses it for the DDNS call

#### Scenario: Secret lives in the challenge's namespace

- **WHEN** a challenge arrives
- **THEN** the solver looks up the secret exclusively in the namespace the challenge itself
  carries — for an `Issuer` that is its namespace, for a `ClusterIssuer` the cluster resource
  namespace of cert-manager
- **AND** the solver has no namespace configuration of its own for this, because cert-manager
  already supplies the correct namespace in the `ChallengeRequest`

#### Scenario: Secret is missing

- **WHEN** the referenced secret does not exist
- **THEN** the solver rejects the challenge with an error naming the namespace and secret name
- **AND** the error is recognizable as a configuration error — like any other misconfiguration
  when resolving the token

The same applies if access to the secret is not permitted. Neither resolves by itself; a caller
that distinguishes misconfiguration from a temporary outage of the Kubernetes API must be able to
assign these cases to the former.

#### Scenario: Key missing in the secret

- **WHEN** the secret exists but does not contain the specified key
- **THEN** the solver rejects the challenge with an error naming the missing key and the
  existing key names

#### Scenario: Empty token

- **WHEN** the value under the specified key is empty or contains only whitespace
- **THEN** the solver rejects the challenge with a configuration error

#### Scenario: Default key

- **WHEN** `tokenSecretRef` specifies no `key`
- **THEN** the solver uses the key `token`

#### Scenario: Whitespace is trimmed

- **WHEN** the token value in the secret ends with a line break, as produced by
  `kubectl create secret --from-file`
- **THEN** the solver trims surrounding whitespace before using the token

#### Scenario: Token with disallowed characters

- **WHEN** the token value contains characters other than digits and lowercase letters `a`–`f`
- **THEN** the solver rejects the challenge with an error naming the format problem
- **AND** the error message does not contain the token value

### Requirement: Token transport mode

The field `tokenAuthMode` SHALL define how the token is transmitted and be optional.

#### Scenario: Basic auth by default

- **WHEN** `tokenAuthMode` is not set
- **THEN** the solver transmits the token via HTTP basic auth, so that it does not appear in the
  URL

#### Scenario: Query mode chosen explicitly

- **WHEN** `tokenAuthMode` is set to `query`
- **THEN** the solver transmits the token as a query parameter

#### Scenario: Invalid mode

- **WHEN** `tokenAuthMode` has a value other than `basic` or `query`
- **THEN** the solver rejects the challenge with a configuration error naming the allowed values

### Requirement: Timeout per DDNS call

The field `httpTimeout` SHALL define the upper bound for a single DDNS call and be optional.

#### Scenario: Default timeout

- **WHEN** `httpTimeout` is not set
- **THEN** the solver uses the default value configured at service start

#### Scenario: Timeout as duration

- **WHEN** `httpTimeout` is set to `45s`
- **THEN** the solver aborts a DDNS call after 45 seconds with a timeout error

#### Scenario: Invalid duration

- **WHEN** `httpTimeout` is not a valid Go duration or is not positive
- **THEN** the solver rejects the challenge with a configuration error

#### Scenario: Duration above the upper bound

- **WHEN** `httpTimeout` is above the upper bound of 50 seconds
- **THEN** the solver rejects the challenge with a configuration error naming the upper bound

Rationale for the upper bound: the extension API server aborts the request after its
`RequestTimeout` (default 60 s) anyway, but the context of a challenge is not tied to the
request. A value above 50 s can cause cert-manager to treat the aborted request as a timeout and
proceed to `CleanUp` while the old `Present` call to ISPConfig is still running — the late `add`
may then arrive after the `delete` and leave an orphaned TXT record. The bound also makes the
time budget of a challenge (`httpTimeout` plus a reserve for resolving the secret) overflow-safe.

### Requirement: Never disclose the token

Configuration and error messages SHALL NOT contain the token value under any circumstances.

#### Scenario: Token masked in log output

- **WHEN** a structure containing a resolved token ends up in a log line
- **THEN** the placeholder `[REDACTED]` appears instead of the token value

#### Scenario: Token masked in error messages

- **WHEN** an error contains a URL whose query parameters carry the token
- **THEN** the token value in the error message is replaced by `[REDACTED]`

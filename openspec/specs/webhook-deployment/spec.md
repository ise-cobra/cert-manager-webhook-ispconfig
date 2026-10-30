# webhook-deployment Specification

## Purpose
Run the solver as a TLS-secured Kubernetes extension API server and ship it as a Helm chart.

## Requirements

### Requirement: Configuration via flags and environment variables

The service SHALL accept every setting both as a command-line flag and as an environment
variable, so that the same binary can be configured locally and in a container.

#### Scenario: Group name via environment variable

- **WHEN** the service is started with `GROUP_NAME=acme.example.com`
- **THEN** it serves the API group `acme.example.com`

#### Scenario: Flag takes precedence

- **WHEN** the same setting is given as a flag and as an environment variable
- **THEN** the flag value wins

#### Scenario: Group name is missing

- **WHEN** neither flag nor environment variable supplies a group name
- **THEN** the service exits with an error message and a non-zero exit code

#### Scenario: Endpoint is missing

- **WHEN** neither flag nor environment variable supplies a base URL of the DDNS API
- **THEN** the service exits with an error message and a non-zero exit code

#### Scenario: Environment-specific values without built-in default

- **WHEN** the flag definitions of the service are inspected
- **THEN** group name and endpoint carry no default value

Rationale: both values are environment-specific and are set by the chart. A built-in value would
let a deployment that lacks the environment variable start healthy — in the case of the endpoint
with real DDNS calls, including the real token, to an address nobody configured. It would also
make the two scenarios above unreachable.

#### Scenario: TLS material does not match

- **WHEN** certificate and key file do not form a matching pair — for example because the two
  flags are swapped
- **THEN** the service aborts at start with an error message naming the flag and the path

#### Scenario: No secrets as flags

- **WHEN** the flag definitions of the service are inspected
- **THEN** there is no flag and no environment variable that takes a DDNS token

### Requirement: TLS-secured extension API server

The service SHALL be reachable as a Kubernetes extension API server via TLS only and load
certificate and key from configured files.

#### Scenario: Serving certificate from files

- **WHEN** certificate and key files are configured
- **THEN** the service uses exactly this certificate for incoming connections

#### Scenario: Minimum TLS version

- **WHEN** a client offers a TLS version below 1.2
- **THEN** the service rejects the connection

#### Scenario: Missing certificate

- **WHEN** the configured certificate file is not readable
- **THEN** the service aborts at start with an error message instead of starting without TLS

### Requirement: Delegate authentication and authorization

The service SHALL delegate authentication and authorization of incoming requests to the
Kubernetes API server, so that only authorized callers can trigger challenges.

#### Scenario: Request without permission

- **WHEN** an authenticated caller without `create` permission on the solver resource tries to
  trigger a challenge
- **THEN** the service rejects the request without calling the DDNS API

#### Scenario: cert-manager may call

- **WHEN** the service account of cert-manager has `create` on the solver resource of the API
  group
- **THEN** its `Present` and `CleanUp` requests are processed

### Requirement: Health endpoints

The service SHALL provide liveness and readiness endpoints, so that Kubernetes detects a
non-functional pod.

#### Scenario: Ready after start

- **WHEN** the service has started and is initialized
- **THEN** the readiness endpoint answers with a success status

#### Scenario: Probe via TLS

- **WHEN** Kubernetes executes the probes
- **THEN** they run via HTTPS on the secure port of the service

### Requirement: Structured logging in one stream

The service SHALL emit all log output — including that of the embedded Kubernetes libraries —
through `log/slog` in a uniform format.

#### Scenario: JSON by default

- **WHEN** no log format is given or `auto` is chosen
- **THEN** the service writes log lines as JSON — no terminal detection takes place; the chart
  sets the default explicitly to `json`, not to `auto`

#### Scenario: Readable output for local runs

- **WHEN** the log format is explicitly set to `text`
- **THEN** the service writes plain, human-readable log lines without color

#### Scenario: Library logs in the same format

- **WHEN** an embedded Kubernetes library emits a log line
- **THEN** it appears in the same format and stream as the log lines of the service

#### Scenario: Configurable log level

- **WHEN** the service is started with log level `debug`
- **THEN** debug lines appear in the output as well

### Requirement: Optional telemetry

The service SHALL provide traces and metrics via OpenTelemetry. Without a configured exporter it
MUST NOT generate any network traffic.

#### Scenario: Telemetry inactive

- **WHEN** no OTLP endpoint is configured
- **THEN** the service starts normally and sends no telemetry data

#### Scenario: Telemetry active

- **WHEN** an OTLP endpoint is configured
- **THEN** the service exports spans and metrics of the DDNS calls to this endpoint

#### Scenario: No high-cardinality attributes

- **WHEN** a metric for a DDNS call is recorded
- **THEN** its attributes contain neither domain names nor record values nor tokens

### Requirement: Graceful shutdown

On a termination signal the service SHALL complete running requests and then exit.

#### Scenario: SIGTERM during a challenge

- **WHEN** the service receives `SIGTERM` while a challenge is being processed
- **THEN** it completes the running processing, accepts no new requests and terminates with exit
  code 0

### Requirement: Delivery as a Helm chart

The project SHALL ship a Helm chart that installs the webhook ready for operation. The chart
MUST be self-contained and MUST NOT default environment-specific values.

#### Scenario: APIService registration

- **WHEN** the chart is installed
- **THEN** an `APIService` exists for the configured API group in version `v1alpha1` that points
  to the webhook's service

#### Scenario: TLS material via cert-manager

- **WHEN** the chart is installed
- **THEN** cert-manager issues the webhook's serving certificate from a chart-owned CA, which a
  dedicated self-signed issuer issues
- **AND** the CA bundle of the `APIService` is injected automatically

#### Scenario: Minimal permissions

- **WHEN** the RBAC objects created by the chart are inspected
- **THEN** the webhook gets read access to secrets only and only the delegation required for an
  extension API server

#### Scenario: Permissions for the authentication ConfigMap

- **WHEN** the permissions on the ConfigMap `extension-apiserver-authentication` are inspected
- **THEN** they include `get`, `list` and `watch`, because the extension API server reads it via
  an informer and the pod never becomes `Ready` otherwise
- **AND** they are restricted to exactly this ConfigMap name

#### Scenario: Secret read access can be restricted

- **WHEN** the names of the token secrets are configured in the chart
- **THEN** read access is limited to exactly these secrets

#### Scenario: Unrestricted secret access needs an explicit opt-in

- **WHEN** the chart is rendered with an empty list of token secret names and without
  `rbac.acknowledgeUnrestrictedSecretAccess`
- **THEN** rendering fails with a message explaining the risk and both ways out

#### Scenario: Values that can never work fail at render time

- **WHEN** the chart is rendered with values the webhook rejects at startup or that can never
  produce a working installation — an `http://` endpoint without `webhook.allowInsecureEndpoint`,
  an `httpTimeout` outside 1s to 50s, a NetworkPolicy direction without rules, missing TLS
  material or CA trust anchor, a disabled ServiceAccount without a name, or an unknown value key
- **THEN** rendering fails with a message naming the value, instead of a pod that crash-loops or
  an APIService that never becomes `Available`

#### Scenario: Hardened pod

- **WHEN** the webhook's pod is started
- **THEN** it runs as non-root with a read-only root file system, without privileges and without
  additional capabilities

#### Scenario: Self-contained chart

- **WHEN** the chart is installed
- **THEN** it needs no other chart, declares no chart dependencies and renders all objects with its
  own templates

#### Scenario: No default for API group and DDNS endpoint

- **WHEN** the chart is rendered without `groupName` or without `webhook.endpoint`
- **THEN** rendering fails with a message naming the missing value
- **AND** the chart's default values contain neither an API group nor a DDNS endpoint

#### Scenario: Chart can be checked

- **WHEN** `helm lint` and `helm template` are applied to the chart with `groupName`,
  `webhook.endpoint` and the token secret names set
- **THEN** both run without errors and produce valid Kubernetes manifests

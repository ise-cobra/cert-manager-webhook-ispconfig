# ispconfig-ddns-client Specification

## Purpose
HTTP client for the DDNS token API of the ISPConfig module `mhofer117/ispconfig-ddns-module`, the only component with network access to the DNS provider.

## Requirements

### Requirement: Request construction against the DDNS API

The client SHALL send calls to the path `/ddns/update.php` below the configured base URL and pass
the parameters `action`, `type`, `record` and `data`.

#### Scenario: Creating a TXT record

- **WHEN** a TXT record `_acme-challenge.example.com` with the value `abc123` is created
- **THEN** the client sends a request to `<endpoint>/ddns/update.php` with `action=add`,
  `type=TXT`, `record=_acme-challenge.example.com` and `data=abc123`

#### Scenario: Deleting a TXT record

- **WHEN** the same record is deleted
- **THEN** the client sends the same request with `action=delete`

#### Scenario: HTTP method matches the action

- **WHEN** an action is executed
- **THEN** the client uses `POST` for `add` and `DELETE` for `delete`, in addition to the
  explicitly set `action` parameter

#### Scenario: No zone parameter

- **WHEN** a request is built
- **THEN** it contains **no** `zone` parameter, so that the server derives the zone itself and
  the token restriction applies to the relative record name

#### Scenario: No ttl parameter

- **WHEN** a request is built
- **THEN** it contains no `ttl` parameter, because the server does not support one

#### Scenario: Base URL with a path

- **WHEN** the base URL contains a path (`https://host/ispconfig`)
- **THEN** the client appends `/ddns/update.php` to it instead of discarding the path

### Requirement: Authentication with the DDNS token

By default the client SHALL send the token via HTTP basic auth with the user name `anonymous`, so
that it does not appear in the URL. A query mode MUST be available as a fallback.

#### Scenario: Basic auth by default

- **WHEN** the client sends a request without special configuration
- **THEN** it carries an `Authorization` header with user `anonymous` and the token as password
- **AND** the URL contains no `token` parameter

#### Scenario: Query mode as fallback

- **WHEN** query mode is configured
- **THEN** the client passes the token as the `token` query parameter
- **AND** sends no `Authorization` header

### Requirement: Evaluating success and failure

The client SHALL evaluate the result based on the HTTP status and handle the two special cases in
which the desired state has been reached despite an error signal.

#### Scenario: Successful execution

- **WHEN** the server answers with status 200 and a body such as
  `Scheduled update to '...' of record ...`
- **THEN** the client reports success

#### Scenario: Record already exists on create

- **WHEN** an `add` is answered with status 200 and a body starting with `ERROR:`
  (`ERROR: ... is already set in ...`)
- **THEN** the client reports success, because the desired state has been reached
- **AND** marks the result as "unchanged" so that the caller can log it

#### Scenario: Record does not exist on delete

- **WHEN** a `delete` is answered with status 404
- **THEN** the client reports a distinguishable "not found" error that the caller can treat as
  success during `CleanUp`

#### Scenario: `ERROR:` body with 2xx applies to every action

- **WHEN** a call of any action is answered with a 2xx status and a body starting with `ERROR:`
- **THEN** the client reports success with the result "unchanged"

Rationale: for delete this branch is currently unreachable in the module — `loadDnsRecord()`
aborts earlier with `dnsNotFound()`, i.e. with `404`. The evaluation still does not distinguish
the action, so that a patched module version does not lead to permanently stuck challenges. The
case is treated as success, not as an error.

#### Scenario: Invalid token

- **WHEN** the server answers with status 401
- **THEN** the client returns an error recognizable as an authentication error

#### Scenario: Missing permission

- **WHEN** the server answers with status 403 (`Permission denied for ...`)
- **THEN** the client returns an error recognizable as a permission error that contains the
  response text

#### Scenario: Other error statuses

- **WHEN** the server answers with 400, 429 or 500
- **THEN** the client returns an error naming the status and the response text

#### Scenario: Response text aids diagnosis

- **WHEN** an error occurs and the server returned a response text
- **THEN** the error message contains this text in truncated form

#### Scenario: Oversized response text

- **WHEN** the server returns a very long body
- **THEN** the client reads only a limited amount and truncates the text for the error message

### Requirement: Validate the token format

The client SHALL reject a token that does not consist solely of lowercase letters `a`–`f` and
digits, because the server silently strips other characters and then reports an authentication
error.

#### Scenario: Token with uppercase letters

- **WHEN** a token contains uppercase letters
- **THEN** the client refuses to use it with an error naming the problem
- **AND** the error message does not contain the token value

#### Scenario: Empty token

- **WHEN** an empty token is passed
- **THEN** the client refuses to use it with an error

#### Scenario: Valid token

- **WHEN** a token consists only of digits and lowercase letters `a`–`f`
- **THEN** the client accepts it

### Requirement: Payload limits

The client SHALL reject record values exceeding the length of 255 characters allowed by the
server, instead of waiting for an error from the server.

#### Scenario: Record value too long

- **WHEN** a record value is longer than 255 characters
- **THEN** the client rejects the call with an error naming the allowed length

#### Scenario: Value without quotes

- **WHEN** a record value is passed
- **THEN** the client sends it unchanged, without adding surrounding quotes

### Requirement: Transport security and timeout

The client SHALL communicate via TLS with a minimum version of 1.2 and bound every call with a
timeout. Plain `http` endpoints SHALL only be accepted after an explicit opt-in intended for
development.

#### Scenario: Timeout applies

- **WHEN** the server does not answer within the configured timeout
- **THEN** the client aborts the call and returns a timeout error

#### Scenario: Cancellation via the context

- **WHEN** the passed context is cancelled
- **THEN** the client aborts the running call

#### Scenario: Minimum TLS version

- **WHEN** the client establishes a connection
- **THEN** it uses at least TLS 1.2

#### Scenario: http endpoint without opt-in

- **WHEN** the endpoint uses the scheme `http` and the insecure opt-in is not set
- **THEN** the endpoint is rejected with `ErrInsecureEndpoint`, before any request is sent

#### Scenario: http endpoint with opt-in

- **WHEN** the endpoint uses the scheme `http` and the insecure opt-in is set
- **THEN** the client accepts the endpoint and sends its requests without TLS

### Requirement: No retry and no session handling

The client SHALL NOT retry a failed call by itself and SHALL NOT store cookies.

#### Scenario: No retry

- **WHEN** a call ends with an error
- **THEN** the client returns the error without sending the call again

#### Scenario: Cookies are discarded

- **WHEN** the server sets a session cookie
- **THEN** the client does not send it back on subsequent calls

### Requirement: Never disclose the token

The client SHALL NOT disclose the token in any log line, error message or telemetry data.

#### Scenario: Token not in error messages

- **WHEN** a network error occurs whose original message contains the request URL
- **THEN** any token in it is replaced by `[REDACTED]`

#### Scenario: No full URL in log lines

- **WHEN** the client logs a call
- **THEN** the log line contains host, action and record name, but not the full URL

#### Scenario: No full URL in transport errors

- **WHEN** the HTTP call fails before a response is available (timeout, DNS, TLS)
- **THEN** the returned error names the operation, host and cause, but not the full URL
- **AND** `errors.As` does not yield a `*url.Error` whose `URL` field would carry it
- **AND** the cause remains checkable via `errors.Is` (for example `context.DeadlineExceeded`)

Rationale: `net/http` wraps every transport error in a `*url.Error` that carries the full address
in its message **and** in a field. Redacting the text covers only the message; the field would
remain reachable through the error chain.

#### Scenario: Response text at debug level

- **WHEN** a call has completed
- **THEN** the client logs the truncated response text at `debug`

### Requirement: Telemetry of DDNS calls

The client SHALL add a span and metrics to every call without using high-cardinality or
sensitive attributes.

#### Scenario: Span per call

- **WHEN** a call is executed
- **THEN** the client creates a span whose attributes contain the action and the HTTP status,
  but neither record name nor record value nor token

#### Scenario: Error event without response text

- **WHEN** a call fails and the client records the error on the span
- **THEN** the event carries only the error class, not the full message

Rationale: `span.RecordError` puts the error text into the span as `exception.message`. On `403`
the server's response text names the record (`Permission denied for record
_acme-challenge.www.example.com`) — it belongs in the log line, not in the tracing backend. The
full message is kept in the error returned to cert-manager and in the error log line.

#### Scenario: Metrics per call

- **WHEN** a call has completed
- **THEN** the client records count and duration with the attributes action and result

#### Scenario: No automatic HTTP instrumentation

- **WHEN** the client's HTTP transport is built
- **THEN** no instrumentation is used that sets the full URL as an attribute

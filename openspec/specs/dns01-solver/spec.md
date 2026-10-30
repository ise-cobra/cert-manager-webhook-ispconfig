# dns01-solver Specification

## Purpose
Solve ACME DNS01 challenges for cert-manager by creating and removing TXT records through the ISPConfig DDNS API.

## Requirements

### Requirement: Solver name and API group

The webhook SHALL register as an ACME DNS01 solver named `ispconfig` within a configurable API
group. The name MUST match the `solverName` in the DNS01 configuration of the ACME issuer.

#### Scenario: Solver name is reported

- **WHEN** cert-manager asks the solver for its name through the webhook interface
- **THEN** the solver always returns `ispconfig`

#### Scenario: API group from configuration

- **WHEN** the service is started with the API group `acme.example.com`
- **THEN** it serves the resource `v1alpha1.acme.example.com` and accepts `ChallengeRequest`s
  for this group only

### Requirement: Create the TXT record for a challenge

On the `Present` action the solver SHALL create a TXT record with the challenge key as its value
through the ISPConfig DDNS API.

#### Scenario: Record is created

- **WHEN** a `ChallengeRequest` arrives with `ResolvedFQDN` `_acme-challenge.example.com.` and
  `Key` `abc123`
- **THEN** the solver calls the DDNS API with `action=add`, `type=TXT`,
  `record=_acme-challenge.example.com` and `data=abc123`
- **AND** reports success as soon as the API confirms the call

#### Scenario: Trailing dot is removed

- **WHEN** `ResolvedFQDN` ends with a trailing dot (`_acme-challenge.example.com.`)
- **THEN** the solver passes the record name without that dot (`_acme-challenge.example.com`)
- **AND** the same applies to multiple trailing dots

#### Scenario: Empty ResolvedFQDN

- **WHEN** a `ChallengeRequest` arrives without `ResolvedFQDN`
- **THEN** the solver rejects the request with an error
- **AND** no call to the DDNS API is made

#### Scenario: ResolvedFQDN yields no record name

- **WHEN** `ResolvedFQDN` consists of dots only
- **THEN** the solver rejects the request with the same error as for a missing `ResolvedFQDN` —
  not later in a downstream layer with a different error class
- **AND** no call to the DDNS API is made and no secret is read

#### Scenario: DDNS API error is passed through

- **WHEN** the DDNS API answers the call with an error
- **THEN** `Present` returns an error naming the action, the record name and the cause
- **AND** cert-manager retries the challenge according to its own backoff strategy

#### Scenario: Present is idempotent

- **WHEN** `Present` is called for a challenge whose TXT record already exists with an
  identical value
- **THEN** the solver reports success, because the desired state has been reached

### Requirement: Remove the TXT record of a challenge

On the `CleanUp` action the solver SHALL remove exactly the TXT record it created before —
identified by record name **and** value.

#### Scenario: Record is deleted selectively

- **WHEN** a `ChallengeRequest` with `ResolvedFQDN` `_acme-challenge.example.com.` and `Key`
  `abc123` arrives for cleanup
- **THEN** the solver calls the DDNS API with `action=delete`, `type=TXT`,
  `record=_acme-challenge.example.com` and `data=abc123`

#### Scenario: Other records stay untouched

- **WHEN** further TXT values exist under the same record name
- **THEN** the solver removes only the value of its own challenge and never deletes all records
  of that name

#### Scenario: CleanUp is idempotent

- **WHEN** `CleanUp` is called for a challenge whose TXT record no longer exists
- **THEN** the solver reports success, because the desired state has been reached
- **AND** logs this case at `info`

### Requirement: Concurrent challenges on the same record name

The solver SHALL support wildcard and apex challenges of the same domain that share the same
record name but carry different values.

#### Scenario: Wildcard and apex at the same time

- **WHEN** two challenges with different keys but the same `ResolvedFQDN`
  `_acme-challenge.example.com.` are presented for `example.com` and `*.example.com`
- **THEN** the solver creates two TXT records with the same name and different values
- **AND** both values can be queried for ACME validation at the same time

#### Scenario: Cleaning up one challenge keeps the other

- **WHEN** one of the two challenges is cleaned up
- **THEN** the TXT record of the other challenge remains unchanged

### Requirement: Check the challenge type only when set

The solver SHALL reject an explicitly specified challenge type other than `dns-01`. An **empty**
type field MUST be accepted, because the cert-manager conformance suite sets neither `Type` nor
`Action`, and dispatching to `Present`/`CleanUp` is already done by the calling layer.

#### Scenario: Unsupported challenge type

- **WHEN** a `ChallengeRequest` with `Type` `http-01` arrives
- **THEN** the solver rejects the request with an error naming the received type
- **AND** no call to the DDNS API is made

#### Scenario: Empty challenge type

- **WHEN** a `ChallengeRequest` without `Type` arrives
- **THEN** the solver processes the request normally

### Requirement: No ambient credentials

The solver SHALL NOT use credentials from the pod's environment. The DDNS token comes
exclusively from the secret referenced in the issuer.

#### Scenario: AllowAmbientCredentials is ignored

- **WHEN** a `ChallengeRequest` with `AllowAmbientCredentials: true` arrives, but no
  `tokenSecretRef` is configured
- **THEN** the solver rejects the request with a configuration error

### Requirement: Repeatable initialization

Initialization SHALL be callable multiple times without failing — the conformance suite starts
the solver several times within one test run.

#### Scenario: Repeated initialization

- **WHEN** initialization is called twice with a valid client configuration
- **THEN** it returns no error both times and the solver stays functional

#### Scenario: Initialization without client configuration

- **WHEN** initialization is called without a client configuration
- **THEN** it returns an error, because no token can be resolved without Kubernetes access

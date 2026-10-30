# Security policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Report them privately through
[GitHub private vulnerability reporting](https://github.com/ise-cobra/cert-manager-webhook-ispconfig/security/advisories/new).

Include the affected version, a description of the impact and, if possible, steps to reproduce.
We acknowledge reports within five working days and keep you informed about the fix.

## Supported versions

Only the latest release receives security fixes.

## Scope notes

- The DDNS token is sent via HTTP basic auth and is redacted from every error, log line and
  trace. A token appearing in any output is a vulnerability.
- A user who may create an `Issuer` in a namespace can point `config.endpoint` at an arbitrary
  HTTPS host. Restrict egress with `networkPolicy.enabled: true` and limit secret access with
  `rbac.secretResourceNames`; see the chart README.

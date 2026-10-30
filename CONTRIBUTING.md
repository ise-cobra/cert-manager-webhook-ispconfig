# Contributing

Thanks for your interest in improving cert-manager-webhook-ispconfig. Bug reports, questions and
pull requests are welcome.

## Reporting issues

- Search existing issues first.
- Include the webhook and cert-manager versions, the relevant `Challenge` status and webhook
  logs. **Remove tokens, domain names you consider private and any personal data** before
  posting.
- Security problems go through [SECURITY.md](SECURITY.md), not public issues.

## Development setup

Requirements: Go (version from `go.mod`), [golangci-lint](https://golangci-lint.run) v2, Helm 3,
and a C compiler for `go test -race`.

```shell
go build ./...
go test -race -cover ./...
golangci-lint run
helm lint --strict charts/cert-manager-webhook-ispconfig \
  --set groupName=acme.example.com \
  --set webhook.endpoint=https://ispconfig.example.com
```

`helm lint` does not evaluate the chart's `fail`/`required` guards. The `chart` job in
[.github/workflows/ci.yml](.github/workflows/ci.yml) renders every guard with `helm template`
and validates the manifests with kubeconform; run its scripts locally when you change the chart.

The conformance suite is described in [e2e/README.md](e2e/README.md).

Read [AGENTS.md](AGENTS.md) before your first change. It lists the pitfalls that are not obvious
from the code: coupled dependency versions, why the token must never appear in errors, and the
quirks of the DDNS API.

## Pull requests

- **Behaviour changes start with a spec.** The specification lives in [openspec/](openspec/)
  ([OpenSpec](https://github.com/Fission-AI/OpenSpec)). Create a change proposal with
  `openspec new change <name>` (it lands under `openspec/changes/`) containing the delta to the
  affected spec. Pure bug fixes and documentation changes need none, unless they change specified
  behaviour.
- **Tests first.** New behaviour comes with tests; coverage of production code stays above 80 %.
- **Commits** follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
  (`feat:`, `fix:`, `docs:`, `refactor:`, `chore:`, `build:`, `ci:`, `test:`).
- **Dependencies**: prefer the standard library and existing dependencies; discuss a new
  dependency in an issue first. Do not raise
  `github.com/cert-manager/cert-manager` or `k8s.io/*` individually (see AGENTS.md).
- Keep pull requests focused; CI (lint, tests, govulncheck, chart and image build) must pass.

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).

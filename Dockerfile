# syntax=docker/dockerfile:1

# Build stage runs on the build host and cross-compiles for the target platform, so
# multi-arch images need no emulation.
FROM --platform=$BUILDPLATFORM golang:1.26.10@sha256:670bb5aa5349ae03b8516764718486f4f16399134bdc9acd0c46a23f043ab05c AS build

WORKDIR /src
COPY go.mod go.sum ./
# Modules go into the layer, not a cache mount: only layers are exported to an external build
# cache. Declared before the ARGs so that all platforms and versions share this layer.
RUN go mod download

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown

COPY cmd/ cmd/
COPY internal/ internal/
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath \
      -ldflags "-s -w \
        -X github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/common/version.Version=${VERSION} \
        -X github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/common/version.Commit=${COMMIT}" \
      -o /out/webhook ./cmd/webhook

FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329

# https://github.com/opencontainers/image-spec/blob/main/annotations.md
# revision, version and created are set by the release workflow.
LABEL org.opencontainers.image.title="cert-manager-webhook-ispconfig" \
    org.opencontainers.image.description="cert-manager DNS01 solver webhook for the ISPConfig DDNS token API" \
    org.opencontainers.image.source="https://github.com/ise-cobra/cert-manager-webhook-ispconfig" \
    org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app
COPY --from=build /out/webhook /app/webhook
COPY LICENSE /licenses/LICENSE

# Numeric instead of "nonroot:nonroot" (DL3066): distroless has no /etc/passwd to resolve
# a name. Port 8443 needs no capability to bind.
USER 65532:65532
EXPOSE 8443

ENTRYPOINT ["/app/webhook"]

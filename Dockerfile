# syntax=docker/dockerfile:1.7
#
# BuildKit `RUN --mount=type=cache` shares /go/pkg/mod and
# /root/.cache/go-build across builds. Combined with cache-to=registry
# in release.yml, a build that only touches application code skips the
# full module download + most of the per-package compilation cost.

FROM golang:1.25-alpine AS builder

LABEL org.opencontainers.image.source="https://git.nhsoul.fr/nhpro/orion-auth-backend"
LABEL org.opencontainers.image.url="https://git.nhsoul.fr/nhpro/orion-auth-backend"
LABEL org.opencontainers.image.description="OrionAuth Backend"

ARG SWAG_VERSION=v1.16.6

RUN apk add --no-cache git ca-certificates build-base

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

COPY . .

# Generate swagger docs (required by main.go import of orion-auth-backend/docs).
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go install github.com/swaggo/swag/cmd/swag@${SWAG_VERSION} && \
    swag init -g main.go -o docs/

# Build the static binary. Tests run in the CI test workflow on every
# PR + push, so we skip the in-image `go test` (saves ~3 minutes per
# release without weakening the gate — release.yml only fires on a
# published release, which is downstream of a green test workflow).
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /orionauth .

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata
RUN adduser -D -u 1000 orionauth

COPY --from=builder /orionauth /usr/local/bin/orionauth
COPY --from=builder /src/config.yaml /etc/orionauth/config.yaml

USER orionauth
EXPOSE 8080
ENTRYPOINT ["orionauth"]

FROM golang:1.25-alpine AS builder

LABEL org.opencontainers.image.source="https://git.nhsoul.fr/nhpro/orion-auth-backend"
LABEL org.opencontainers.image.url="https://git.nhsoul.fr/nhpro/orion-auth-backend"
LABEL org.opencontainers.image.description="OrionAuth Backend"

RUN apk add --no-cache git ca-certificates build-base

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go test ./... -race -count=1
RUN go install github.com/swaggo/swag/cmd/swag@latest && swag init
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /orionauth .

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

RUN adduser -D -u 1000 orionauth

COPY --from=builder /orionauth /usr/local/bin/orionauth
COPY --from=builder /src/config.yaml /etc/orionauth/config.yaml

USER orionauth

EXPOSE 8080

ENTRYPOINT ["orionauth"]

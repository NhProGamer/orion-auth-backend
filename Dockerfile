FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /orionauth .

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

RUN adduser -D -u 1000 orionauth

COPY --from=builder /orionauth /usr/local/bin/orionauth

USER orionauth

EXPOSE 8080

ENTRYPOINT ["orionauth"]

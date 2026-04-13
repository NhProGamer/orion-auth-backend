# Suggested Commands

## Build & Run
- `go build -o orionauth .` — Build the binary
- `go run .` — Run the server (listens on :8080 by default)
- `./orionauth` — Run compiled binary

## Testing
- `go test ./...` — Run all tests
- `go test ./user/...` — Run tests for specific package
- `go test -v -run TestName ./pkg/...` — Run specific test verbose
- `go test -race ./...` — Run with race detector
- `go test -cover ./...` — Run with coverage

## Formatting & Linting
- `gofmt -w .` — Format all Go files
- `goimports -w .` — Format imports
- `go vet ./...` — Static analysis
- `golangci-lint run` — Linter (if installed)

## Dependencies
- `go mod tidy` — Clean up go.mod/go.sum
- `go mod download` — Download dependencies

## Database
- PostgreSQL required (default: localhost:5432, db: orionauth, user: orionauth, pass: orionauth)
- Migrations run automatically on startup via embedded goose SQL files
- Config file: `config.yaml` or env vars with ORION_ prefix

## Config Override via Environment
- `ORION_SERVER_PORT=9090` overrides server.port
- `ORION_DATABASE_HOST=db.example.com` overrides database.host
- Pattern: ORION_ + UPPER_SNAKE_CASE of yaml path

## System Utils
- `git`, `ls`, `cd`, `grep`, `find` — Standard Linux tools

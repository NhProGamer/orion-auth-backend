# Task Completion Checklist

When a coding task is completed, run in order:

1. `gofmt -w .` — Format code
2. `go vet ./...` — Static analysis
3. `go build ./...` — Verify compilation
4. `go test ./...` — Run all tests (if any exist)
5. `go mod tidy` — If dependencies were added/removed

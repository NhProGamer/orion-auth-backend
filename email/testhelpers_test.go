package email

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func testCtx() context.Context { return context.Background() }

func uuidNew(t *testing.T) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid v7: %v", err)
	}
	return id
}

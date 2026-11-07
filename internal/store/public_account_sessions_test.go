package store

import (
	"bytes"
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
)

func TestPublicAccountSessionValidationBeforeIO(t *testing.T) {
	s := &Store{}
	ctx := context.Background()
	id := "12345678-1234-4234-8234-123456789abc"
	for _, pair := range [][2]string{{"bad", "product"}, {id, ""}, {id, "product with spaces"}} {
		if _, _, err := s.AuthorizedPublicAccountSession(ctx, pair[0], pair[1]); !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("authorization validation: %v", err)
		}
		if err := s.RevokePublicAccountSession(ctx, pair[0], pair[1]); !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("revocation validation: %v", err)
		}
	}
	for _, hashes := range [][2][]byte{{nil, nil}, {make([]byte, 31), make([]byte, 32)}, {make([]byte, 32), make([]byte, 33)}, {bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{1}, 32)}} {
		if _, _, err := s.RotatePublicAccountRefresh(ctx, hashes[0], hashes[1]); !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("refresh validation: %v", err)
		}
	}
	for _, input := range []struct {
		version                 uint64
		holder, country, region string
	}{{math.MaxUint64, "self", "", ""}, {1, "guardian", "", ""}, {1, "self", "street address", ""}, {1, "self", "US", "US-full street address"}, {1, "self", "US", "RU-MOW"}} {
		if _, err := s.UpdatePublicAccountProfile(ctx, id, "product", input.version, input.holder, input.country, input.region); !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("profile validation: %v", err)
		}
	}
}

func TestPublicAccountInsertValidationBeforeIO(t *testing.T) {
	ctx := context.Background()
	if err := insertAccountSession(ctx, nil, AccountSession{}); !errors.Is(err, domain.ErrInvalid) {
		t.Fatal(err)
	}
	if err := insertAccountRefresh(ctx, nil, AccountRefresh{}); !errors.Is(err, domain.ErrInvalid) {
		t.Fatal(err)
	}
	if err := revokeAccountSessionTx(ctx, nil, AccountSession{}, time.Now(), "backend", "user supplied reason"); !errors.Is(err, domain.ErrInvalid) {
		t.Fatal(err)
	}
}

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
)

func TestDirectoryInputGuards(t *testing.T) {
	s := &Store{}
	ctx := context.Background()
	id := "26cdf873-992e-4c15-83cd-19c72729135a"
	for _, input := range []struct {
		product, after string
		limit          uint64
	}{{"", "", 1}, {"bad/product", "", 1}, {"product", "bad", 1}, {"product", "", 0}, {"product", id, 51}} {
		if _, err := s.DirectoryAccounts(ctx, input.product, input.after, input.limit); !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("list guard: %v", err)
		}
	}
	for _, input := range [][2]string{{"", id}, {"bad/product", id}, {"product", ""}, {"product", "bad"}} {
		if _, err := s.DirectoryAccount(ctx, input[0], input[1]); !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("lookup guard: %v", err)
		}
	}
}

func TestDirectoryPermissionFailsClosed(t *testing.T) {
	now := time.Now().UTC()
	good := DirectoryPermission{ID: "26cdf873-992e-4c15-83cd-19c72729135a", Status: "granted", PolicyVersion: "v1", RecordedAt: now}
	for _, status := range []string{"granted", "withdrawn"} {
		p := good
		p.Status = status
		if got := validDirectoryPermission(p, now); got != p {
			t.Fatal("valid permission metadata lost")
		}
	}
	for _, change := range []func(*DirectoryPermission){
		func(p *DirectoryPermission) { p.ID = "" },
		func(p *DirectoryPermission) { p.PolicyVersion = " " },
		func(p *DirectoryPermission) { p.RecordedAt = time.Time{} },
		func(p *DirectoryPermission) { p.RecordedAt = time.Unix(0, 0) },
		func(p *DirectoryPermission) { p.Status = "allowed" },
	} {
		p := good
		change(&p)
		if got := validDirectoryPermission(p, now); got != (DirectoryPermission{Status: "unknown"}) {
			t.Fatal("malformed permission did not fail closed")
		}
	}
	if got := validDirectoryPermission(good, time.Time{}); got.Status != "unknown" {
		t.Fatal("missing creation timestamp accepted")
	}
}

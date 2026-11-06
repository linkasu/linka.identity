//go:build integration

package store_test

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/cryptokit"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/service"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

func TestYDBPublicChallengeCreationIsAtomicBoundAndIdempotent(t *testing.T) {
	endpoint, databasePath := os.Getenv("TEST_YDB_ENDPOINT"), os.Getenv("TEST_YDB_DATABASE")
	if endpoint == "" || databasePath == "" {
		t.Skip("explicit local YDB fixture is not configured")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "grpc" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1") || databasePath != "/local" {
		t.Fatal("public registration tests require a loopback /local emulator")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	database := openIntegrationStore(t, ctx)
	product, installation := "challenge-"+newID(t)[:8], newID(t)
	if _, _, err := database.CreateInstallation(ctx, store.Installation{ID: installation, ProductID: product, Platform: "integration"}); err != nil {
		t.Fatal(err)
	}
	makeInput := func(email string) (store.PublicEmailChallenge, store.EmailVerification) {
		c, v, _ := makePublicChallengeInput(t, ctx, product, installation, email)
		return c, v
	}
	first, verification := makeInput("first-" + product + "@example.test")
	saved, created, err := database.CreatePublicEmailChallenge(ctx, first, verification, 200)
	if err != nil || !created || saved.Version != 1 {
		t.Fatalf("create: created=%v error=%v", created, err)
	}
	replay, created, err := database.CreatePublicEmailChallenge(ctx, first, verification, 200)
	if err != nil || created || replay.Version != 1 || !bytes.Equal(replay.Code.Data, first.Code.Data) {
		t.Fatalf("idempotent replay changed the queued message: created=%v error=%v", created, err)
	}
	conflict := first
	conflict.RequestFingerprint = bytes.Repeat([]byte{6}, 32)
	if _, _, err := database.CreatePublicEmailChallenge(ctx, conflict, verification, 200); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("request ID accepted a different context: %v", err)
	}
	second, secondVerification := makeInput("first-" + product + "@example.test")
	if _, _, err := database.CreatePublicEmailChallenge(ctx, second, secondVerification, 200); err == nil {
		t.Fatal("resend budget was ignored")
	} else {
		var limited *store.PublicRateLimitError
		if !errors.As(err, &limited) {
			t.Fatalf("resend returned an unexpected error: %v", err)
		}
	}
	row, err := database.Client().QueryRow(ctx, `DECLARE $id AS Utf8; SELECT COUNT(*) FROM email_verifications WHERE id=$id;`, query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(second.ID).Build()), query.WithTxControl(query.SnapshotReadOnlyTxControl()))
	if err != nil {
		t.Fatal(err)
	}
	var partial uint64
	if err := row.Scan(&partial); err != nil || partial != 0 {
		t.Fatalf("rate-limited request left a partial verification: count=%d error=%v", partial, err)
	}
	correction, correctionVerification := makeInput("corrected-" + product + "@example.test")
	if _, created, err := database.CreatePublicEmailChallenge(ctx, correction, correctionVerification, 200); err != nil || !created {
		t.Fatalf("corrected address: created=%v error=%v", created, err)
	}
	old, err := database.PublicEmailChallenge(ctx, first.ID)
	if err != nil || old.State != domain.PublicChallengeCancelled || len(old.Code.Data) != 0 || len(old.CodeHash) != 0 {
		t.Fatalf("old flow remained deliverable/verifiable after correction: state=%s error=%v", old.State, err)
	}
}

func makePublicChallengeInput(t *testing.T, ctx context.Context, product, installation, email string) (store.PublicEmailChallenge, store.EmailVerification, *service.IdentityService) {
	t.Helper()
	provider, _ := cryptokit.NewLocalAESKeyProvider("integration-kek", bytes.Repeat([]byte{1}, 32))
	indexer, _ := cryptokit.NewBlindIndexer(1, map[int][]byte{1: bytes.Repeat([]byte{2}, 32)})
	envelope := cryptokit.NewEnvelope(provider)
	preparer := service.NewIdentityService(nil, envelope, indexer, false)
	id, now := newID(t), time.Now().UTC().Truncate(time.Microsecond)
	v, err := preparer.PreparePublicVerification(ctx, service.PublicVerificationInput{ID: id, ProductID: product, InstallationID: installation, Email: email, ExpiresAt: now.Add(10 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	code, err := envelope.Encrypt(ctx, []byte("123456"), []byte(id))
	if err != nil {
		t.Fatal(err)
	}
	c := store.PublicEmailChallenge{ID: id, ProductID: product, InstallationID: installation, Purpose: "product_registration", HolderRole: "self", RequestFingerprint: bytes.Repeat([]byte{3}, 32), NonceHash: bytes.Repeat([]byte{4}, 32), CodeHash: bytes.Repeat([]byte{5}, 32), OTPKeyID: "test", Code: code, EmailBlindIndex: v.BlindIndex, EmailBlindIndexVersion: v.BlindIndexVersion, State: domain.PublicChallengeRequested, MailAvailableAt: now, CreatedAt: now, UpdatedAt: now, ExpiresAt: v.ExpiresAt, Version: 1}
	return c, v, preparer
}

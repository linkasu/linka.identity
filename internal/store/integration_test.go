//go:build integration

package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/cryptokit"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/ids"
	"github.com/linka-cloud/linka.identity/internal/schema"
	"github.com/linka-cloud/linka.identity/internal/service"
	"github.com/linka-cloud/linka.identity/internal/store"
)

func TestYDBIdentityOutboxAndPrivacyFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	database := openIntegrationStore(t, ctx)

	productID := "integration-" + strings.ReplaceAll(newID(t), "-", "")[:12]
	installationID := newID(t)
	installation, created, err := database.CreateInstallation(ctx, store.Installation{
		ID: installationID, ProductID: productID, Platform: "integration",
	})
	if err != nil || !created || installation.ID != installationID {
		t.Fatalf("create installation: created=%v installation=%#v err=%v", created, installation, err)
	}
	if _, created, err := database.CreateInstallation(ctx, store.Installation{
		ID: installationID, ProductID: productID, Platform: "integration",
	}); err != nil || created {
		t.Fatalf("idempotent installation: created=%v err=%v", created, err)
	}

	recordedAt := time.Now().UTC().Truncate(time.Microsecond)
	installationKey := opaqueKey(t)
	if err := database.EnsureSubjectAlias(ctx, installationKey, productID, "metric", "installation", installationID); err != nil {
		t.Fatalf("create installation alias: %v", err)
	}
	if err := database.SetTelemetryPreference(ctx, store.Subject{Kind: "installation", ID: installationID}, installationKey,
		productID, "denied", recordedAt, recordedAt); err != nil {
		t.Fatalf("deny telemetry: %v", err)
	}
	events, err := database.ClaimOutbox(ctx, 20)
	if err != nil || len(events) != 1 || events[0].Topic != "telemetry.suppression.requested" {
		t.Fatalf("claim suppression: events=%#v err=%v", events, err)
	}
	completeOutbox(t, ctx, database, events[0])

	provider, err := cryptokit.NewLocalAESKeyProvider("integration-kek", bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	indexer, err := cryptokit.NewBlindIndexer(1, map[int][]byte{1: bytes.Repeat([]byte{2}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	identities := service.NewIdentityServiceWithVerification(database, cryptokit.NewEnvelope(provider), indexer, false, 15*time.Minute)
	verificationID, _, err := identities.BeginEmailVerification(ctx, service.BeginEmailVerificationInput{
		ProductID: productID, Email: "Owner@Example.test", Namespace: "account", AgeCategory: "adult", InstallationID: &installationID,
	})
	if err != nil {
		t.Fatalf("begin verification: %v", err)
	}
	if err := database.VerifyEmailOwnership(ctx, verificationID, productID, "integration-verifier", "evidence", time.Now().UTC()); err != nil {
		t.Fatalf("verify email: %v", err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	var identity service.RegisterEmailIdentityResult
	var mu sync.Mutex
	for range 2 {
		go func() {
			<-start
			result, completeErr := identities.CompleteEmailVerification(ctx, verificationID, productID, true)
			if completeErr == nil {
				mu.Lock()
				identity = result
				mu.Unlock()
			}
			results <- completeErr
		}()
	}
	close(start)
	var successes int
	for range 2 {
		if err := <-results; err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("verification successes=%d, want 1", successes)
	}
	if err := database.ValidateEnvelopeKeyIDs(ctx, map[string]struct{}{"integration-kek": {}}); err != nil {
		t.Fatalf("envelope key guard: %v", err)
	}
	if err := database.ValidateBlindIndexVersions(ctx, map[int][]byte{1: bytes.Repeat([]byte{2}, 32)}); err != nil {
		t.Fatalf("blind-index guard: %v", err)
	}
	assertConcurrentIdentityDeduplication(t, ctx, identities, productID)
	assertExpiredVerificationCleanup(t, ctx, database, provider, indexer, productID)
	assertOrganizationMembershipAndConsent(t, ctx, database, identity.PersonID, productID)

	accountKey := opaqueKey(t)
	personKey := opaqueKey(t)
	if err := database.EnsureSubjectAlias(ctx, accountKey, productID, "metric", "account", identity.AccountID); err != nil {
		t.Fatal(err)
	}
	if err := database.EnsureSubjectAlias(ctx, personKey, productID, "metric", "person", identity.PersonID); err != nil {
		t.Fatal(err)
	}
	request, created, err := database.CreatePrivacyRequest(ctx, store.PrivacyRequest{
		Subject: store.Subject{Kind: "person", ID: identity.PersonID}, SubjectKey: personKey,
		RequestType: "deletion", Scope: "all", RequestedAt: time.Now().UTC(),
		RequestedByWorkload: "integration", IdempotencyKey: "delete-" + newID(t),
	}, map[string]string{productID: "metric"})
	if err != nil || !created {
		t.Fatalf("create privacy request: created=%v err=%v", created, err)
	}
	if jobs, err := database.ClaimPrivacyErasures(ctx, 10); err != nil || len(jobs) != 0 {
		t.Fatalf("erasure before receipts: jobs=%#v err=%v", jobs, err)
	}
	events, err = database.ClaimOutbox(ctx, 20)
	if err != nil || len(events) != 3 {
		t.Fatalf("claim deletion fanout: events=%#v err=%v", events, err)
	}
	for _, event := range events {
		completeOutbox(t, ctx, database, event)
	}
	jobs, err := database.ClaimPrivacyErasures(ctx, 10)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim YDB erasure: jobs=%#v err=%v", jobs, err)
	}
	if err := database.ErasePrivacyJob(ctx, jobs[0]); err != nil {
		t.Fatalf("erase privacy job: %v", err)
	}
	status, err := database.GetPrivacyRequest(ctx, request.ID)
	if err != nil || status.Status != "completed" || status.CompletedAt == nil {
		t.Fatalf("privacy completion: status=%#v err=%v", status, err)
	}
	if err := database.ResolveTokenSubject(ctx, productID, "account", identity.AccountID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("erased account remained active: %v", err)
	}
	assertPrivacyCancellation(t, ctx, database, productID)
}

func assertExpiredVerificationCleanup(t *testing.T, ctx context.Context, database *store.Store, provider cryptokit.KeyProvider, indexer *cryptokit.BlindIndexer, productID string) {
	t.Helper()
	expiring := service.NewIdentityServiceWithVerification(database, cryptokit.NewEnvelope(provider), indexer, false, time.Nanosecond)
	if _, _, err := expiring.BeginEmailVerification(ctx, service.BeginEmailVerificationInput{
		ProductID: productID, Email: "expired@example.test", Namespace: "account", AgeCategory: "adult",
	}); err != nil {
		t.Fatalf("create expiring verification: %v", err)
	}
	deleted, err := database.DeleteExpiredEmailVerifications(ctx, time.Now().UTC().Add(time.Second), 100)
	if err != nil || deleted < 1 {
		t.Fatalf("expired verification cleanup: deleted=%d err=%v", deleted, err)
	}
}

func assertOrganizationMembershipAndConsent(t *testing.T, ctx context.Context, database *store.Store, personID, productID string) {
	t.Helper()
	sourceID, targetID := newID(t), newID(t)
	if err := database.CreateOrganization(ctx, sourceID, "Source organization"); err != nil {
		t.Fatal(err)
	}
	if err := database.CreateOrganization(ctx, targetID, "Target organization"); err != nil {
		t.Fatal(err)
	}
	submissionID := newID(t)
	if err := database.CreateOrganizationSubmission(ctx, store.OrganizationSubmission{
		ID: submissionID, PersonID: &personID, ProductID: productID, SubmittedName: "Submitted organization",
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.ResolveOrganizationSubmission(ctx, submissionID, "matched", &sourceID, "integration", "matched in integration test"); err != nil {
		t.Fatal(err)
	}
	membership := store.Membership{
		ID: newID(t), PersonID: personID, OrganizationID: sourceID, ProductID: productID, Status: "active",
	}
	if err := database.CreateMembership(ctx, membership); err != nil {
		t.Fatal(err)
	}
	role := "teacher"
	membership.RoleLabel = &role
	if err := database.CreateMembership(ctx, membership); err != nil {
		t.Fatalf("optimistic membership update: %v", err)
	}
	if err := database.MergeOrganization(ctx, sourceID, targetID, "integration", "deduplicate organizations"); err != nil {
		t.Fatalf("serializable organization merge: %v", err)
	}
	if err := database.CreateConsent(ctx, store.Consent{
		ID: newID(t), Subject: store.Subject{Kind: "person", ID: personID}, ProductID: productID,
		ConsentType: "terms", PolicyVersion: "1", Status: "granted", RecordedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create consent: %v", err)
	}
}

func assertConcurrentIdentityDeduplication(t *testing.T, ctx context.Context, identities *service.IdentityService, productID string) {
	t.Helper()
	start := make(chan struct{})
	type registration struct {
		result service.RegisterEmailIdentityResult
		err    error
	}
	results := make(chan registration, 2)
	for range 2 {
		go func() {
			<-start
			result, err := identities.RegisterEmailIdentity(ctx, service.RegisterEmailIdentityInput{
				ProductID: productID, Email: "race@example.test", Namespace: "donation",
				AgeCategory: "adult", VerifiedAt: time.Now().UTC(),
			})
			results <- registration{result: result, err: err}
		}()
	}
	close(start)
	var personID string
	var created int
	for range 2 {
		registration := <-results
		if registration.err != nil {
			t.Fatalf("concurrent identity registration: %v", registration.err)
		}
		if personID == "" {
			personID = registration.result.PersonID
		} else if registration.result.PersonID != personID {
			t.Fatalf("concurrent registration created different persons: %s != %s", registration.result.PersonID, personID)
		}
		if registration.result.Created {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("created identities=%d, want 1", created)
	}
}

func assertPrivacyCancellation(t *testing.T, ctx context.Context, database *store.Store, productID string) {
	t.Helper()
	installationID := newID(t)
	if _, _, err := database.CreateInstallation(ctx, store.Installation{ID: installationID, ProductID: productID, Platform: "cancel-test"}); err != nil {
		t.Fatal(err)
	}
	key := opaqueKey(t)
	if err := database.EnsureSubjectAlias(ctx, key, productID, "metric", "installation", installationID); err != nil {
		t.Fatal(err)
	}
	request, _, err := database.CreatePrivacyRequest(ctx, store.PrivacyRequest{
		Subject: store.Subject{Kind: "installation", ID: installationID}, SubjectKey: key,
		RequestType: "deletion", Scope: "product", ProductID: &productID, RequestedAt: time.Now().UTC(),
		RequestedByWorkload: "integration", IdempotencyKey: "cancel-" + newID(t),
	}, map[string]string{productID: "metric"})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.UpdatePrivacyRequestStatus(ctx, store.PrivacyStatusUpdate{
		ID: request.ID, Status: "processing", Actor: "integration", AuditNote: "reviewed before cancellation",
	}); err != nil {
		t.Fatalf("mark privacy request processing: %v", err)
	}
	if err := database.UpdatePrivacyRequestStatus(ctx, store.PrivacyStatusUpdate{
		ID: request.ID, Status: "completed", Actor: "integration", AuditNote: "must be orchestrator-only",
	}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("manual privacy completion error=%v, want conflict", err)
	}
	if err := database.UpdatePrivacyRequestStatus(ctx, store.PrivacyStatusUpdate{
		ID: request.ID, Status: "cancelled", Actor: "integration", AuditNote: "cancel before delivery",
	}); err != nil {
		t.Fatalf("cancel privacy request: %v", err)
	}
	if events, err := database.ClaimOutbox(ctx, 20); err != nil || len(events) != 0 {
		t.Fatalf("cancelled outbox claimed: events=%#v err=%v", events, err)
	}
	if jobs, err := database.ClaimPrivacyErasures(ctx, 10); err != nil || len(jobs) != 0 {
		t.Fatalf("cancelled erasure claimed: jobs=%#v err=%v", jobs, err)
	}
	if err := database.ResolveTokenSubject(ctx, productID, "installation", installationID); err != nil {
		t.Fatalf("cancelled request erased installation: %v", err)
	}
}

func completeOutbox(t *testing.T, ctx context.Context, database *store.Store, event store.OutboxEvent) {
	t.Helper()
	receipt, err := json.Marshal(map[string]string{"request_id": event.ID, "status": "completed"})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.MarkOutboxDelivered(ctx, event.ID, receipt); err != nil {
		t.Fatalf("complete outbox %s: %v", event.ID, err)
	}
}

func openIntegrationStore(t *testing.T, ctx context.Context) *store.Store {
	t.Helper()
	endpoint := os.Getenv("TEST_YDB_ENDPOINT")
	databasePath := os.Getenv("TEST_YDB_DATABASE")
	if endpoint == "" || databasePath == "" {
		t.Skip("TEST_YDB_ENDPOINT and TEST_YDB_DATABASE are not set")
	}
	database, err := store.Open(ctx, endpoint, databasePath)
	if err != nil {
		t.Fatalf("open YDB: %v", err)
	}
	t.Cleanup(database.Close)
	if err := schema.Apply(ctx, database.Client(), time.Now().UTC()); err != nil {
		t.Fatalf("apply schema: %v", err)
	}
	if err := schema.Apply(ctx, database.Client(), time.Now().UTC()); err != nil {
		t.Fatalf("idempotent schema rerun: %v", err)
	}
	if err := database.Ready(ctx); err != nil {
		t.Fatalf("YDB readiness: %v", err)
	}
	return database
}

func newID(t *testing.T) string {
	t.Helper()
	id, err := ids.NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func opaqueKey(t *testing.T) string {
	t.Helper()
	return strings.ToLower(strings.ReplaceAll(newID(t)+newID(t), "-", ""))[:64]
}

//go:build integration

package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/authz"
	"github.com/linka-cloud/linka.identity/internal/cryptokit"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/httpapi"
	"github.com/linka-cloud/linka.identity/internal/ids"
	"github.com/linka-cloud/linka.identity/internal/migrations"
	"github.com/linka-cloud/linka.identity/internal/pairwise"
	"github.com/linka-cloud/linka.identity/internal/service"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/linka-cloud/linka.identity/internal/token"
)

func TestAnonymousInstallationTelemetrySuppressionOutbox(t *testing.T) {
	ctx := context.Background()
	database := openIntegrationStore(t, ctx)

	installationID, _ := ids.NewUUID()
	_, created, err := database.CreateInstallation(ctx, store.Installation{
		ID: installationID, ProductID: "integration", Platform: "test",
	})
	if err != nil || !created {
		t.Fatalf("create anonymous installation: created=%v err=%v", created, err)
	}
	recordedAt := time.Now().UTC().Truncate(time.Microsecond)
	if err := database.SetTelemetryPreference(ctx, store.Subject{Kind: "installation", ID: installationID}, strings.Repeat("a", 64),
		"integration", "denied", recordedAt, recordedAt.Add(time.Second)); err != nil {
		t.Fatalf("deny telemetry: %v", err)
	}
	events, err := database.ClaimOutbox(ctx, 10)
	if err != nil {
		t.Fatalf("claim outbox: %v", err)
	}
	if len(events) != 1 || events[0].Topic != "telemetry.suppression.requested" {
		t.Fatalf("unexpected outbox events: %#v", events)
	}
	var payload struct {
		RequestedAt time.Time `json:"requested_at"`
	}
	if err := json.Unmarshal(events[0].Payload, &payload); err != nil || !payload.RequestedAt.Equal(recordedAt.Add(time.Second)) {
		t.Fatalf("outbox requested_at = %s, err=%v", payload.RequestedAt, err)
	}
	if err := database.RescheduleOutbox(ctx, events[0].ID, time.Millisecond); err != nil {
		t.Fatalf("reschedule downstream poll: %v", err)
	}
	var attempts, pollCount int
	if err := database.Pool().QueryRow(ctx, `SELECT attempts, poll_count FROM outbox_events WHERE id = $1`, events[0].ID).Scan(&attempts, &pollCount); err != nil || attempts != 0 || pollCount != 1 {
		t.Fatalf("outbox counters after poll: attempts=%d polls=%d err=%v", attempts, pollCount, err)
	}
	if _, err := database.Pool().Exec(ctx, `UPDATE outbox_events SET available_at = now() WHERE id = $1`, events[0].ID); err != nil {
		t.Fatal(err)
	}
	events, err = database.ClaimOutbox(ctx, 10)
	if err != nil || len(events) != 1 || events[0].Attempt != 0 {
		t.Fatalf("claim after poll: events=%#v err=%v", events, err)
	}
	if err := database.RetryOutbox(ctx, events[0].ID, "transport failed", time.Millisecond, 3); err != nil {
		t.Fatalf("retry transport: %v", err)
	}
	if err := database.Pool().QueryRow(ctx, `SELECT attempts, poll_count FROM outbox_events WHERE id = $1`, events[0].ID).Scan(&attempts, &pollCount); err != nil || attempts != 1 || pollCount != 1 {
		t.Fatalf("outbox counters after transport failure: attempts=%d polls=%d err=%v", attempts, pollCount, err)
	}
	if err := database.SetTelemetryPreference(ctx, store.Subject{Kind: "installation", ID: installationID}, strings.Repeat("a", 64),
		"integration", "denied", recordedAt.Add(time.Second), recordedAt.Add(2*time.Second)); err != nil {
		t.Fatalf("repeat telemetry denial: %v", err)
	}
	var count int
	if err := database.Pool().QueryRow(ctx, "SELECT count(*) FROM outbox_events").Scan(&count); err != nil {
		t.Fatalf("count outbox: %v", err)
	}
	if count != 1 {
		t.Fatalf("repeated denial created %d events, want 1", count)
	}
}

func TestEncryptedEmailDonationIsolationAndOptionalAccount(t *testing.T) {
	ctx := context.Background()
	database := openIntegrationStore(t, ctx)
	provider, err := cryptokit.NewLocalAESKeyProvider("integration-kek", bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatalf("create key provider: %v", err)
	}
	indexer, err := cryptokit.NewBlindIndexer(1, map[int][]byte{1: bytes.Repeat([]byte{2}, 32)})
	if err != nil {
		t.Fatalf("create blind indexer: %v", err)
	}
	envelope := cryptokit.NewEnvelope(provider)
	identities := service.NewIdentityService(database, envelope, indexer, false)

	_, err = identities.RegisterEmailIdentity(ctx, service.RegisterEmailIdentityInput{
		ProductID: "plays", Email: "Private@Example.test", Namespace: "account",
		AgeCategory: "minor", LinkAcrossProducts: true, VerifiedAt: time.Now().UTC(),
	})
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("minor global linkage: got %v, want forbidden", err)
	}
	donation, err := identities.RegisterEmailIdentity(ctx, service.RegisterEmailIdentityInput{
		ProductID: "donations", Email: "Private@Example.test", Namespace: "donation",
		AgeCategory: "adult", LinkAcrossProducts: true, VerifiedAt: time.Now().UTC(),
	})
	if err != nil || !donation.Created || donation.AccountID != "" {
		t.Fatalf("create donation identity: %#v err=%v", donation, err)
	}
	account, err := identities.RegisterEmailIdentity(ctx, service.RegisterEmailIdentityInput{
		ProductID: "donations", Email: "Private@Example.test", Namespace: "account",
		AgeCategory: "adult", VerifiedAt: time.Now().UTC(),
	})
	if err != nil || !account.Created || account.PersonID == donation.PersonID || account.AccountID != "" {
		t.Fatalf("create isolated optional account identity: %#v err=%v", account, err)
	}
	repeated, err := identities.RegisterEmailIdentity(ctx, service.RegisterEmailIdentityInput{
		ProductID: "donations", Email: "private@example.test", Namespace: "donation",
		AgeCategory: "adult", VerifiedAt: time.Now().UTC(),
	})
	if err != nil || repeated.Created || repeated.PersonID != donation.PersonID {
		t.Fatalf("resolve repeated donation identity: %#v err=%v", repeated, err)
	}

	var identityID, namespace, linkageScope, scopeKey string
	var encrypted cryptokit.Ciphertext
	if err := database.Pool().QueryRow(ctx, `
		SELECT id::text, identity_namespace, linkage_scope, scope_key,
		       encryption_algorithm, key_id, wrapped_data_key, email_nonce, encrypted_email
		FROM email_identities WHERE person_id = $1`, donation.PersonID).Scan(
		&identityID, &namespace, &linkageScope, &scopeKey, &encrypted.Algorithm,
		&encrypted.KeyID, &encrypted.WrappedDataKey, &encrypted.Nonce, &encrypted.Data); err != nil {
		t.Fatalf("read encrypted identity: %v", err)
	}
	if bytes.Contains(bytes.ToLower(encrypted.Data), []byte("private@example.test")) {
		t.Fatal("ciphertext contains raw email")
	}
	if err := database.ValidateEnvelopeKeyIDs(ctx, map[string]struct{}{}); err == nil {
		t.Fatal("missing persisted envelope key alias was accepted")
	}
	if err := database.ValidateEnvelopeKeyIDs(ctx, map[string]struct{}{"integration-kek": {}}); err != nil {
		t.Fatalf("configured envelope key alias rejected: %v", err)
	}
	aad := []byte(strings.Join([]string{"email-v1", identityID, namespace, linkageScope, scopeKey}, "\x00"))
	plaintext, err := envelope.Decrypt(ctx, encrypted, aad)
	if err != nil || string(plaintext) != "private@example.test" {
		t.Fatalf("decrypt persisted envelope: plaintext=%q err=%v", plaintext, err)
	}
}

func TestPrivacyDeletionWaitsForMetricReceiptBeforePostgresErasure(t *testing.T) {
	ctx := context.Background()
	database := openIntegrationStore(t, ctx)

	installationID, _ := ids.NewUUID()
	if _, _, err := database.CreateInstallation(ctx, store.Installation{
		ID: installationID, ProductID: "plays", Platform: "test",
	}); err != nil {
		t.Fatalf("create installation: %v", err)
	}
	subjectKey := strings.Repeat("b", 64)
	if err := database.EnsureSubjectAlias(ctx, subjectKey, "plays", "metric", "installation", installationID); err != nil {
		t.Fatalf("create subject alias: %v", err)
	}
	productID := "plays"
	request, created, err := database.CreatePrivacyRequest(ctx, store.PrivacyRequest{
		Subject:             store.Subject{Kind: "installation", ID: installationID},
		SubjectKey:          subjectKey,
		RequestType:         "deletion",
		Scope:               "product",
		ProductID:           &productID,
		RequestedAt:         time.Now().UTC(),
		RequestedByWorkload: "privacy-integration",
		IdempotencyKey:      "delete-installation-1",
	}, map[string]string{"plays": "metric"})
	if err != nil || !created {
		t.Fatalf("create privacy request: created=%v err=%v", created, err)
	}

	if _, err := database.Pool().Exec(ctx, `UPDATE privacy_requests SET status = 'completed' WHERE id = $1`, request.ID); err == nil {
		t.Fatal("privacy completion guard accepted incomplete request")
	}
	jobs, err := database.ClaimPrivacyErasures(ctx, 10)
	if err != nil {
		t.Fatalf("claim blocked postgres erasure: %v", err)
	}
	if len(jobs) != 0 {
		t.Fatalf("claimed %d postgres jobs before metric receipt", len(jobs))
	}

	events, err := database.ClaimOutbox(ctx, 10)
	if err != nil || len(events) != 1 || events[0].PrivacyStepID == nil {
		t.Fatalf("claim metric deletion event: events=%#v err=%v", events, err)
	}
	if err := database.MarkOutboxDelivered(ctx, events[0].ID, json.RawMessage(`{"request_id":"`+events[0].ID+`","status":"pending"}`)); err == nil {
		t.Fatal("pending metric receipt completed privacy step")
	}
	if err := database.MarkOutboxDelivered(ctx, events[0].ID, json.RawMessage(`{"request_id":"`+events[0].ID+`","status":"completed"}`)); err != nil {
		t.Fatalf("record metric receipt: %v", err)
	}
	jobs, err = database.ClaimPrivacyErasures(ctx, 10)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim unblocked postgres erasure: jobs=%#v err=%v", jobs, err)
	}
	if err := database.ErasePrivacyJob(ctx, jobs[0]); err != nil {
		t.Fatalf("erase installation: %v", err)
	}

	status, err := database.GetPrivacyRequest(ctx, request.ID)
	if err != nil || status.Status != "completed" || status.CompletedAt == nil {
		t.Fatalf("privacy request not completed: status=%#v err=%v", status, err)
	}
	var disabled bool
	if err := database.Pool().QueryRow(ctx, `
		SELECT disabled_at IS NOT NULL AND person_id IS NULL
		FROM product_installations WHERE id = $1`, installationID).Scan(&disabled); err != nil || !disabled {
		t.Fatalf("installation was not erased: disabled=%v err=%v", disabled, err)
	}
	var aliasCount int
	if err := database.Pool().QueryRow(ctx, `SELECT count(*) FROM subject_aliases WHERE subject_id = $1`, installationID).Scan(&aliasCount); err != nil || aliasCount != 0 {
		t.Fatalf("installation aliases remain: count=%d err=%v", aliasCount, err)
	}
}

func TestEmailVerificationCanBeConsumedOnlyOnce(t *testing.T) {
	ctx := context.Background()
	database := openIntegrationStore(t, ctx)
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
		ProductID: "plays", Email: "owner@example.test", Namespace: "account", AgeCategory: "adult",
	})
	if err != nil {
		t.Fatalf("begin email verification: %v", err)
	}
	if err := database.VerifyEmailOwnership(ctx, verificationID, "plays", "email-verifier", "evidence-1", time.Now().UTC()); err != nil {
		t.Fatalf("verify email ownership: %v", err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, completeErr := identities.CompleteEmailVerification(ctx, verificationID, "plays", true)
			results <- completeErr
		}()
	}
	close(start)
	var successCount int
	for range 2 {
		if err := <-results; err == nil {
			successCount++
		}
	}
	if successCount != 1 {
		t.Fatalf("successful verification consumptions = %d, want 1", successCount)
	}
	var identityCount int
	if err := database.Pool().QueryRow(ctx, `SELECT count(*) FROM email_identities`).Scan(&identityCount); err != nil || identityCount != 1 {
		t.Fatalf("email identities = %d, err=%v", identityCount, err)
	}
	var verificationCount, auditCount int
	if err := database.Pool().QueryRow(ctx, `SELECT count(*) FROM email_verifications`).Scan(&verificationCount); err != nil || verificationCount != 0 {
		t.Fatalf("consumed verification envelopes = %d, err=%v", verificationCount, err)
	}
	if err := database.Pool().QueryRow(ctx, `SELECT count(*) FROM email_verification_audit`).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("verification audit rows = %d, err=%v", auditCount, err)
	}
}

func TestExpiredStandaloneEmailVerificationCleanup(t *testing.T) {
	ctx := context.Background()
	database := openIntegrationStore(t, ctx)
	provider, _ := cryptokit.NewLocalAESKeyProvider("integration-kek", bytes.Repeat([]byte{1}, 32))
	indexer, _ := cryptokit.NewBlindIndexer(1, map[int][]byte{1: bytes.Repeat([]byte{2}, 32)})
	expiring := service.NewIdentityServiceWithVerification(database, cryptokit.NewEnvelope(provider), indexer, false, time.Minute)
	active := service.NewIdentityServiceWithVerification(database, cryptokit.NewEnvelope(provider), indexer, false, time.Hour)
	if _, _, err := expiring.BeginEmailVerification(ctx, service.BeginEmailVerificationInput{
		ProductID: "plays", Email: "expired@example.test", Namespace: "account", AgeCategory: "adult",
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := active.BeginEmailVerification(ctx, service.BeginEmailVerificationInput{
		ProductID: "plays", Email: "active@example.test", Namespace: "account", AgeCategory: "adult",
	}); err != nil {
		t.Fatal(err)
	}
	deleted, err := database.DeleteExpiredEmailVerifications(ctx, time.Now().UTC().Add(2*time.Minute), 100)
	if err != nil || deleted != 1 {
		t.Fatalf("expired cleanup: deleted=%d err=%v", deleted, err)
	}
	var count int
	if err := database.Pool().QueryRow(ctx, `SELECT count(*) FROM email_verifications`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("standalone verification count=%d err=%v", count, err)
	}
}

func TestAccountAndLinkedInstallationDeletionEndToEnd(t *testing.T) {
	ctx := context.Background()
	database := openIntegrationStore(t, ctx)
	provider, _ := cryptokit.NewLocalAESKeyProvider("integration-kek", bytes.Repeat([]byte{1}, 32))
	indexer, _ := cryptokit.NewBlindIndexer(1, map[int][]byte{1: bytes.Repeat([]byte{2}, 32)})
	identities := service.NewIdentityServiceWithVerification(database, cryptokit.NewEnvelope(provider), indexer, false, 15*time.Minute)
	pairwiseIDs, _ := pairwise.New(bytes.Repeat([]byte{3}, 32))
	installationID, _ := ids.NewUUID()
	if _, _, err := database.CreateInstallation(ctx, store.Installation{ID: installationID, ProductID: "plays", Platform: "test"}); err != nil {
		t.Fatal(err)
	}
	verificationID, _, err := identities.BeginEmailVerification(ctx, service.BeginEmailVerificationInput{
		ProductID: "plays", Email: "linked@example.test", Namespace: "account", AgeCategory: "adult", InstallationID: &installationID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.VerifyEmailOwnership(ctx, verificationID, "plays", "email-verifier", "evidence-linked", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	identity, err := identities.CompleteEmailVerification(ctx, verificationID, "plays", true)
	if err != nil {
		t.Fatal(err)
	}
	accountKey := pairwiseIDs.Subject("plays", "metric", "account", identity.AccountID)
	personKey := pairwiseIDs.Subject("plays", "metric", "person", identity.PersonID)
	installationKey := pairwiseIDs.Subject("plays", "metric", "installation", installationID)
	for _, alias := range []struct {
		key, kind, id string
	}{{accountKey, "account", identity.AccountID}, {personKey, "person", identity.PersonID}, {installationKey, "installation", installationID}} {
		if err := database.EnsureSubjectAlias(ctx, alias.key, "plays", "metric", alias.kind, alias.id); err != nil {
			t.Fatal(err)
		}
	}

	signer, _ := token.NewSigner(bytes.Repeat([]byte{4}, 32), "active", "identity.test", time.Minute, 15*time.Minute)
	authenticator, _ := authz.New([]authz.Workload{{
		ID: "plays-workload", Token: strings.Repeat("w", 32), Roles: []authz.Role{authz.RoleProduct}, Products: []string{"plays"},
	}})
	handler := httpapi.New(database, identities, signer, authenticator, pairwiseIDs, map[string]string{"plays": "metric"}, false, time.Minute,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	stalePreferenceRequest := httptest.NewRequest(http.MethodPut, "/v1/telemetry-preferences", strings.NewReader(`{"subject_type":"account","subject_key":"`+accountKey+`","product_id":"plays","preference":"denied","recorded_at":"`+time.Now().UTC().Add(-25*time.Hour).Format(time.RFC3339)+`"}`))
	stalePreferenceRequest.Header.Set("Content-Type", "application/json")
	stalePreferenceRequest.Header.Set("Authorization", "Bearer "+strings.Repeat("w", 32))
	stalePreferenceResponse := httptest.NewRecorder()
	handler.ServeHTTP(stalePreferenceResponse, stalePreferenceRequest)
	if stalePreferenceResponse.Code != http.StatusBadRequest {
		t.Fatalf("stale client recorded_at status=%d", stalePreferenceResponse.Code)
	}
	tokenRequest := httptest.NewRequest(http.MethodPost, "/v1/tokens", strings.NewReader(`{"product_id":"plays","subject_type":"account","subject_key":"`+accountKey+`"}`))
	tokenRequest.Header.Set("Content-Type", "application/json")
	tokenRequest.Header.Set("Authorization", "Bearer "+strings.Repeat("w", 32))
	tokenResponse := httptest.NewRecorder()
	handler.ServeHTTP(tokenResponse, tokenRequest)
	if tokenResponse.Code != http.StatusCreated {
		t.Fatalf("issue account token: status=%d body=%s", tokenResponse.Code, tokenResponse.Body.String())
	}
	var tokenBody struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(tokenResponse.Body.Bytes(), &tokenBody); err != nil {
		t.Fatal(err)
	}
	claims, err := signer.VerifyForTest(tokenBody.AccessToken)
	if err != nil || claims.Subject != accountKey || claims.PersonKey == nil || *claims.PersonKey != personKey {
		t.Fatalf("account token claims=%#v err=%v", claims, err)
	}

	request, created, err := database.CreatePrivacyRequest(ctx, store.PrivacyRequest{
		Subject: store.Subject{Kind: "person", ID: identity.PersonID}, SubjectKey: personKey,
		RequestType: "deletion", Scope: "all", RequestedAt: time.Now().UTC(),
		RequestedByWorkload: "privacy-global", IdempotencyKey: "account-linked-install-delete",
	}, map[string]string{"plays": "metric"})
	if err != nil || !created {
		t.Fatalf("create all-scope deletion: created=%v err=%v", created, err)
	}
	events, err := database.ClaimOutbox(ctx, 10)
	if err != nil || len(events) != 3 {
		t.Fatalf("privacy fanout events=%d err=%v", len(events), err)
	}
	for _, event := range events {
		receipt := json.RawMessage(`{"request_id":"` + event.ID + `","status":"completed"}`)
		if err := database.MarkOutboxDelivered(ctx, event.ID, receipt); err != nil {
			t.Fatal(err)
		}
	}
	jobs, err := database.ClaimPrivacyErasures(ctx, 10)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("postgres erasure jobs=%#v err=%v", jobs, err)
	}
	if err := database.ErasePrivacyJob(ctx, jobs[0]); err != nil {
		t.Fatal(err)
	}
	status, err := database.GetPrivacyRequest(ctx, request.ID)
	if err != nil || status.Status != "completed" {
		t.Fatalf("privacy status=%#v err=%v", status, err)
	}
	var erased bool
	if err := database.Pool().QueryRow(ctx, `
		SELECT person.deleted_at IS NOT NULL
		   AND account.status = 'deleted'
		   AND installation.disabled_at IS NOT NULL
		   AND installation.person_id IS NULL
		FROM persons person
		JOIN accounts account ON account.person_id = person.id
		JOIN product_installations installation ON installation.id = $2
		WHERE person.id = $1`, identity.PersonID, installationID).Scan(&erased); err != nil || !erased {
		t.Fatalf("linked identity not erased: erased=%v err=%v", erased, err)
	}
	var sensitiveCount int
	if err := database.Pool().QueryRow(ctx, `
		SELECT (SELECT count(*) FROM email_identities WHERE person_id = $1)
		     + (SELECT count(*) FROM subject_aliases WHERE subject_id IN ($1::uuid, $2::uuid, $3::uuid))`,
		identity.PersonID, installationID, identity.AccountID).Scan(&sensitiveCount); err != nil || sensitiveCount != 0 {
		t.Fatalf("identity data remains: count=%d err=%v", sensitiveCount, err)
	}
}

func TestCancelledOrRejectedPrivacyRequestCannotErase(t *testing.T) {
	for _, terminal := range []string{"cancelled", "rejected"} {
		t.Run(terminal, func(t *testing.T) {
			ctx := context.Background()
			database := openIntegrationStore(t, ctx)
			installationID, _ := ids.NewUUID()
			_, _, _ = database.CreateInstallation(ctx, store.Installation{ID: installationID, ProductID: "plays", Platform: "test"})
			subjectKey := strings.Repeat("c", 64)
			_ = database.EnsureSubjectAlias(ctx, subjectKey, "plays", "metric", "installation", installationID)
			productID := "plays"
			request, _, err := database.CreatePrivacyRequest(ctx, store.PrivacyRequest{
				Subject: store.Subject{Kind: "installation", ID: installationID}, SubjectKey: subjectKey,
				RequestType: "deletion", Scope: "product", ProductID: &productID, RequestedAt: time.Now().UTC(),
				RequestedByWorkload: "privacy-admin", IdempotencyKey: "terminal-" + terminal,
			}, map[string]string{"plays": "metric"})
			if err != nil {
				t.Fatal(err)
			}
			if err := database.UpdatePrivacyRequestStatus(ctx, store.PrivacyStatusUpdate{
				ID: request.ID, Status: terminal, Actor: "privacy-admin", AuditNote: "integration terminal transition",
			}); err != nil {
				t.Fatal(err)
			}
			if pending, err := database.ClaimOutbox(ctx, 10); err != nil || len(pending) != 0 {
				t.Fatalf("terminal outbox claims=%#v err=%v", pending, err)
			}
			if jobs, err := database.ClaimPrivacyErasures(ctx, 10); err != nil || len(jobs) != 0 {
				t.Fatalf("terminal erasure jobs=%#v err=%v", jobs, err)
			}
			var active bool
			if err := database.Pool().QueryRow(ctx, `SELECT disabled_at IS NULL FROM product_installations WHERE id = $1`, installationID).Scan(&active); err != nil || !active {
				t.Fatalf("terminal request erased installation: active=%v err=%v", active, err)
			}
		})
	}
}

func openIntegrationStore(t *testing.T, ctx context.Context) *store.Store {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	database, err := store.Open(ctx, databaseURL, 5)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(database.Close)
	if err := migrations.Run(ctx, database.Pool()); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	if err := database.Ready(ctx); err != nil {
		t.Fatalf("database should be ready after migrations: %v", err)
	}
	if _, err := database.Pool().Exec(ctx, "TRUNCATE email_verifications, subject_aliases, outbox_events, persons CASCADE"); err != nil {
		t.Fatalf("truncate database: %v", err)
	}
	return database
}

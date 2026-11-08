//go:build integration

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/authz"
	"github.com/linka-cloud/linka.identity/internal/ids"
	"github.com/linka-cloud/linka.identity/internal/installationbroker"
	"github.com/linka-cloud/linka.identity/internal/pairwise"
	"github.com/linka-cloud/linka.identity/internal/schema"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/linka-cloud/linka.identity/internal/token"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

func TestPublicConsentAndPrivateIssuerIntegration(t *testing.T) {
	endpoint, path := os.Getenv("TEST_YDB_ENDPOINT"), os.Getenv("TEST_YDB_DATABASE")
	if endpoint == "" || path == "" {
		t.Skip("isolated TEST_YDB endpoint not configured")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "grpc" || (u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") || path != "/local" {
		t.Fatal("requires loopback /local emulator")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	db, err := store.Open(ctx, endpoint, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if err := schema.Apply(ctx, db.Client(), time.Now()); err != nil {
		t.Fatal(err)
	}
	signer, _ := token.NewSigner(bytes.Repeat([]byte{1}, 32), "test", "issuer", time.Minute, time.Minute)
	generator, _ := pairwise.New(bytes.Repeat([]byte{2}, 32))
	root, err := ids.NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	product := "http-consent-" + root
	workload := strings.Repeat("w", 32)
	authenticator, err := authz.New([]authz.Workload{{ID: "consent-test", Token: workload, Roles: []authz.Role{authz.RoleProduct}, Products: []string{product}}})
	if err != nil {
		t.Fatal(err)
	}
	broker, err := installationbroker.New(db, signer, generator, installationbroker.Config{Products: map[string]installationbroker.Product{product: {Audience: "metric"}},
		RegistrationProducts: map[string]struct{}{product: {}}, PolicyVersion: "base2026-07-19-v3", RefreshTTL: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	handler := New(db, nil, signer, authenticator, generator, map[string]string{product: "metric"}, broker, nil, nil, nil, false, time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil)))
	input := installationbroker.RegisterInput{RequestID: root, ProductID: product, Platform: "android", Preference: "allowed", PolicyVersion: "base2026-07-19-v3", RecordedAt: time.Now().UTC().Truncate(time.Millisecond)}
	registered, err := broker.Register(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	alias, err := db.ResolveSubjectAlias(ctx, registered.InstallationKey, product, "metric")
	if err != nil {
		t.Fatal(err)
	}
	requestID, err := ids.NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	decision := store.InstallationConsentDecision{Subject: store.Subject{Kind: "installation", ID: alias.SubjectID}, SubjectKey: registered.InstallationKey, ProductID: product,
		RequestID: requestID, ExpectedVersion: 1, Preference: "allowed", PolicyVersion: input.PolicyVersion, RecordedAt: input.RecordedAt}
	state, err := db.SetInstallationConsent(ctx, decision)
	if err != nil {
		t.Fatal(err)
	}
	privateBody, _ := json.Marshal(map[string]string{"product_id": product, "subject_type": "installation", "subject_key": registered.InstallationKey})
	issue := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/v1/tokens", bytes.NewReader(privateBody))
		r.Header.Set("Authorization", "Bearer "+workload)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if response := issue(); response.Code != 403 {
		t.Fatalf("private pending issuer status %d", response.Code)
	}
	if replay, err := broker.Register(ctx, input); err != nil || replay.MetricsToken != nil {
		t.Fatal("bootstrap replay bypassed pending managed consent")
	}
	if err := db.Client().Exec(ctx, `DECLARE $id AS Utf8; UPDATE outbox_events SET status="processing" WHERE id=$id;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(state.EventID).Build()), query.WithTxControl(query.SerializableReadWriteTxControl(query.CommitTx()))); err != nil {
		t.Fatal(err)
	}
	receipt, _ := json.Marshal(map[string]string{"request_id": state.EventID, "status": "completed"})
	if err := db.MarkOutboxDelivered(ctx, state.EventID, receipt); err != nil {
		t.Fatal(err)
	}
	response := issue()
	if response.Code != 201 {
		t.Fatalf("private delivered issuer status %d", response.Code)
	}
	var access installationbroker.AccessToken
	if err := json.Unmarshal(response.Body.Bytes(), &access); err != nil {
		t.Fatal(err)
	}
	claims, err := signer.VerifyForTest(access.AccessToken)
	if err != nil || claims.ConsentEpoch != 1 || claims.Subject != registered.InstallationKey {
		t.Fatal("private issuer omitted authoritative epoch")
	}
	if replay, err := broker.Register(ctx, input); err != nil || replay.MetricsToken == nil {
		t.Fatal("delivered bootstrap replay failed")
	} else {
		claims, err := signer.VerifyForTest(replay.MetricsToken.AccessToken)
		if err != nil || claims.ConsentEpoch != 1 {
			t.Fatal("bootstrap replay omitted managed epoch")
		}
	}
}

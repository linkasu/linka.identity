//go:build integration

package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/accountbroker"
	"github.com/linka-cloud/linka.identity/internal/authz"
	"github.com/linka-cloud/linka.identity/internal/cryptokit"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/ids"
	"github.com/linka-cloud/linka.identity/internal/installationbroker"
	"github.com/linka-cloud/linka.identity/internal/pairwise"
	"github.com/linka-cloud/linka.identity/internal/productdirectory"
	"github.com/linka-cloud/linka.identity/internal/schema"
	"github.com/linka-cloud/linka.identity/internal/service"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/linka-cloud/linka.identity/internal/token"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

// Only synthetic mail is captured, never sent or included in test diagnostics.
type publicFlowMail struct {
	to, body string
	calls    int
}

func (m *publicFlowMail) Send(_ context.Context, to, _ string, body string) error {
	m.to, m.body = to, body
	m.calls++
	return nil
}

func TestPublicAccountFlowIntegration(t *testing.T) {
	endpoint, databasePath := os.Getenv("TEST_YDB_ENDPOINT"), os.Getenv("TEST_YDB_DATABASE")
	if endpoint == "" || databasePath == "" {
		t.Skip("TEST_YDB_ENDPOINT and TEST_YDB_DATABASE are required")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal("invalid local YDB endpoint")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "grpc" || (u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback())) || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || databasePath != "/local" {
		t.Fatal("integration fixture must use grpc://loopback:port and /local")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	database, err := store.Open(ctx, endpoint, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	if err := schema.Apply(ctx, database.Client(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := database.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	row, err := database.Client().QueryRow(ctx, `DECLARE $from AS Timestamp;
SELECT COUNT(*) FROM public_auth_events WHERE bucket='otp-request:global' AND created_at >= $from;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$from").Timestamp(time.Now().UTC().Add(-24*time.Hour)).Build()),
		query.WithTxControl(query.SnapshotReadOnlyTxControl()))
	if err != nil {
		t.Fatal(err)
	}
	var used uint64
	if err := row.Scan(&used); err != nil {
		t.Fatal(err)
	}
	if used > 198 {
		t.Fatal("local fixture has insufficient remaining global daily budget for two synthetic challenges; do not reset shared limiter state")
	}

	for _, mode := range []string{"refresh_replay", "explicit_revoke"} {
		t.Run(mode, func(t *testing.T) {
			publicFlowScenario(t, ctx, database, mode)
		})
	}
}

func publicFlowScenario(t *testing.T, ctx context.Context, database *store.Store, mode string) {
	t.Helper()
	newID := func() string {
		id, err := ids.NewUUID()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	product := "http-flow-" + strings.ReplaceAll(newID(), "-", "")[:12]
	email := "flow-" + newID() + "@example.test"
	const origin = "https://public-flow.example.test"
	const policy = "integration-registration-v1"
	const workloadToken = "synthetic-directory-workload-token-123456789"
	products := map[string]installationbroker.Product{product: {Audience: product + "-metrics"}}
	allowed := map[string]struct{}{product: {}}
	provider, err := cryptokit.NewLocalAESKeyProvider("integration-kek", bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	envelope := cryptokit.NewEnvelope(provider)
	indexer, err := cryptokit.NewBlindIndexer(1, map[int][]byte{1: bytes.Repeat([]byte{2}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := token.NewSigner(bytes.Repeat([]byte{3}, 32), "integration", "https://identity.example.test", 5*time.Minute, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	aliases, err := pairwise.New(bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	identities := service.NewIdentityService(database, envelope, indexer, false)
	installations, err := installationbroker.New(database, signer, aliases, installationbroker.Config{Products: products, RegistrationProducts: allowed, PolicyVersion: policy, RefreshTTL: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	accounts, err := accountbroker.New(accountbroker.Dependencies{Repository: database, Installations: installations, Identity: identities, Envelope: envelope, Signer: signer, Pairwise: aliases}, accountbroker.Config{Products: products, RegistrationProducts: allowed, RegistrationPolicyVersion: policy, OTPKeyID: "integration-otp", OTPKey: bytes.Repeat([]byte{5}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	directory, err := productdirectory.New(database, envelope, aliases, map[string]string{product: products[product].Audience})
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := authz.New([]authz.Workload{{ID: "integration-directory", Token: workloadToken, Roles: []authz.Role{authz.RoleProductDirectoryRead}, Products: []string{product}}})
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	handler := New(database, identities, signer, authenticator, aliases, map[string]string{product: products[product].Audience}, installations, accounts, directory, map[string]struct{}{origin: {}}, false, time.Minute, slog.New(slog.NewJSONHandler(&logs, nil)))
	request := func(method, path, credential, requestOrigin string, input any, want int, output any) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(body)).WithContext(ctx)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", requestOrigin)
		if credential != "" {
			r.Header.Set("Authorization", "Bearer "+credential)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s: status %d, want %d", method, path, w.Code, want)
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Type") != "application/json" || w.Header().Get("X-Request-ID") == "" {
			t.Fatalf("%s: missing response security headers", path)
		}
		if strings.HasPrefix(path, "/v1/public/") && requestOrigin == origin && w.Header().Get("Access-Control-Allow-Origin") != origin {
			t.Fatal("allowed origin was not echoed")
		}
		if strings.HasPrefix(path, "/v1/internal/") && w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("private directory enabled browser CORS")
		}
		if w.Header().Get("Access-Control-Allow-Credentials") != "" {
			t.Fatal("public flow enabled cookie credentials")
		}
		if output != nil {
			if err := json.Unmarshal(w.Body.Bytes(), output); err != nil {
				t.Fatalf("%s: invalid response JSON", path)
			}
		}
		return w
	}
	public := func(method, path, credential string, input any, want int, output any) *httptest.ResponseRecorder {
		t.Helper()
		return request(method, path, credential, origin, input, want, output)
	}
	assertNullMetrics := func(w *httptest.ResponseRecorder) {
		t.Helper()
		if !bytes.Contains(w.Body.Bytes(), []byte(`"metrics_token":null`)) {
			t.Fatal("unknown telemetry preference produced a metrics token")
		}
	}
	var installation installationbroker.Registration
	bootstrap := installationbroker.RegisterInput{RequestID: newID(), ProductID: product, Platform: "web", Preference: "unknown", PolicyVersion: policy, RecordedAt: time.Now().UTC().Truncate(time.Microsecond)}
	assertNullMetrics(public("POST", "/v1/public/installations", "", bootstrap, 201, &installation))
	if installation.Preference != "unknown" || installation.Product != product || !pairwise.Valid(installation.InstallationKey) || installation.RefreshToken == "" {
		t.Fatal("invalid unknown bootstrap contract")
	}
	public("POST", "/v1/public/installations/token", installation.RefreshToken, struct{}{}, 403, nil)
	installationContext, err := installations.AuthenticateInstallation(ctx, installation.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	preference, err := database.GetTelemetryPreference(ctx, store.Subject{Kind: "installation", ID: installationContext.InstallationID}, product)
	if err != nil || preference.Preference != "unknown" {
		t.Fatal("bootstrap did not persist unknown telemetry preference")
	}

	nonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32))
	begin := accountbroker.ChallengeInput{RequestID: newID(), ProductID: product, Email: email, Purpose: accountbroker.RegistrationPurpose, ClientNonce: nonce, HolderRole: "self"}
	request("POST", "/v1/public/email/challenges", installation.RefreshToken, "https://attacker.example.test", begin, 403, nil)
	var challenge accountbroker.ChallengeResponse
	public("POST", "/v1/public/email/challenges", installation.RefreshToken, begin, 202, &challenge)
	if challenge.ChallengeID != begin.RequestID || challenge.Status != "pending" || challenge.ContractVersion != 1 || !challenge.ExpiresAt.After(time.Now()) {
		t.Fatal("invalid generic challenge contract")
	}
	mail := &publicFlowMail{}
	owner := newID()
	for {
		worked, err := accounts.ProcessEmail(ctx, mail, owner)
		if err == nil {
			if !worked || mail.calls != 1 || mail.to != email {
				t.Fatal("owned challenge did not deliver exactly one synthetic message")
			}
			break
		}
		var limited *store.PublicRateLimitError
		if !errors.As(err, &limited) {
			t.Fatalf("process synthetic email: %v", err)
		}
		// Wait only for the authoritative limiter deadline, bounded by the test context.
		wait := time.Until(limited.RetryAt)
		if wait <= 0 {
			t.Fatal("sender limiter returned a non-future retry criterion")
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			t.Fatal("sender rate-limit deadline exceeded test context")
		case <-timer.C:
		}
	}
	code := regexp.MustCompile(`\b[0-9]{6}\b`).FindString(mail.body)
	if code == "" {
		t.Fatal("synthetic SMTP body contained no OTP")
	}
	verifyPath := "/v1/public/email/challenges/" + challenge.ChallengeID + "/verify"
	proof := accountbroker.VerifyInput{ProductID: product, Code: code, ClientNonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))}
	w := public("POST", verifyPath, installation.RefreshToken, proof, 400, nil)
	if w.Body.String() != "{\"error\":\"challenge_rejected\"}\n" {
		t.Fatal("wrong nonce did not use generic challenge rejection")
	}
	proof.ClientNonce = nonce
	var registered accountbroker.Registration
	registrationResponse := public("POST", verifyPath, installation.RefreshToken, proof, 200, &registered)
	assertNullMetrics(registrationResponse)
	public("POST", verifyPath, installation.RefreshToken, proof, 400, nil)
	claims, err := signer.VerifyAccountAccess(registered.AccountToken.AccessToken)
	if err != nil || claims.Product != product || claims.Subject != registered.AccountKey || claims.Audience != token.AccountAudience || len(claims.Scopes) != 1 || claims.Scopes[0] != token.AccountScope || registered.InstallationKey != installation.InstallationKey {
		t.Fatal("account credential escaped its product/account/install context")
	}
	session, profile, err := database.AuthorizedPublicAccountSession(ctx, claims.SessionID, product)
	if err != nil || session.InstallationID != installationContext.InstallationID || profile.Version != registered.AccountProfile.Version {
		t.Fatal("account token does not select its committed session/profile")
	}
	receipt, err := signer.VerifyRegistrationReceipt(registered.RegistrationReceipt)
	if err != nil || receipt.Product != product || receipt.Subject != registered.AccountKey || receipt.InstallationKey != installation.InstallationKey || receipt.PolicyVersion != policy || receipt.HolderRole != "self" {
		t.Fatal("offline receipt is not bound to registration")
	}
	for _, jwt := range []string{installation.RefreshToken, registered.AccountToken.AccessToken, registered.RegistrationReceipt} {
		parts := strings.Split(jwt, ".")
		if len(parts) != 3 {
			t.Fatal("credential is not a JWT")
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal("invalid JWT payload")
		}
		for _, secret := range []string{email, session.AccountID, session.InstallationID, `"email"`, `"root_id"`, `"account_id"`, `"installation_id"`, `"person_id"`, `"subject_id"`} {
			if bytes.Contains(payload, []byte(secret)) || bytes.Contains(registrationResponse.Body.Bytes(), []byte(secret)) {
				t.Fatal("public contract exposed contact or root identity")
			}
		}
	}
	update := accountbroker.ProfileInput{Version: registered.AccountProfile.Version, HolderRole: "representative", Country: "RU", Region: "RU-MOW"}
	for _, credential := range []string{registered.RegistrationReceipt, installation.RefreshToken} {
		public("PUT", "/v1/public/account-profile", credential, update, 401, nil)
		public("POST", "/v1/public/account-sessions/refresh", credential, struct{}{}, 401, nil)
	}
	public("POST", "/v1/public/installations/token", registered.AccountToken.AccessToken, struct{}{}, 401, nil)
	invalidCountry := update
	invalidCountry.Country = "RUS"
	public("PUT", "/v1/public/account-profile", registered.AccountToken.AccessToken, invalidCountry, 400, nil)
	var updated accountbroker.Profile
	public("PUT", "/v1/public/account-profile", registered.AccountToken.AccessToken, update, 200, &updated)
	if updated.Version != update.Version+1 || updated.Country != "RU" || updated.Region != "RU-MOW" || updated.HolderRole != "representative" || updated.Product != product {
		t.Fatal("profile update lost declared values or CAS version")
	}
	public("PUT", "/v1/public/account-profile", registered.AccountToken.AccessToken, update, 409, nil)
	update.Version = updated.Version

	query := productdirectory.QueryInput{ProductID: product, Limit: 10}
	var page productdirectory.Page
	request("POST", "/v1/internal/product-directory/query", workloadToken, origin, query, 200, &page)
	if page.Product != product || len(page.Entries) != 1 {
		t.Fatal("scoped directory did not return exactly the owned registration")
	}
	entry := page.Entries[0]
	if entry.Email != email || entry.AccountKey != aliases.Subject(product, products[product].Audience, "account", session.AccountID) || entry.ContactReference == "" || entry.Version != updated.Version || entry.TelemetryPreference != "unknown" {
		t.Fatal("directory registration/profile/telemetry mismatch")
	}
	assertUnknownPermissions := func(permissions map[string]productdirectory.Permission) {
		t.Helper()
		if len(permissions) != 3 {
			t.Fatal("directory permission categories missing")
		}
		for _, category := range []string{"news", "research", "service"} {
			p := permissions[category]
			if p.Status != "unknown" || p.EvidenceID != "" || p.PolicyVersion != "" || !p.RecordedAt.IsZero() {
				t.Fatal("registration invented communication permission")
			}
		}
	}
	assertUnknownPermissions(entry.Permissions)
	check := productdirectory.CheckInput{ProductID: product, References: []string{entry.ContactReference}}
	var checks productdirectory.Checks
	request("POST", "/v1/internal/product-directory/check", workloadToken, origin, check, 200, &checks)
	if len(checks.Results) != 1 || checks.Results[0].State != "active" || checks.Results[0].AccountKey != entry.AccountKey || checks.Results[0].Version != updated.Version {
		t.Fatal("directory check did not re-read current profile")
	}
	assertUnknownPermissions(checks.Results[0].Permissions)
	for _, path := range []string{"query", "check"} {
		input := any(query)
		if path == "check" {
			input = check
		}
		for _, credential := range []string{registered.AccountToken.AccessToken, registered.RegistrationReceipt, installation.RefreshToken} {
			request("POST", "/v1/internal/product-directory/"+path, credential, origin, input, 401, nil)
		}
	}
	request("POST", "/v1/internal/product-directory/query", workloadToken, "", productdirectory.QueryInput{ProductID: "other-product"}, 403, nil)

	var rotated accountbroker.Registration
	assertNullMetrics(public("POST", "/v1/public/account-sessions/refresh", registered.RefreshToken, struct{}{}, 200, &rotated))
	if rotated.RefreshToken == registered.RefreshToken || rotated.AccountKey != registered.AccountKey || rotated.AccountProfile.Version != updated.Version {
		t.Fatal("refresh did not rotate its capability and retain profile")
	}
	if mode == "refresh_replay" {
		public("POST", "/v1/public/account-sessions/refresh", registered.RefreshToken, struct{}{}, 401, nil)
	} else {
		public("POST", "/v1/public/account-sessions/revoke", rotated.AccountToken.AccessToken, struct{}{}, 200, nil)
	}
	for _, access := range []string{registered.AccountToken.AccessToken, rotated.AccountToken.AccessToken} {
		public("PUT", "/v1/public/account-profile", access, update, 401, nil)
	}
	public("POST", "/v1/public/account-sessions/refresh", rotated.RefreshToken, struct{}{}, 401, nil)
	if _, _, err := database.AuthorizedPublicAccountSession(ctx, claims.SessionID, product); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("revoked family still authorized in persistent state")
	}
	if _, err := signer.VerifyRegistrationReceipt(registered.RegistrationReceipt); err != nil {
		t.Fatal("online revocation invalidated offline receipt evidence")
	}
	for _, secret := range []string{email, code, nonce, workloadToken, installation.RefreshToken, registered.RefreshToken, registered.AccountToken.AccessToken, registered.RegistrationReceipt, entry.ContactReference} {
		if strings.Contains(logs.String(), secret) {
			t.Fatal("HTTP logs exposed synthetic confidential data")
		}
	}
}

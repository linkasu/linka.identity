package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/installationbroker"
	"github.com/linka-cloud/linka.identity/internal/pairwise"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/linka-cloud/linka.identity/internal/token"
)

func TestRefreshPublicInstallationToken(t *testing.T) {
	for _, test := range []struct {
		name          string
		product       string
		invalid       bool
		preference    string
		aliasErr      error
		subjectErr    error
		preferenceErr error
		status        int
		errorCode     string
	}{
		{name: "looks compatibility", product: "linka-looks", preference: "allowed", status: http.StatusOK},
		{name: "plays unchanged", product: "linka-plays", preference: "allowed", status: http.StatusOK},
		{name: "invalid credential", product: "linka-looks", invalid: true, preference: "allowed", status: http.StatusUnauthorized, errorCode: "invalid_refresh_credential"},
		{name: "denied", product: "linka-looks", preference: "denied", status: http.StatusForbidden, errorCode: "telemetry_denied"},
		{name: "alias repository error", product: "linka-looks", aliasErr: errors.New("alias unavailable"), status: http.StatusInternalServerError, errorCode: "internal_error"},
		{name: "subject repository error", product: "linka-looks", subjectErr: errors.New("subject unavailable"), status: http.StatusInternalServerError, errorCode: "internal_error"},
		{name: "preference repository error", product: "linka-looks", preferenceErr: errors.New("preference unavailable"), status: http.StatusInternalServerError, errorCode: "internal_error"},
	} {
		t.Run(test.name, func(t *testing.T) {
			signer, err := token.NewSigner(bytes.Repeat([]byte{1}, 32), "test-key", "test-issuer", time.Minute, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			pairwiseIDs, err := pairwise.New(bytes.Repeat([]byte{2}, 32))
			if err != nil {
				t.Fatal(err)
			}
			const subjectID = "11111111-1111-4111-8111-111111111111"
			audience := test.product + "-metric"
			key := pairwiseIDs.Subject(test.product, audience, "installation", subjectID)
			repository := &refreshTestRepository{
				alias:      store.ResolvedAlias{OpaqueKey: key, ProductID: test.product, Audience: audience, SubjectType: "installation", SubjectID: subjectID},
				preference: test.preference, aliasErr: test.aliasErr, subjectErr: test.subjectErr, preferenceErr: test.preferenceErr,
			}
			broker, err := installationbroker.New(repository, signer, pairwiseIDs, installationbroker.Config{
				Products: map[string]installationbroker.Product{
					"linka-looks": {Audience: "linka-looks-metric"},
					"linka-plays": {Audience: "linka-plays-metric"},
				},
				RegistrationProducts: map[string]struct{}{"linka-plays": {}},
				PolicyVersion:        "v1", RefreshTTL: 24 * time.Hour,
			})
			if err != nil {
				t.Fatal(err)
			}
			credential, _, err := signer.SignRefresh(test.product, key, "v1", 24*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if test.invalid {
				credential = "invalid"
			}
			handler := New(nil, nil, signer, nil, pairwiseIDs, nil, broker, nil, nil, nil, false, time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil)))
			request := httptest.NewRequest(http.MethodPost, "/v1/public/installations/token", strings.NewReader("{}"))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer "+credential)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.status, response.Body.String())
			}
			var body map[string]json.RawMessage
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if test.status != http.StatusOK {
				if string(body["error"]) != `"`+test.errorCode+`"` || len(body) != 1 {
					t.Fatalf("error response = %s", response.Body.String())
				}
				return
			}
			if string(body["product"]) != `"`+test.product+`"` || string(body["installation_key"]) != `"`+key+`"` {
				t.Fatalf("installation identity = %s", response.Body.String())
			}
			var nested installationbroker.AccessToken
			if err := json.Unmarshal(body["metrics_token"], &nested); err != nil {
				t.Fatal(err)
			}
			claims, err := signer.VerifyForTest(nested.AccessToken)
			if err != nil || claims.Product != test.product || claims.Subject != key || claims.Audience != audience || nested.TokenType != "Bearer" || !nested.ExpiresAt.After(time.Now()) {
				t.Fatalf("invalid metrics token: claims=%+v err=%v", claims, err)
			}
			var nestedJSON map[string]json.RawMessage
			if err := json.Unmarshal(body["metrics_token"], &nestedJSON); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"access_token", "token_type", "expires_at"} {
				flat, exists := body[field]
				if test.product == "linka-looks" {
					if !exists || !bytes.Equal(flat, nestedJSON[field]) {
						t.Errorf("Looks %s must equal metrics_token.%s", field, field)
					}
				} else if exists {
					t.Errorf("unexpected %s for %s", field, test.product)
				}
			}
			wantFields := 3
			if test.product == "linka-looks" {
				wantFields = 6
			}
			if len(body) != wantFields {
				t.Errorf("response fields = %d, want %d", len(body), wantFields)
			}
		})
	}
}

type refreshTestRepository struct {
	alias         store.ResolvedAlias
	preference    string
	aliasErr      error
	subjectErr    error
	preferenceErr error
}

func (*refreshTestRepository) RegisterPublicInstallation(context.Context, store.PublicInstallationRegistration) (store.Installation, error) {
	panic("registration must not be called during refresh")
}

func (*refreshTestRepository) DenyPublicInstallation(context.Context, store.PublicTelemetryDenial) (time.Time, error) {
	panic("denial must not be called during refresh")
}

func (f *refreshTestRepository) ResolveSubjectAlias(_ context.Context, key, product, audience string) (store.ResolvedAlias, error) {
	if f.aliasErr != nil {
		return store.ResolvedAlias{}, f.aliasErr
	}
	if key != f.alias.OpaqueKey || product != f.alias.ProductID || audience != f.alias.Audience {
		return store.ResolvedAlias{}, domain.ErrNotFound
	}
	return f.alias, nil
}

func (f *refreshTestRepository) ResolveTokenSubject(_ context.Context, product, kind, id string) error {
	if product != f.alias.ProductID || kind != f.alias.SubjectType || id != f.alias.SubjectID {
		return domain.ErrNotFound
	}
	return f.subjectErr
}

func (f *refreshTestRepository) GetTelemetryPreference(_ context.Context, subject store.Subject, product string) (store.TelemetryPreference, error) {
	if product != f.alias.ProductID || subject.Kind != f.alias.SubjectType || subject.ID != f.alias.SubjectID {
		return store.TelemetryPreference{}, domain.ErrNotFound
	}
	return store.TelemetryPreference{Preference: f.preference}, f.preferenceErr
}

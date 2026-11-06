package productdirectory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/authz"
	"github.com/linka-cloud/linka.identity/internal/cryptokit"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/pairwise"
	"github.com/linka-cloud/linka.identity/internal/store"
)

type directoryRepository struct {
	record store.DirectoryAccount
	err    error
	audits int
}

func (r *directoryRepository) DirectoryAccounts(context.Context, string, string, uint64) ([]store.DirectoryAccount, error) {
	return []store.DirectoryAccount{r.record}, nil
}

func (r *directoryRepository) DirectoryAccount(context.Context, string, string) (store.DirectoryAccount, error) {
	return r.record, r.err
}

func (r *directoryRepository) AuditProductDirectory(context.Context, string, string, string, time.Time) error {
	r.audits++
	return nil
}

func directoryPrincipal(t *testing.T, role authz.Role, product string) authz.Principal {
	t.Helper()
	a, err := authz.New([]authz.Workload{{ID: "crm-directory", Token: strings.Repeat("k", 32), Roles: []authz.Role{role}, Products: []string{product}}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("k", 32))
	p, ok := a.Authenticate(r)
	if !ok {
		t.Fatal("fixture principal unavailable")
	}
	return p
}

func TestDirectoryRequiresScopedWorkloadAndKeepsReferencesOpaque(t *testing.T) {
	ctx := context.Background()
	provider, _ := cryptokit.NewLocalAESKeyProvider("test", bytes.Repeat([]byte{1}, 32))
	envelope := cryptokit.NewEnvelope(provider)
	aliases, _ := pairwise.New(bytes.Repeat([]byte{2}, 32))
	account, identity := "29ec7dcf-553f-4e55-8a3a-715529874cc6", "77541b01-028b-4072-a21b-547ad3070d7e"
	email, err := envelope.Encrypt(ctx, []byte("owner@example.test"), cryptokit.EmailIdentityAAD(identity, "account", "product", "linka-type"))
	if err != nil {
		t.Fatal(err)
	}
	rows := &directoryRepository{record: store.DirectoryAccount{Profile: store.ProductAccount{ProductID: "linka-type", AccountID: account, EmailIdentityID: identity, HolderRole: "representative", Status: "active", VerifiedAt: time.Now().UTC(), Version: 1}, PersonID: "internal-person-not-for-export", Namespace: "account", LinkageScope: "product", ScopeKey: "linka-type", Email: email, TelemetryPreference: "unknown"}}
	directory, err := New(rows, envelope, aliases, map[string]string{"linka-type": "linka-type-metric", "linka-looks": "linka-looks-metric"})
	if err != nil {
		t.Fatal(err)
	}
	reader := directoryPrincipal(t, authz.RoleProductDirectoryRead, "linka-type")
	if _, err := directory.Query(ctx, directoryPrincipal(t, authz.RoleProduct, "linka-type"), QueryInput{ProductID: "linka-type"}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatal("a product workload gained contact-directory privileges")
	}
	if _, err := directory.Query(ctx, reader, QueryInput{ProductID: "linka-looks"}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatal("directory reader crossed its product grant")
	}
	page, err := directory.Query(ctx, reader, QueryInput{ProductID: "linka-type"})
	if err != nil || len(page.Entries) != 1 || page.Entries[0].Email != "owner@example.test" || page.Entries[0].Permissions["news"].Status != "unknown" {
		t.Fatalf("verified address became permission or disappeared: %v", err)
	}
	encoded, _ := json.Marshal(page)
	if bytes.Contains(encoded, []byte(account)) || bytes.Contains(encoded, []byte(identity)) || bytes.Contains(encoded, []byte("internal-person")) {
		t.Fatal("directory exported an internal identity ID")
	}
	ref := page.Entries[0].ContactReference
	if ref == "" || strings.Contains(ref, "owner") {
		t.Fatal("contact reference is not opaque")
	}
	checked, err := directory.Check(ctx, reader, CheckInput{ProductID: "linka-type", References: []string{ref}})
	if err != nil || checked.Results[0].State != "active" || checked.Results[0].AccountKey != page.Entries[0].AccountKey {
		t.Fatalf("reference did not bind back to its own product account: %v", err)
	}
	rows.err = domain.ErrNotFound
	checked, err = directory.Check(ctx, reader, CheckInput{ProductID: "linka-type", References: []string{ref}})
	if err != nil || checked.Results[0].State != "inactive" {
		t.Fatal("withdrawal/deletion was hidden by a weekly contact copy")
	}
	directory.now = func() time.Time { return time.Now().UTC().Add(9 * 24 * time.Hour) }
	checked, err = directory.Check(ctx, reader, CheckInput{ProductID: "linka-type", References: []string{ref}})
	if err != nil || checked.Results[0].State != "unknown" {
		t.Fatal("expired reference was treated as current authority")
	}
	if rows.audits != 4 {
		t.Fatalf("protected directory operations were not audited: %d", rows.audits)
	}
}

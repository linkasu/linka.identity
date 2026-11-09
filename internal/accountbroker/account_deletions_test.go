package accountbroker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/linka-cloud/linka.identity/internal/token"
)

func expiredDeletionJWT(t *testing.T, b *Broker, input token.AccountAccessInput) string {
	t.Helper()
	encoded, _, err := b.signer.SignAccountAccess(input)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(encoded, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims token.AccountAccessClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	claims.IssuedAt, claims.ExpiresAt = time.Now().Add(-2*time.Minute).Unix(), time.Now().Add(-time.Minute).Unix()
	payload, err = json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload)
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)), []byte(unsigned)))
}

type deletionRepository struct {
	Repository
	session        store.AccountSession
	denied         bool
	createErr      error
	created        *store.PublicAccountDeletion
	status         store.PrivacyRequestStatus
	authorizations int
}

func (r *deletionRepository) AuthorizedPublicAccountSession(_ context.Context, id, product string) (store.AccountSession, store.ProductAccount, error) {
	r.authorizations++
	if r.denied || id != r.session.ID || product != r.session.ProductID {
		return store.AccountSession{}, store.ProductAccount{}, domain.ErrNotFound
	}
	return r.session, store.ProductAccount{}, nil
}

func (r *deletionRepository) CreatePublicAccountDeletion(_ context.Context, input store.PublicAccountDeletion, products map[string]string) (store.PrivacyRequestStatus, error) {
	if r.createErr != nil {
		return store.PrivacyRequestStatus{}, r.createErr
	}
	if input.SessionID != r.session.ID || input.AccountID != r.session.AccountID || input.ProductID != r.session.ProductID || products[input.ProductID] == "" {
		return store.PrivacyRequestStatus{}, domain.ErrNotFound
	}
	r.created = &input
	r.status = store.PrivacyRequestStatus{ID: "private-root-request", RequestType: "deletion", Scope: "product", ProductID: &input.ProductID, Status: "requested", RequestedAt: input.RequestedAt}
	return r.status, nil
}

func (r *deletionRepository) PublicAccountDeletionStatus(_ context.Context, requestID, product, hash string) (store.PrivacyRequestStatus, error) {
	if r.created == nil || r.created.RequestID != requestID || r.created.ProductID != product || r.created.StatusSecretHash != hash {
		return store.PrivacyRequestStatus{}, domain.ErrNotFound
	}
	return r.status, nil
}

func TestCreateDeletionBindsSignedSubjectSessionAndProduct(t *testing.T) {
	for _, name := range []string{"valid", "cross account", "wrong product", "unknown product", "wrong session", "revoked session", "expired JWT", "status secret", "revoked during transaction"} {
		t.Run(name, func(t *testing.T) {
			b, _, _, fixture := newBeginBroker(t)
			r := &deletionRepository{session: store.AccountSession{ID: "ac17879e-b16b-4a2d-b763-764230f51587", AccountID: "3499c1bc-e936-43af-a601-f98562dd0351", ProductID: fixture.ProductID}}
			b.repository = r
			input := DeletionInput{RequestID: fixture.RequestID, StatusSecret: fixture.ClientNonce}
			claims := token.AccountAccessInput{Product: r.session.ProductID, SessionID: r.session.ID, Subject: b.pairwise.Subject(r.session.ProductID, token.AccountAudience, "account", r.session.AccountID), TTL: time.Minute}
			switch name {
			case "cross account":
				claims.Subject = b.pairwise.Subject(r.session.ProductID, token.AccountAudience, "account", "another-account")
			case "wrong product":
				claims.Product = "other-product"
				b.products[claims.Product] = "other-metric"
			case "unknown product":
				claims.Product = "unknown-product"
			case "wrong session":
				claims.SessionID = fixture.RequestID
			case "revoked session":
				r.denied = true
			case "revoked during transaction":
				r.createErr = domain.ErrNotFound
			}
			credential, _, err := b.signer.SignAccountAccess(claims)
			if err != nil {
				t.Fatal(err)
			}
			if name == "expired JWT" {
				// A separately signed, already expired JWT exercises the real verifier.
				credential = expiredDeletionJWT(t, b, claims)
			}
			if name == "status secret" {
				credential = input.StatusSecret
			}
			result, err := b.CreateDeletion(t.Context(), credential, input)
			if name != "valid" {
				if !errors.Is(err, ErrAccountCredential) || r.created != nil {
					t.Fatalf("unexpected authority: %+v %v", result, err)
				}
				return
			}
			if err != nil || result.Status != "requested" || result.RequestID != input.RequestID || r.created == nil || r.created.StatusSecretHash == input.StatusSecret || len(r.created.StatusSecretHash) != 64 {
				t.Fatalf("creation: %+v %v", result, err)
			}
		})
	}
}

func TestDeletionStatusCapabilitySurvivesSessionErasureAndCannotCrossContext(t *testing.T) {
	b, _, _, fixture := newBeginBroker(t)
	product := fixture.ProductID
	r := &deletionRepository{created: &store.PublicAccountDeletion{RequestID: fixture.RequestID, ProductID: product, StatusSecretHash: deletionSecretHash(fixture.ClientNonce)}, denied: true,
		status: store.PrivacyRequestStatus{ID: "private-root-request", RequestType: "deletion", Scope: "product", ProductID: &product, Status: "completed", RequestedAt: time.Now().UTC()}}
	b.repository = r
	for _, name := range []string{"valid", "wrong secret", "wrong request", "wrong product", "unknown product", "malformed secret", "malformed UUID"} {
		t.Run(name, func(t *testing.T) {
			input := DeletionStatusInput{RequestID: fixture.RequestID, ProductID: product}
			secret, expected := fixture.ClientNonce, error(nil)
			switch name {
			case "wrong secret":
				secret = strings.Repeat("A", 43)
				expected = domain.ErrNotFound
			case "wrong request":
				input.RequestID = "ac17879e-b16b-4a2d-b763-764230f51587"
				expected = domain.ErrNotFound
			case "wrong product":
				input.ProductID = "other-product"
				b.products[input.ProductID] = "other-metric"
				expected = domain.ErrNotFound
			case "unknown product":
				input.ProductID = "unknown-product"
				expected = domain.ErrNotFound
			case "malformed secret":
				secret += "="
				expected = ErrAccountCredential
			case "malformed UUID":
				input.RequestID = "no"
				expected = domain.ErrInvalid
			}
			result, err := b.DeletionStatus(t.Context(), secret, input)
			if !errors.Is(err, expected) || r.authorizations != 0 {
				t.Fatalf("status: %+v %v", result, err)
			}
			if expected == nil {
				encoded, _ := json.Marshal(result)
				if result.Status != "completed" || strings.Contains(string(encoded), "private-root") || strings.Contains(string(encoded), secret) {
					t.Fatalf("unsafe status: %s", encoded)
				}
			}
		})
	}
}

func TestDeletionValidatesInputBeforeRepositoryAndBoundsResponse(t *testing.T) {
	b, _, _, fixture := newBeginBroker(t)
	for _, input := range []DeletionInput{
		{RequestID: "not-a-uuid", StatusSecret: fixture.ClientNonce},
		{RequestID: fixture.RequestID, StatusSecret: fixture.ClientNonce + "="},
		{RequestID: fixture.RequestID, StatusSecret: strings.Repeat("A", 42) + "B"},
		{RequestID: fixture.RequestID},
	} {
		if _, err := b.CreateDeletion(t.Context(), "not-a-JWT", input); !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("malformed input accepted: %v", err)
		}
	}
	product := fixture.ProductID
	result := store.PrivacyRequestStatus{ID: "private-request", RequestType: "deletion", Scope: "product", ProductID: &product}
	for _, status := range []string{"requested", "processing", "completed", "rejected", "cancelled"} {
		result.Status = status
		got, err := publicDeletionStatus(result, product, fixture.RequestID)
		if err != nil || got.Status != status || got.RequestID != fixture.RequestID {
			t.Fatalf("status lost: %+v %v", got, err)
		}
	}
	for _, name := range []string{"unknown status", "all scope", "export", "wrong product", "missing product"} {
		bad := result
		switch name {
		case "unknown status":
			bad.Status = "accepted"
		case "all scope":
			bad.Scope = "all"
		case "export":
			bad.RequestType = "export"
		case "wrong product":
			other := "other-product"
			bad.ProductID = &other
		case "missing product":
			bad.ProductID = nil
		}
		if _, err := publicDeletionStatus(bad, product, fixture.RequestID); err == nil {
			t.Fatalf("invalid response context: %s", name)
		}
	}
}

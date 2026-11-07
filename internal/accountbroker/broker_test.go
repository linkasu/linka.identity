package accountbroker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/cryptokit"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/installationbroker"
	"github.com/linka-cloud/linka.identity/internal/pairwise"
	"github.com/linka-cloud/linka.identity/internal/service"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/linka-cloud/linka.identity/internal/token"
)

type beginRepository struct {
	Repository
	rows          map[string]store.PublicEmailChallenge
	verifications []store.EmailVerification
	creates       int
	completions   []store.PublicEmailCompletion
	session       store.AccountSession
	profile       store.ProductAccount
	cancelOnRead  bool
	claimErrors   []error
	claimCalls    int
}

func (r *beginRepository) EmailVerification(_ context.Context, id string) (store.EmailVerification, error) {
	for _, v := range r.verifications {
		if v.ID == id {
			return v, nil
		}
	}
	return store.EmailVerification{}, domain.ErrNotFound
}

func (r *beginRepository) CompletePublicEmailChallenge(_ context.Context, input store.PublicEmailCompletion) (store.PublicEmailRegistration, error) {
	r.completions = append(r.completions, input)
	if input.Identity.AccountID == "" {
		return store.PublicEmailRegistration{}, domain.ErrNotFound
	}
	r.session = store.AccountSession{ID: input.SessionID, ProductID: input.ProductID, AccountID: input.Identity.AccountID, InstallationID: input.InstallationID, State: domain.PublicSessionActive, ExpiresAt: input.RefreshExpiresAt, CreatedAt: input.Identity.VerifiedAt, Version: 1}
	r.profile = store.ProductAccount{ProductID: input.ProductID, AccountID: input.Identity.AccountID, EmailIdentityID: input.Identity.ID, HolderRole: "representative", Status: "active", VerifiedAt: input.Identity.VerifiedAt, Version: 1}
	return store.PublicEmailRegistration{Identity: store.EmailIdentity{AccountID: r.session.AccountID}, Session: r.session, Account: r.profile}, nil
}

func (r *beginRepository) PublicEmailChallenge(_ context.Context, id string) (store.PublicEmailChallenge, error) {
	row, ok := r.rows[id]
	if !ok {
		return row, domain.ErrNotFound
	}
	if r.cancelOnRead {
		row.State = domain.PublicChallengeCancelled
		r.rows[id] = row
	}
	return row, nil
}

func (r *beginRepository) ClaimPublicEmailDelivery(_ context.Context, owner string, products []string, _ uint64) (store.PublicEmailChallenge, store.EmailVerification, error) {
	r.claimCalls++
	if len(r.claimErrors) != 0 {
		err := r.claimErrors[0]
		r.claimErrors = r.claimErrors[1:]
		return store.PublicEmailChallenge{}, store.EmailVerification{}, err
	}
	for _, row := range r.rows {
		if row.State != domain.PublicChallengeRequested || row.MailAvailableAt.After(time.Now().UTC()) {
			continue
		}
		allowed := false
		for _, product := range products {
			allowed = allowed || product == row.ProductID
		}
		if !allowed {
			continue
		}
		until := time.Now().UTC().Add(90 * time.Second)
		row.State, row.MailClaimToken, row.MailClaimUntil = domain.PublicChallengeDelivering, &owner, &until
		row.ExpiresAt = time.Now().UTC().Add(domain.PublicEmailCodeTTL)
		r.rows[row.ID] = row
		verification, err := r.EmailVerification(context.Background(), row.ID)
		verification.ExpiresAt = row.ExpiresAt
		for i := range r.verifications {
			if r.verifications[i].ID == row.ID {
				r.verifications[i] = verification
			}
		}
		return row, verification, err
	}
	return store.PublicEmailChallenge{}, store.EmailVerification{}, domain.ErrNotFound
}

func (r *beginRepository) DeferPublicEmailDelivery(_ context.Context, id, owner string, retryAt time.Time) error {
	row := r.rows[id]
	if row.MailClaimToken == nil || *row.MailClaimToken != owner {
		return domain.ErrConflict
	}
	row.State, row.MailAvailableAt = domain.PublicChallengeRequested, retryAt
	row.MailClaimToken, row.MailClaimUntil = nil, nil
	row.ExpiresAt = row.CreatedAt.Add(domain.PublicEmailQueueTTL)
	r.rows[id] = row
	return nil
}

func (r *beginRepository) FinishPublicEmailDelivery(_ context.Context, id, owner string, state domain.PublicChallengeState) error {
	row := r.rows[id]
	if row.MailClaimToken == nil || *row.MailClaimToken != owner {
		return domain.ErrConflict
	}
	row.State = state
	r.rows[id] = row
	return nil
}

func (r *beginRepository) CreatePublicEmailChallenge(_ context.Context, c store.PublicEmailChallenge, v store.EmailVerification, daily uint64) (store.PublicEmailChallenge, bool, error) {
	if daily != 200 {
		return c, false, domain.ErrInvalid
	}
	r.creates++
	r.rows[c.ID] = c
	r.verifications = append(r.verifications, v)
	return c, true, nil
}

type installationAuthenticator struct{ product string }

func (a installationAuthenticator) AuthenticateInstallation(_ context.Context, credential string) (installationbroker.InstallationContext, error) {
	if credential != "fixture-installation-refresh" {
		return installationbroker.InstallationContext{}, installationbroker.ErrInvalidCredential
	}
	return installationbroker.InstallationContext{ProductID: a.product, InstallationID: "ac17879e-b16b-4a2d-b763-764230f51587", InstallationKey: strings.Repeat("a", 64), TelemetryAudience: "linka-type-metric"}, nil
}

func newBeginBroker(t *testing.T) (*Broker, *beginRepository, *cryptokit.Envelope, ChallengeInput) {
	t.Helper()
	provider, _ := cryptokit.NewLocalAESKeyProvider("test", bytes.Repeat([]byte{1}, 32))
	envelope := cryptokit.NewEnvelope(provider)
	indexer, _ := cryptokit.NewBlindIndexer(1, map[int][]byte{1: bytes.Repeat([]byte{2}, 32)})
	signer, _ := token.NewSigner(bytes.Repeat([]byte{3}, 32), "test", "https://identity.example.test", 5*time.Minute, 15*time.Minute)
	aliases, _ := pairwise.New(bytes.Repeat([]byte{4}, 32))
	repository := &beginRepository{rows: make(map[string]store.PublicEmailChallenge)}
	b, err := New(Dependencies{Repository: repository, Installations: installationAuthenticator{"linka-type"}, Identity: service.NewIdentityService(nil, envelope, indexer, false), Envelope: envelope, Signer: signer, Pairwise: aliases}, Config{
		Products: map[string]installationbroker.Product{"linka-type": {Audience: "linka-type-metric"}}, RegistrationProducts: map[string]struct{}{"linka-type": {}}, RegistrationPolicyVersion: "product-registration-v1", OTPKeyID: "test", OTPKey: bytes.Repeat([]byte{5}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	input := ChallengeInput{RequestID: "3499c1bc-e936-43af-a601-f98562dd0351", ProductID: "linka-type", Email: "Owner@Example.Test", Purpose: RegistrationPurpose, ClientNonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32)), HolderRole: "representative"}
	return b, repository, envelope, input
}

func TestBeginPublicEmailChallengeProtectsPurposeContextAndAddress(t *testing.T) {
	b, repository, envelope, input := newBeginBroker(t)
	result, err := b.Begin(context.Background(), "fixture-installation-refresh", input)
	if err != nil || result.Status != "queued" || result.ContractVersion != 1 || result.ChallengeID != input.RequestID || repository.creates != 1 {
		t.Fatalf("begin: %+v error=%v", result, err)
	}
	if !result.ExpiresAt.After(time.Now().UTC().Add(47 * time.Hour)) {
		t.Fatal("queue wait consumed the OTP delivery window")
	}
	encoded, _ := json.Marshal(result)
	if bytes.Contains(bytes.ToLower(encoded), []byte("owner@example.test")) {
		t.Fatal("generic challenge response exposed an address")
	}
	c := repository.rows[result.ChallengeID]
	if len(c.CodeHash) != 32 || len(c.NonceHash) != 32 || bytes.Equal(c.NonceHash, []byte(input.ClientNonce)) || c.State != domain.PublicChallengeRequested || c.HolderRole != "representative" {
		t.Fatal("challenge proof/context was not protected")
	}
	plain, err := envelope.Decrypt(context.Background(), c.Code, otpAAD(c.ID, c.ProductID))
	if err != nil || len(plain) != 6 {
		t.Fatal("queued code is not recoverable only by the server sender")
	}
	v := repository.verifications[0]
	if v.VerifiedAt != nil || v.LinkAcrossProducts || v.Namespace != "account" || v.AgeCategory != "unknown" {
		t.Fatal("request alone invented verification or consent")
	}
	if _, err := b.Begin(context.Background(), "fixture-installation-refresh", input); err != nil || repository.creates != 1 {
		t.Fatalf("idempotent replay reserved another message: %v", err)
	}
	input.Email = "different@example.test"
	if _, err := b.Begin(context.Background(), "fixture-installation-refresh", input); !errors.Is(err, domain.ErrConflict) || repository.creates != 1 {
		t.Fatalf("idempotency UUID accepted another context: %v", err)
	}
}

func TestBeginPublicEmailChallengeRequiresMatchingInstallationAndAllowedProduct(t *testing.T) {
	b, repository, _, input := newBeginBroker(t)
	if _, err := b.Begin(context.Background(), "invalid", input); err == nil || repository.creates != 0 {
		t.Fatal("invalid installation capability reached the queue")
	}
	b.installations = installationAuthenticator{"linka-looks"}
	if _, err := b.Begin(context.Background(), "fixture-installation-refresh", input); err == nil || repository.creates != 0 {
		t.Fatal("another product's installation reached the queue")
	}
}

func TestVerifyPublicEmailSeparatesAccountAccessReceiptAndTelemetry(t *testing.T) {
	b, repository, envelope, input := newBeginBroker(t)
	challenge, err := b.Begin(context.Background(), "fixture-installation-refresh", input)
	if err != nil {
		t.Fatal(err)
	}
	c := repository.rows[challenge.ChallengeID]
	c.State = domain.PublicChallengeDelivered
	repository.rows[c.ID] = c
	code, err := envelope.Decrypt(context.Background(), c.Code, otpAAD(c.ID, c.ProductID))
	if err != nil {
		t.Fatal(err)
	}
	registered, err := b.Verify(context.Background(), "fixture-installation-refresh", c.ID, VerifyInput{ProductID: input.ProductID, ClientNonce: input.ClientNonce, Code: string(code)})
	if err != nil || registered.MetricsToken != nil || registered.AccountToken.TokenType != "Bearer" || len(registered.RefreshToken) != 43 {
		t.Fatalf("registration response did not separate credentials: %v", err)
	}
	access, err := b.signer.VerifyAccountAccess(registered.AccountToken.AccessToken)
	if err != nil || access.Subject != registered.AccountKey || access.SessionID != repository.session.ID {
		t.Fatalf("account token is not bound to committed session: %v", err)
	}
	receipt, err := b.signer.VerifyRegistrationReceipt(registered.RegistrationReceipt)
	if err != nil || receipt.Product != input.ProductID || receipt.Subject != registered.AccountKey || receipt.InstallationKey != registered.InstallationKey || receipt.HolderRole != "representative" {
		t.Fatalf("receipt is not bound to its local product/install context: %v", err)
	}
	if _, err := b.signer.VerifyAccountAccess(registered.RegistrationReceipt); err == nil {
		t.Fatal("local receipt became online authority")
	}
	encoded, _ := json.Marshal(registered)
	if bytes.Contains(bytes.ToLower(encoded), []byte("owner@example.test")) || bytes.Contains(encoded, []byte(repository.session.AccountID)) {
		t.Fatal("public response exposed a contact or root account ID")
	}
}

func TestWrongPublicOTPDoesNotPrepareOrGrantIdentity(t *testing.T) {
	b, repository, _, input := newBeginBroker(t)
	challenge, err := b.Begin(context.Background(), "fixture-installation-refresh", input)
	if err != nil {
		t.Fatal(err)
	}
	c := repository.rows[challenge.ChallengeID]
	c.State = domain.PublicChallengeDelivered
	repository.rows[c.ID] = c
	// A sender/preparation dependency failure must be irrelevant for a wrong code.
	b.identity = nil
	if _, err := b.Verify(context.Background(), "fixture-installation-refresh", c.ID, VerifyInput{ProductID: input.ProductID, ClientNonce: input.ClientNonce, Code: "invalid"}); err == nil || len(repository.completions) != 0 {
		t.Fatal("malformed OTP reached persistence")
	}
	wrong := "000000"
	if bytes.Equal(c.CodeHash, b.digest("code", c.ProductID, c.InstallationID, c.ID, RegistrationPurpose, hex.EncodeToString(c.NonceHash), hex.EncodeToString(c.EmailBlindIndex), wrong)) {
		wrong = "000001"
	}
	if _, err := b.Verify(context.Background(), "fixture-installation-refresh", c.ID, VerifyInput{ProductID: input.ProductID, ClientNonce: input.ClientNonce, Code: wrong}); !errors.Is(err, domain.ErrNotFound) || len(repository.completions) != 1 || repository.completions[0].Identity.AccountID != "" {
		t.Fatalf("wrong code prepared an identity or skipped the durable attempt: %v", err)
	}
}

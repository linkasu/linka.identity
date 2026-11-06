package store

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/cryptokit"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

// The client models the SDK's commit-on-nil contract, not YDB's SQL engine.
type verificationClient struct {
	query.Client
	mu           sync.Mutex
	tx           verificationTx
	transactions int
	committed    []string
	consumed     bool
}

func (c *verificationClient) DoTx(ctx context.Context, operation query.TxOperation, _ ...query.DoTxOption) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.transactions++
	c.tx.pending = nil
	c.tx.consumed = c.consumed
	if err := operation(ctx, &c.tx); err != nil {
		return err
	}
	c.committed = append(c.committed, c.tx.pending...)
	for _, sql := range c.tx.pending {
		if strings.Contains(sql, "DELETE FROM email_verifications") {
			c.consumed = true
		}
	}
	return nil
}

type verificationTx struct {
	query.TxActor
	verification EmailVerification
	claim        *string
	processingAt *time.Time
	consumeErr   error
	existing     bool
	consumed     bool
	pending      []string
}

func (tx *verificationTx) QueryRow(_ context.Context, sql string, _ ...query.ExecuteOption) (query.Row, error) {
	v := tx.verification
	switch {
	case strings.Contains(sql, "FROM email_verifications"):
		if tx.consumed {
			return nil, query.ErrNoRows
		}
		if strings.Contains(sql, "SELECT product_id, installation_id") {
			return verificationRow{values: []any{v.ProductID, v.InstallationID, v.Namespace, v.AgeCategory,
				v.GuardianRelationship, v.LinkAcrossProducts, uint64(v.BlindIndexVersion), v.BlindIndex,
				v.ExpiresAt, v.VerifiedAt, tx.claim, tx.processingAt}}, nil
		}
		verifier, evidence := "verifier", "evidence"
		return verificationRow{values: []any{v.InstallationID, v.ProductID, &verifier, &evidence, v.VerifiedAt, tx.claim, uint64(2)}}, nil
	case strings.Contains(sql, "FROM email_blind_indexes"):
		if tx.existing {
			return verificationRow{values: []any{"existing-identity"}}, nil
		}
		return nil, query.ErrNoRows
	case strings.Contains(sql, "FROM email_identities"):
		return verificationRow{values: []any{"existing-person"}}, nil
	case strings.Contains(sql, "FROM accounts_by_person"):
		return verificationRow{values: []any{"existing-account"}}, nil
	case strings.Contains(sql, "FROM product_installations"):
		return verificationRow{values: []any{v.ProductID, (*string)(nil), (*time.Time)(nil), uint64(1)}}, nil
	case strings.Contains(sql, "UPDATE product_installations"):
		tx.pending = append(tx.pending, sql)
		return verificationRow{values: []any{uint64(2)}}, nil
	default:
		return nil, errors.New("unexpected query: " + sql)
	}
}

func (tx *verificationTx) Exec(_ context.Context, sql string, _ ...query.ExecuteOption) error {
	tx.pending = append(tx.pending, sql)
	if strings.Contains(sql, "INSERT INTO email_verification_audit") {
		return tx.consumeErr
	}
	return nil
}

type verificationRow struct {
	query.Row
	values []any
}

func (row verificationRow) Scan(dst ...any) error {
	if len(dst) != len(row.values) {
		return errors.New("unexpected scan shape")
	}
	for i, value := range row.values {
		reflect.ValueOf(dst[i]).Elem().Set(reflect.ValueOf(value))
	}
	return nil
}

func atomicVerificationFixture() (*Store, *verificationClient, NewEmailIdentity, []cryptokit.BlindIndex) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	claim, installation := "claim", "installation"
	verification := EmailVerification{ID: "verification", ProductID: "plays", Namespace: "account", AgeCategory: "adult",
		InstallationID: &installation, VerifiedAt: &now, ExpiresAt: now.Add(time.Minute), BlindIndexVersion: 1, BlindIndex: []byte("index")}
	client := &verificationClient{tx: verificationTx{verification: verification, claim: &claim, processingAt: &now}}
	identity := NewEmailIdentity{ID: "identity", PersonID: "person", AccountID: "account", ProductID: "plays",
		Namespace: "account", AgeCategory: "adult", InstallationID: &installation, VerifiedAt: now,
		BlindIndexVersion: 1, BlindIndex: []byte("index"), LinkageScope: "product", ScopeKey: "plays", CreateAccount: true}
	return &Store{client: client, now: func() time.Time { return now }}, client, identity, []cryptokit.BlindIndex{{Version: 1, Value: []byte("index")}}
}

func TestRegisterVerifiedEmailIdentityRollsBackRegistrationOnConsumeFailure(t *testing.T) {
	database, client, identity, indexes := atomicVerificationFixture()
	failure := errors.New("audit insertion failed")
	client.tx.consumeErr = failure
	result, created, err := database.RegisterVerifiedEmailIdentity(context.Background(), "verification", "plays", "claim", identity, indexes)
	if !errors.Is(err, failure) || created || result != (EmailIdentity{}) {
		t.Fatalf("result=%#v created=%v err=%v", result, created, err)
	}
	if client.transactions != 1 || len(client.committed) != 0 || client.consumed {
		t.Fatal("registration escaped the failed consumption transaction")
	}
	for _, write := range []string{"INSERT INTO persons", "INSERT INTO email_identities", "INSERT INTO email_blind_indexes", "INSERT INTO accounts", "UPDATE product_installations", "UPDATE subject_aliases", "INSERT INTO email_verification_audit"} {
		if !strings.Contains(strings.Join(client.tx.pending, "\n"), write) {
			t.Fatalf("consume failure was not reached after %s", write)
		}
	}
	client.tx.consumeErr = nil
	result, created, err = database.RegisterVerifiedEmailIdentity(context.Background(), "verification", "plays", "claim", identity, indexes)
	if err != nil || !created || result.AccountID != "account" || !client.consumed {
		t.Fatalf("retry result=%#v created=%v err=%v", result, created, err)
	}
	if _, _, err := database.RegisterVerifiedEmailIdentity(context.Background(), "verification", "plays", "claim", identity, indexes); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("replay error=%v", err)
	}
}

func TestRegisterVerifiedEmailIdentityConcurrentCompletion(t *testing.T) {
	database, client, identity, indexes := atomicVerificationFixture()
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, _, err := database.RegisterVerifiedEmailIdentity(context.Background(), "verification", "plays", "claim", identity, indexes)
			results <- err
		}()
	}
	successes := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		} else if !errors.Is(err, domain.ErrNotFound) {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful completions=%d", successes)
	}
	for _, write := range []string{"INSERT INTO accounts (", "INSERT INTO email_verification_audit"} {
		if count := strings.Count(strings.Join(client.committed, "\n"), write); count != 1 {
			t.Fatalf("%s count=%d", write, count)
		}
	}
}

func TestRegisterVerifiedEmailIdentityRejectsMismatchedOrExpiredClaim(t *testing.T) {
	for name, mutate := range map[string]func(*verificationClient, *NewEmailIdentity, *[]cryptokit.BlindIndex){
		"product":   func(_ *verificationClient, i *NewEmailIdentity, _ *[]cryptokit.BlindIndex) { i.ProductID = "other" },
		"namespace": func(_ *verificationClient, i *NewEmailIdentity, _ *[]cryptokit.BlindIndex) { i.Namespace = "donation" },
		"scope": func(_ *verificationClient, i *NewEmailIdentity, _ *[]cryptokit.BlindIndex) {
			i.LinkageScope, i.ScopeKey = "global", "global"
		},
		"scope key": func(_ *verificationClient, i *NewEmailIdentity, _ *[]cryptokit.BlindIndex) { i.ScopeKey = "other" },
		"email": func(_ *verificationClient, _ *NewEmailIdentity, indexes *[]cryptokit.BlindIndex) {
			(*indexes)[0].Value = []byte("other")
		},
		"current index": func(_ *verificationClient, i *NewEmailIdentity, _ *[]cryptokit.BlindIndex) {
			i.BlindIndex = []byte("other")
		},
		"installation": func(_ *verificationClient, i *NewEmailIdentity, _ *[]cryptokit.BlindIndex) { i.InstallationID = nil },
		"age":          func(_ *verificationClient, i *NewEmailIdentity, _ *[]cryptokit.BlindIndex) { i.AgeCategory = "minor" },
		"guardian": func(_ *verificationClient, i *NewEmailIdentity, _ *[]cryptokit.BlindIndex) {
			guardian := "guardian"
			i.GuardianRelationship = &guardian
		},
		"verified time": func(_ *verificationClient, i *NewEmailIdentity, _ *[]cryptokit.BlindIndex) {
			i.VerifiedAt = i.VerifiedAt.Add(time.Second)
		},
		"unverified": func(c *verificationClient, _ *NewEmailIdentity, _ *[]cryptokit.BlindIndex) {
			c.tx.verification.VerifiedAt = nil
		},
		"claim token": func(c *verificationClient, _ *NewEmailIdentity, _ *[]cryptokit.BlindIndex) {
			token := "other"
			c.tx.claim = &token
		},
		"missing claim":           func(c *verificationClient, _ *NewEmailIdentity, _ *[]cryptokit.BlindIndex) { c.tx.claim = nil },
		"missing processing time": func(c *verificationClient, _ *NewEmailIdentity, _ *[]cryptokit.BlindIndex) { c.tx.processingAt = nil },
		"expired lease": func(c *verificationClient, _ *NewEmailIdentity, _ *[]cryptokit.BlindIndex) {
			expired := c.tx.processingAt.Add(-EmailVerificationClaimLease)
			c.tx.processingAt = &expired
		},
		"expired challenge": func(c *verificationClient, _ *NewEmailIdentity, _ *[]cryptokit.BlindIndex) {
			c.tx.verification.ExpiresAt = *c.tx.processingAt
		},
	} {
		t.Run(name, func(t *testing.T) {
			database, client, identity, indexes := atomicVerificationFixture()
			mutate(client, &identity, &indexes)
			_, _, err := database.RegisterVerifiedEmailIdentity(context.Background(), "verification", "plays", "claim", identity, indexes)
			if !errors.Is(err, domain.ErrNotFound) || len(client.tx.pending) != 0 {
				t.Fatalf("err=%v writes=%d", err, len(client.tx.pending))
			}
		})
	}
}

func TestRegisterEmailIdentitySharedTransactionContract(t *testing.T) {
	for _, verified := range []bool{false, true} {
		for _, existing := range []bool{false, true} {
			database, client, identity, indexes := atomicVerificationFixture()
			client.tx.existing = existing
			var result EmailIdentity
			var created bool
			var err error
			if verified {
				result, created, err = database.RegisterVerifiedEmailIdentity(context.Background(), "verification", "plays", "claim", identity, indexes)
			} else {
				result, created, err = database.RegisterEmailIdentity(context.Background(), identity, indexes)
			}
			if err != nil || created == existing {
				t.Fatalf("verified=%v existing=%v created=%v err=%v", verified, existing, created, err)
			}
			if existing && (result.PersonID != "existing-person" || result.AccountID != "existing-account") {
				t.Fatalf("deduplication result=%#v", result)
			}
			if client.transactions != 1 {
				t.Fatalf("transactions=%d", client.transactions)
			}
		}
	}
}

func TestRegisterVerifiedEmailIdentityProductAndIndexRotationBinding(t *testing.T) {
	database, client, identity, indexes := atomicVerificationFixture()
	if _, _, err := database.RegisterVerifiedEmailIdentity(context.Background(), "verification", "other", "claim", identity, indexes); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("other product error=%v", err)
	}
	identity.BlindIndexVersion, identity.BlindIndex = 2, []byte("rotated-index")
	indexes = append(indexes, cryptokit.BlindIndex{Version: 2, Value: identity.BlindIndex})
	if _, _, err := database.RegisterVerifiedEmailIdentity(context.Background(), "verification", "plays", "claim", identity, indexes[1:]); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing verification index error=%v", err)
	}
	conflicting := append(append([]cryptokit.BlindIndex{}, indexes...), cryptokit.BlindIndex{Version: 1, Value: []byte("other-email")})
	if _, _, err := database.RegisterVerifiedEmailIdentity(context.Background(), "verification", "plays", "claim", identity, conflicting); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("conflicting verification index error=%v", err)
	}
	result, created, err := database.RegisterVerifiedEmailIdentity(context.Background(), "verification", "plays", "claim", identity, indexes)
	if err != nil || !created || result.AccountID != "account" || !client.consumed {
		t.Fatalf("rotation result=%#v created=%v err=%v", result, created, err)
	}
}

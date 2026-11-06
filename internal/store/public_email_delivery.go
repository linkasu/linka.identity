package store

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
	"github.com/ydb-platform/ydb-go-sdk/v3/types"
)

type publicEmailDeliveryError struct{ cause error }

func (publicEmailDeliveryError) Error() string   { return "public email delivery storage failed" }
func (e publicEmailDeliveryError) Unwrap() error { return e.cause }

func validPublicEmailDeliveryProducts(owner string, products []string) error {
	if !domain.ValidUUID(owner) || len(products) > 100 {
		return domain.ErrInvalid
	}
	seen := make(map[string]bool, len(products))
	for _, product := range products {
		if !domain.ValidProductID(product) || seen[product] {
			return domain.ErrInvalid
		}
		seen[product] = true
	}
	if len(products) == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// ClaimPublicEmailDelivery never retries an external send whose outcome is unknown.
func (s *Store) ClaimPublicEmailDelivery(ctx context.Context, owner string, products []string) (PublicEmailChallenge, EmailVerification, error) {
	if err := validPublicEmailDeliveryProducts(owner, products); err != nil {
		return PublicEmailChallenge{}, EmailVerification{}, err
	}
	allowed := make([]types.Value, len(products))
	for i, product := range products {
		allowed[i] = types.UTF8Value(product)
	}
	var saved PublicEmailChallenge
	var verification EmailVerification
	err := s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		saved, verification = PublicEmailChallenge{}, EmailVerification{}
		now := s.now().UTC().Truncate(time.Microsecond)
		parameters := query.WithParameters(ydb.ParamsBuilder().Param("$products").Any(types.ListValue(allowed...)).Param("$now").Timestamp(now).Build())
		row, err := tx.QueryRow(ctx, `DECLARE $products AS List<Utf8>; DECLARE $now AS Timestamp;
SELECT `+publicChallengeColumns+` FROM public_email_challenges VIEW public_email_mail_queue
WHERE state='delivering' AND product_id IN $products AND (mail_claim_until IS NULL OR mail_claim_until <= $now)
ORDER BY created_at,id LIMIT 1;`, parameters)
		if err == nil {
			c, err := scanPublicChallenge(row)
			if err != nil {
				return err
			}
			if err := finishPublicEmailDeliveryTx(ctx, tx, c, domain.PublicChallengeDeliveryUncertain, now); err != nil {
				return err
			}
			saved, err = readPublicChallenge(ctx, tx, c.ID)
			return err
		}
		if !errors.Is(err, query.ErrNoRows) {
			return err
		}
		row, err = tx.QueryRow(ctx, `DECLARE $products AS List<Utf8>; DECLARE $now AS Timestamp;
SELECT `+publicChallengeColumns+` FROM public_email_challenges VIEW public_email_mail_queue
WHERE state='requested' AND product_id IN $products AND mail_available_at <= $now
ORDER BY created_at,id LIMIT 1;`, parameters)
		if err != nil {
			return noRows(err)
		}
		c, err := scanPublicChallenge(row)
		if err != nil {
			return err
		}
		finish := func(state domain.PublicChallengeState) error {
			if err := finishPublicChallengeTx(ctx, tx, c, state, now, nil); err != nil {
				return err
			}
			saved, err = readPublicChallenge(ctx, tx, c.ID)
			return err
		}
		flow, err := tx.QueryRow(ctx, `DECLARE $product AS Utf8; DECLARE $installation AS Utf8;
SELECT challenge_id FROM public_registration_flows WHERE product_id=$product AND installation_id=$installation;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$product").Text(c.ProductID).Param("$installation").Text(c.InstallationID).Build()))
		if errors.Is(err, query.ErrNoRows) {
			return finish(domain.PublicChallengeCancelled)
		}
		if err != nil {
			return err
		}
		var currentID string
		if err := flow.Scan(&currentID); err != nil {
			return err
		}
		if currentID != c.ID {
			return finish(domain.PublicChallengeCancelled)
		}
		if err := validateSubjectWith(ctx, tx, Subject{Kind: "installation", ID: c.InstallationID}, c.ProductID); err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return finish(domain.PublicChallengeCancelled)
			}
			return err
		}
		if !now.Before(c.ExpiresAt) {
			return finish(domain.PublicChallengeExpired)
		}
		v, err := readEmailVerification(ctx, tx, c.ID)
		if errors.Is(err, domain.ErrNotFound) {
			return finish(domain.PublicChallengeCancelled)
		}
		if err != nil {
			return err
		}
		if !now.Before(v.ExpiresAt) {
			return finish(domain.PublicChallengeExpired)
		}
		if !validPublicEmailDeliveryBinding(c, v) || c.MailAttempts != 0 {
			return domain.ErrConflict
		}
		if err := consumePublicAuthLimits(ctx, tx, now, owner, []publicAuthLimit{{Bucket: "otp-send:global", Window: time.Second, Max: 1}}); err != nil {
			return err
		}
		until := now.Add(90 * time.Second)
		if c.ExpiresAt.Before(until) {
			until = c.ExpiresAt
		}
		row, err = tx.QueryRow(ctx, `DECLARE $id AS Utf8; DECLARE $version AS Uint64; DECLARE $owner AS Utf8; DECLARE $until AS Timestamp; DECLARE $now AS Timestamp;
UPDATE public_email_challenges SET state='delivering',mail_attempts=1u,mail_claim_token=$owner,mail_claim_until=$until,updated_at=$now,version=version+1u
WHERE id=$id AND version=$version RETURNING version;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(c.ID).Param("$version").Uint64(c.Version).Param("$owner").Text(owner).Param("$until").Timestamp(until).Param("$now").Timestamp(now).Build()))
		if err := checkPublicVersion(row, err, c.Version); err != nil {
			return err
		}
		saved, err = readPublicChallenge(ctx, tx, c.ID)
		if err == nil {
			verification = v
		}
		return err
	})
	if err != nil {
		return PublicEmailChallenge{}, EmailVerification{}, publicEmailDeliveryError{cause: err}
	}
	return saved, verification, nil
}

func validPublicEmailDeliveryBinding(c PublicEmailChallenge, v EmailVerification) bool {
	return c.ID == v.ID && c.ProductID == v.ProductID && v.InstallationID != nil && c.InstallationID == *v.InstallationID &&
		c.Purpose == "product_registration" && v.Namespace == "account" && v.AgeCategory == "unknown" && v.GuardianRelationship == nil && !v.LinkAcrossProducts &&
		v.VerifiedAt == nil && v.ConsumedAt == nil && v.ProcessingToken == nil && v.ProcessingAt == nil &&
		c.EmailBlindIndexVersion > 0 && c.EmailBlindIndexVersion == v.BlindIndexVersion && len(c.EmailBlindIndex) == 32 && bytes.Equal(c.EmailBlindIndex, v.BlindIndex) &&
		len(c.CodeHash) == 32 && len(c.Code.Data) > 0 && len(c.Code.Nonce) > 0 && len(c.Code.WrappedDataKey) > 0 && c.Code.KeyID != "" && c.Code.Algorithm != "" &&
		len(v.EncryptedEmail.Data) > 0 && len(v.EncryptedEmail.Nonce) > 0 && len(v.EncryptedEmail.WrappedDataKey) > 0 && v.EncryptedEmail.KeyID != "" && v.EncryptedEmail.Algorithm != ""
}

func validPublicEmailDeliveryOutcome(state domain.PublicChallengeState) bool {
	return state == domain.PublicChallengeDelivered || state == domain.PublicChallengeDeliveryFailed || state == domain.PublicChallengeDeliveryUncertain
}

func publicEmailDeliveryAcknowledged(state domain.PublicChallengeState) bool {
	switch state {
	case domain.PublicChallengeConsumed, domain.PublicChallengeLocked, domain.PublicChallengeCancelled, domain.PublicChallengeExpired,
		domain.PublicChallengeDelivered, domain.PublicChallengeDeliveryFailed, domain.PublicChallengeDeliveryUncertain:
		return true
	default:
		return false
	}
}

func (s *Store) FinishPublicEmailDelivery(ctx context.Context, id, owner string, outcome domain.PublicChallengeState) error {
	if !domain.ValidUUID(id) || !domain.ValidUUID(owner) || !validPublicEmailDeliveryOutcome(outcome) {
		return domain.ErrInvalid
	}
	err := s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		c, err := readPublicChallenge(ctx, tx, id)
		if err != nil {
			return err
		}
		if publicEmailDeliveryAcknowledged(c.State) {
			return nil
		}
		if c.State != domain.PublicChallengeDelivering || c.MailClaimToken == nil || *c.MailClaimToken != owner {
			return domain.ErrConflict
		}
		return finishPublicEmailDeliveryTx(ctx, tx, c, outcome, s.now().UTC().Truncate(time.Microsecond))
	})
	if err != nil {
		return publicEmailDeliveryError{cause: err}
	}
	return nil
}

func finishPublicEmailDeliveryTx(ctx context.Context, tx query.TxActor, c PublicEmailChallenge, outcome domain.PublicChallengeState, now time.Time) error {
	if !validPublicEmailDeliveryOutcome(outcome) || !domain.CanTransitionPublicChallenge(c.State, outcome) {
		return domain.ErrConflict
	}
	hash := c.CodeHash
	if outcome == domain.PublicChallengeDeliveryFailed {
		hash = []byte{}
	}
	row, err := tx.QueryRow(ctx, `DECLARE $id AS Utf8; DECLARE $version AS Uint64; DECLARE $state AS Utf8; DECLARE $hash AS Bytes; DECLARE $empty AS Bytes; DECLARE $now AS Timestamp;
UPDATE public_email_challenges SET state=$state,code_hash=$hash,encrypted_code=$empty,code_nonce=$empty,wrapped_code_key=$empty,
code_kms_key_id='',code_encryption_algorithm='',mail_claim_token=NULL,mail_claim_until=NULL,updated_at=$now,version=version+1u
WHERE id=$id AND version=$version RETURNING version;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(c.ID).Param("$version").Uint64(c.Version).Param("$state").Text(string(outcome)).Param("$hash").Bytes(hash).Param("$empty").Bytes([]byte{}).Param("$now").Timestamp(now).Build()))
	if err := checkPublicVersion(row, err, c.Version); err != nil {
		return err
	}
	return appendPublicAccountAudit(ctx, tx, c.ID+"-mail-"+strconv.FormatUint(c.MailAttempts, 10), c.ProductID, "", "sender", "email."+string(outcome), c.ID, now)
}

package store

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"time"
	"unicode"

	"github.com/linka-cloud/linka.identity/internal/cryptokit"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

const publicChallengeColumns = `id,product_id,installation_id,purpose,holder_role,request_fingerprint,nonce_hash,code_hash,otp_key_id,encrypted_code,code_nonce,wrapped_code_key,code_kms_key_id,code_encryption_algorithm,email_blind_index_version,email_blind_index,state,attempts,mail_attempts,mail_available_at,mail_claim_token,mail_claim_until,created_at,updated_at,expires_at,verified_at,consumed_at,version`

func scanPublicChallenge(row query.Row) (c PublicEmailChallenge, err error) {
	var state string
	var indexVersion uint64
	err = row.Scan(&c.ID, &c.ProductID, &c.InstallationID, &c.Purpose, &c.HolderRole,
		&c.RequestFingerprint, &c.NonceHash, &c.CodeHash, &c.OTPKeyID,
		&c.Code.Data, &c.Code.Nonce, &c.Code.WrappedDataKey, &c.Code.KeyID, &c.Code.Algorithm,
		&indexVersion, &c.EmailBlindIndex, &state, &c.Attempts, &c.MailAttempts,
		&c.MailAvailableAt, &c.MailClaimToken, &c.MailClaimUntil, &c.CreatedAt, &c.UpdatedAt,
		&c.ExpiresAt, &c.VerifiedAt, &c.ConsumedAt, &c.Version)
	if err != nil {
		return c, err
	}
	if indexVersion > math.MaxInt {
		return c, domain.ErrInvalid
	}
	c.State, c.EmailBlindIndexVersion = domain.PublicChallengeState(state), int(indexVersion)
	return c, nil
}

func readPublicChallenge(ctx context.Context, executor query.Executor, id string) (PublicEmailChallenge, error) {
	row, err := executor.QueryRow(ctx, `DECLARE $id AS Utf8; SELECT `+publicChallengeColumns+` FROM public_email_challenges WHERE id=$id;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(id).Build()))
	if err != nil {
		return PublicEmailChallenge{}, noRows(err)
	}
	return scanPublicChallenge(row)
}

func (s *Store) PublicEmailChallenge(ctx context.Context, id string) (PublicEmailChallenge, error) {
	if !domain.ValidUUID(id) {
		return PublicEmailChallenge{}, domain.ErrInvalid
	}
	row, err := s.client.QueryRow(ctx, `DECLARE $id AS Utf8; SELECT `+publicChallengeColumns+` FROM public_email_challenges WHERE id=$id;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(id).Build()), query.WithTxControl(query.SnapshotReadOnlyTxControl()))
	if err != nil {
		return PublicEmailChallenge{}, noRows(err)
	}
	return scanPublicChallenge(row)
}

// CreatePublicEmailChallenge atomically persists the encrypted verification,
// delivery job, latest flow and rate reservations. Its caller authenticates the
// installation capability; the transaction rechecks the installation itself.
func (s *Store) CreatePublicEmailChallenge(ctx context.Context, input PublicEmailChallenge, verification EmailVerification, dailyLimit uint64) (PublicEmailChallenge, bool, error) {
	if !validPublicChallengeInput(input, verification) || dailyLimit == 0 || dailyLimit > 10000 {
		return PublicEmailChallenge{}, false, domain.ErrInvalid
	}
	var saved PublicEmailChallenge
	var created bool
	err := s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		saved, created = PublicEmailChallenge{}, false
		existing, err := readPublicChallenge(ctx, tx, input.ID)
		if err == nil {
			if existing.ProductID != input.ProductID || existing.InstallationID != input.InstallationID || !bytes.Equal(existing.RequestFingerprint, input.RequestFingerprint) {
				return domain.ErrConflict
			}
			saved = existing
			return nil
		}
		if !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		now := s.now().UTC().Truncate(time.Microsecond)
		if !input.ExpiresAt.After(now) || input.ExpiresAt.After(now.Add(10*time.Minute)) {
			return domain.ErrInvalid
		}
		contact := input.ProductID + ":" + hex.EncodeToString(input.EmailBlindIndex)
		if err := consumePublicAuthLimits(ctx, tx, now, input.ID, []publicAuthLimit{
			{Bucket: "otp-request:global", Window: 24 * time.Hour, Max: dailyLimit},
			{Bucket: "otp-request:product:" + input.ProductID, Window: 24 * time.Hour, Max: dailyLimit},
			{Bucket: "otp-request:contact:" + contact, Window: 15 * time.Minute, Max: 6},
			{Bucket: "otp-resend:" + contact, Window: time.Minute, Max: 1},
		}); err != nil {
			return err
		}
		var previousID string
		var sessionID *string
		var flowVersion uint64
		flow, err := tx.QueryRow(ctx, `DECLARE $product AS Utf8; DECLARE $installation AS Utf8;
SELECT challenge_id,session_id,version FROM public_registration_flows WHERE product_id=$product AND installation_id=$installation;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$product").Text(input.ProductID).Param("$installation").Text(input.InstallationID).Build()))
		if err == nil {
			if err := flow.Scan(&previousID, &sessionID, &flowVersion); err != nil {
				return err
			}
			previous, err := readPublicChallenge(ctx, tx, previousID)
			if err != nil && !errors.Is(err, domain.ErrNotFound) {
				return err
			}
			if err == nil && domain.CanTransitionPublicChallenge(previous.State, domain.PublicChallengeCancelled) {
				if err := cancelPublicChallenge(ctx, tx, previous, now); err != nil {
					return err
				}
			}
		} else if !errors.Is(err, query.ErrNoRows) {
			return err
		}
		if flowVersion == math.MaxUint64 {
			return domain.ErrConflict
		}
		if err := s.createEmailVerificationTx(ctx, tx, verification); err != nil {
			return err
		}
		if err := insertPublicChallenge(ctx, tx, input); err != nil {
			return err
		}
		if err := tx.Exec(ctx, `DECLARE $product AS Utf8; DECLARE $installation AS Utf8; DECLARE $challenge AS Utf8; DECLARE $session AS Utf8?; DECLARE $now AS Timestamp; DECLARE $version AS Uint64;
UPSERT INTO public_registration_flows(product_id,installation_id,challenge_id,session_id,updated_at,version) VALUES($product,$installation,$challenge,$session,$now,$version);`,
			query.WithParameters(ydb.ParamsBuilder().Param("$product").Text(input.ProductID).Param("$installation").Text(input.InstallationID).
				Param("$challenge").Text(input.ID).Param("$session").Any(nullableText(sessionID)).Param("$now").Timestamp(now).Param("$version").Uint64(flowVersion+1).Build())); err != nil {
			return err
		}
		if err := tx.Exec(ctx, `DECLARE $id AS Utf8; DECLARE $product AS Utf8; DECLARE $entity AS Utf8; DECLARE $now AS Timestamp;
INSERT INTO public_account_audit(id,product_id,session_id,actor,action,entity_id,created_at) VALUES($id,$product,'','installation','email.requested',$entity,$now);`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(input.ID+"-requested").Param("$product").Text(input.ProductID).Param("$entity").Text(input.ID).Param("$now").Timestamp(now).Build())); err != nil {
			return err
		}
		saved, created = input, true
		return nil
	})
	if err != nil {
		return PublicEmailChallenge{}, false, err
	}
	return saved, created, nil
}

func validPublicChallengeInput(c PublicEmailChallenge, v EmailVerification) bool {
	validCipher := func(cipher cryptokit.Ciphertext) bool {
		return len(cipher.Data) > 0 && len(cipher.Nonce) > 0 && len(cipher.WrappedDataKey) > 0 && cipher.KeyID != "" && cipher.Algorithm != ""
	}
	return domain.ValidUUID(c.ID) && domain.ValidUUID(c.InstallationID) && domain.ValidProductID(c.ProductID) &&
		c.Purpose == "product_registration" && domain.ValidHolderRole(c.HolderRole) &&
		len(c.RequestFingerprint) == 32 && len(c.NonceHash) == 32 && len(c.CodeHash) == 32 &&
		len(c.OTPKeyID) >= 1 && len(c.OTPKeyID) <= 100 && strings.TrimSpace(c.OTPKeyID) == c.OTPKeyID && strings.IndexFunc(c.OTPKeyID, unicode.IsControl) == -1 &&
		validCipher(c.Code) && validCipher(v.EncryptedEmail) && c.State == domain.PublicChallengeRequested && c.Version == 1 &&
		c.Attempts == 0 && c.MailAttempts == 0 && c.MailClaimToken == nil && c.MailClaimUntil == nil && c.VerifiedAt == nil && c.ConsumedAt == nil &&
		!c.CreatedAt.IsZero() && c.UpdatedAt.Equal(c.CreatedAt) && !c.MailAvailableAt.Before(c.CreatedAt) && c.MailAvailableAt.Before(c.ExpiresAt) && c.ExpiresAt.Equal(v.ExpiresAt) &&
		c.ID == v.ID && c.ProductID == v.ProductID && v.InstallationID != nil && c.InstallationID == *v.InstallationID &&
		v.Namespace == "account" && v.AgeCategory == "unknown" && v.GuardianRelationship == nil && !v.LinkAcrossProducts && v.VerifiedAt == nil && v.ConsumedAt == nil &&
		c.EmailBlindIndexVersion > 0 && c.EmailBlindIndexVersion == v.BlindIndexVersion && len(c.EmailBlindIndex) == 32 && bytes.Equal(c.EmailBlindIndex, v.BlindIndex)
}

func insertPublicChallenge(ctx context.Context, tx query.TxActor, c PublicEmailChallenge) error {
	return tx.Exec(ctx, `DECLARE $id AS Utf8; DECLARE $product AS Utf8; DECLARE $installation AS Utf8; DECLARE $purpose AS Utf8; DECLARE $holder AS Utf8;
DECLARE $fingerprint AS Bytes; DECLARE $nonce_hash AS Bytes; DECLARE $code_hash AS Bytes; DECLARE $otp_key AS Utf8;
DECLARE $encrypted AS Bytes; DECLARE $nonce AS Bytes; DECLARE $wrapped AS Bytes; DECLARE $key AS Utf8; DECLARE $algorithm AS Utf8;
DECLARE $index_version AS Uint64; DECLARE $index AS Bytes; DECLARE $state AS Utf8; DECLARE $available AS Timestamp;
DECLARE $created AS Timestamp; DECLARE $updated AS Timestamp; DECLARE $expires AS Timestamp;
INSERT INTO public_email_challenges (`+publicChallengeColumns+`) VALUES(
$id,$product,$installation,$purpose,$holder,$fingerprint,$nonce_hash,$code_hash,$otp_key,$encrypted,$nonce,$wrapped,$key,$algorithm,
$index_version,$index,$state,0u,0u,$available,NULL,NULL,$created,$updated,$expires,NULL,NULL,1u);`,
		query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(c.ID).Param("$product").Text(c.ProductID).Param("$installation").Text(c.InstallationID).
			Param("$purpose").Text(c.Purpose).Param("$holder").Text(c.HolderRole).Param("$fingerprint").Bytes(c.RequestFingerprint).
			Param("$nonce_hash").Bytes(c.NonceHash).Param("$code_hash").Bytes(c.CodeHash).Param("$otp_key").Text(c.OTPKeyID).
			Param("$encrypted").Bytes(c.Code.Data).Param("$nonce").Bytes(c.Code.Nonce).Param("$wrapped").Bytes(c.Code.WrappedDataKey).
			Param("$key").Text(c.Code.KeyID).Param("$algorithm").Text(c.Code.Algorithm).
			Param("$index_version").Uint64(uint64(c.EmailBlindIndexVersion)).Param("$index").Bytes(c.EmailBlindIndex).
			Param("$state").Text(string(c.State)).Param("$available").Timestamp(c.MailAvailableAt.UTC()).
			Param("$created").Timestamp(c.CreatedAt.UTC()).Param("$updated").Timestamp(c.UpdatedAt.UTC()).Param("$expires").Timestamp(c.ExpiresAt.UTC()).Build()))
}

func cancelPublicChallenge(ctx context.Context, tx query.TxActor, c PublicEmailChallenge, now time.Time) error {
	row, err := tx.QueryRow(ctx, `DECLARE $id AS Utf8; DECLARE $version AS Uint64; DECLARE $now AS Timestamp; DECLARE $empty AS Bytes;
UPDATE public_email_challenges SET state='cancelled',code_hash=$empty,encrypted_code=$empty,code_nonce=$empty,wrapped_code_key=$empty,
code_kms_key_id='',code_encryption_algorithm='',mail_claim_token=NULL,mail_claim_until=NULL,updated_at=$now,version=version+1u
WHERE id=$id AND version=$version RETURNING version;`, query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(c.ID).Param("$version").Uint64(c.Version).Param("$now").Timestamp(now).Param("$empty").Bytes([]byte{}).Build()))
	if err != nil {
		return optimistic(err)
	}
	var version uint64
	if err := row.Scan(&version); err != nil || c.Version == math.MaxUint64 || version != c.Version+1 {
		return domain.ErrConflict
	}
	return nil
}

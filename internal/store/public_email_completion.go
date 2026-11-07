package store

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"math"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

// CompletePublicEmailChallenge commits proof, registration, device session and
// consumption together. Rejected codes commit only the bounded attempt counter.
func (s *Store) CompletePublicEmailChallenge(ctx context.Context, input PublicEmailCompletion) (PublicEmailRegistration, error) {
	if !domain.ValidUUID(input.ChallengeID) || !domain.ValidUUID(input.InstallationID) || !domain.ValidProductID(input.ProductID) || len(input.NonceHash) != 32 || len(input.CodeHash) != 32 || input.OTPKeyID == "" {
		return PublicEmailRegistration{}, domain.ErrInvalid
	}
	var result PublicEmailRegistration
	var rejected bool
	err := s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		result, rejected = PublicEmailRegistration{}, false
		now := s.now().UTC().Truncate(time.Microsecond)
		c, err := readPublicChallenge(ctx, tx, input.ChallengeID)
		if err != nil {
			return err
		}
		if c.ProductID != input.ProductID || c.InstallationID != input.InstallationID || c.Purpose != "product_registration" || c.OTPKeyID != input.OTPKeyID || subtle.ConstantTimeCompare(c.NonceHash, input.NonceHash) != 1 || c.Attempts >= 5 ||
			(c.State != domain.PublicChallengeDelivering && c.State != domain.PublicChallengeDelivered && c.State != domain.PublicChallengeDeliveryUncertain) {
			return domain.ErrNotFound
		}
		flow, err := tx.QueryRow(ctx, `DECLARE $product AS Utf8; DECLARE $installation AS Utf8;
SELECT challenge_id,session_id,version FROM public_registration_flows WHERE product_id=$product AND installation_id=$installation;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$product").Text(input.ProductID).Param("$installation").Text(input.InstallationID).Build()))
		if err != nil {
			return noRows(err)
		}
		var currentID string
		var previousSession *string
		var flowVersion uint64
		if err := flow.Scan(&currentID, &previousSession, &flowVersion); err != nil {
			return err
		}
		if currentID != c.ID || flowVersion == math.MaxUint64 {
			return domain.ErrNotFound
		}
		if err := validateSubjectWith(ctx, tx, Subject{Kind: "installation", ID: input.InstallationID}, input.ProductID); err != nil {
			return err
		}
		if !now.Before(c.ExpiresAt) {
			rejected = true
			return finishPublicChallengeTx(ctx, tx, c, domain.PublicChallengeExpired, now, nil)
		}
		if subtle.ConstantTimeCompare(c.CodeHash, input.CodeHash) != 1 {
			c.Attempts++
			rejected = true
			if c.Attempts == 5 {
				return finishPublicChallengeTx(ctx, tx, c, domain.PublicChallengeLocked, now, nil)
			}
			row, err := tx.QueryRow(ctx, `DECLARE $id AS Utf8; DECLARE $version AS Uint64; DECLARE $attempts AS Uint64; DECLARE $now AS Timestamp;
UPDATE public_email_challenges SET attempts=$attempts,updated_at=$now,version=version+1u WHERE id=$id AND version=$version RETURNING version;`,
				query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(c.ID).Param("$version").Uint64(c.Version).Param("$attempts").Uint64(c.Attempts).Param("$now").Timestamp(now).Build()))
			return checkPublicVersion(row, err, c.Version)
		}
		identity := input.Identity
		if !domain.ValidUUID(input.SessionID) || len(input.RefreshHash) != 32 || !input.RefreshExpiresAt.After(now) || input.RefreshExpiresAt.After(now.Add(90*24*time.Hour)) ||
			!domain.ValidUUID(identity.ID) || !domain.ValidUUID(identity.PersonID) || !domain.ValidUUID(identity.AccountID) || !identity.CreateAccount || identity.VerifiedAt.IsZero() || identity.VerifiedAt.Before(c.CreatedAt) || identity.VerifiedAt.After(now) {
			return domain.ErrInvalid
		}
		verification, err := readEmailVerification(ctx, tx, c.ID)
		if err != nil {
			return err
		}
		if verification.Namespace != "account" || verification.AgeCategory != "unknown" || verification.GuardianRelationship != nil || verification.LinkAcrossProducts ||
			!now.Before(verification.ExpiresAt) || verification.BlindIndexVersion != c.EmailBlindIndexVersion || !bytes.Equal(verification.BlindIndex, c.EmailBlindIndex) || verification.Version == math.MaxUint64 {
			return domain.ErrNotFound
		}
		verification.VerifiedAt = &identity.VerifiedAt
		if !verifiedEmailIdentityMatches(verification, identity, input.Indexes) {
			return domain.ErrNotFound
		}
		row, err := tx.QueryRow(ctx, `DECLARE $id AS Utf8; DECLARE $version AS Uint64; DECLARE $verified AS Timestamp; DECLARE $claim AS Utf8; DECLARE $now AS Timestamp;
UPDATE email_verifications SET verified_at=$verified,verified_by='public-email-otp',evidence_id=$id,processing_token=$claim,processing_at=$now,version=version+1u
WHERE id=$id AND version=$version RETURNING version;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(c.ID).Param("$version").Uint64(verification.Version).Param("$verified").Timestamp(identity.VerifiedAt).Param("$claim").Text(input.SessionID).Param("$now").Timestamp(now).Build()))
		if err := checkPublicVersion(row, err, verification.Version); err != nil {
			return err
		}
		registered, _, err := s.registerEmailIdentityTx(ctx, tx, identity, input.Indexes)
		if err != nil {
			return err
		}
		row, err = tx.QueryRow(ctx, `DECLARE $account AS Utf8; DECLARE $person AS Utf8;
SELECT a.status,p.deleted_at FROM accounts AS a INNER JOIN persons AS p ON a.person_id=p.id WHERE a.id=$account AND a.person_id=$person;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$account").Text(registered.AccountID).Param("$person").Text(registered.PersonID).Build()))
		if err != nil {
			return noRows(err)
		}
		var accountState string
		var deletedAt *time.Time
		if err := row.Scan(&accountState, &deletedAt); err != nil {
			return err
		}
		if accountState != "active" || deletedAt != nil {
			return domain.ErrNotFound
		}
		if pending, err := publicAccountDeletionPending(ctx, tx, registered.PersonID, c.InstallationID, c.ProductID); err != nil {
			return err
		} else if pending {
			return domain.ErrNotFound
		}
		profile, err := registerPublicProductAccount(ctx, tx, c, registered, identity.VerifiedAt, now)
		if err != nil {
			return err
		}
		if previousSession != nil {
			previous, err := readAccountSession(ctx, tx, *previousSession)
			if err != nil && !errors.Is(err, domain.ErrNotFound) {
				return err
			}
			if err == nil {
				if previous.ProductID != c.ProductID || previous.InstallationID != c.InstallationID || previous.AccountID != registered.AccountID || previous.ID == input.SessionID {
					return domain.ErrConflict
				}
				if err := revokeAccountSessionTx(ctx, tx, previous, now, "installation", "reauthentication"); err != nil {
					return err
				}
			}
		}
		session := AccountSession{ID: input.SessionID, ProductID: c.ProductID, AccountID: registered.AccountID, InstallationID: c.InstallationID, State: domain.PublicSessionActive, CreatedAt: now, ExpiresAt: input.RefreshExpiresAt.UTC(), Version: 1}
		if err := insertAccountSession(ctx, tx, session); err != nil {
			return err
		}
		if err := insertAccountRefresh(ctx, tx, AccountRefresh{Hash: input.RefreshHash, SessionID: session.ID, IssuedAt: now, ExpiresAt: session.ExpiresAt, Version: 1}); err != nil {
			return err
		}
		row, err = tx.QueryRow(ctx, `DECLARE $product AS Utf8; DECLARE $installation AS Utf8; DECLARE $session AS Utf8; DECLARE $now AS Timestamp; DECLARE $version AS Uint64;
UPDATE public_registration_flows SET session_id=$session,updated_at=$now,version=version+1u WHERE product_id=$product AND installation_id=$installation AND version=$version RETURNING version;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$product").Text(c.ProductID).Param("$installation").Text(c.InstallationID).Param("$session").Text(session.ID).Param("$now").Timestamp(now).Param("$version").Uint64(flowVersion).Build()))
		if err := checkPublicVersion(row, err, flowVersion); err != nil {
			return err
		}
		if err := consumeEmailVerificationTx(ctx, tx, c.ID, input.SessionID, registered.PersonID, now); err != nil {
			return err
		}
		if err := finishPublicChallengeTx(ctx, tx, c, domain.PublicChallengeConsumed, now, &identity.VerifiedAt); err != nil {
			return err
		}
		if err := appendPublicAccountAudit(ctx, tx, session.ID+"-registered", c.ProductID, session.ID, "installation", "registration.verified", registered.AccountID, now); err != nil {
			return err
		}
		result = PublicEmailRegistration{Identity: registered, Account: profile, Session: session}
		return nil
	})
	if err != nil {
		return PublicEmailRegistration{}, err
	}
	if rejected {
		return PublicEmailRegistration{}, domain.ErrNotFound
	}
	return result, nil
}

func checkPublicVersion(row query.Row, err error, previous uint64) error {
	if err != nil {
		return optimistic(err)
	}
	var next uint64
	if err := row.Scan(&next); err != nil {
		return err
	}
	if previous == math.MaxUint64 || next != previous+1 {
		return domain.ErrConflict
	}
	return nil
}

func finishPublicChallengeTx(ctx context.Context, tx query.TxActor, c PublicEmailChallenge, state domain.PublicChallengeState, now time.Time, verifiedAt *time.Time) error {
	allowed := domain.CanTransitionPublicChallenge(c.State, state)
	var consumedAt *time.Time
	if state == domain.PublicChallengeConsumed {
		allowed = domain.CanTransitionPublicChallenge(c.State, domain.PublicChallengeVerified) && domain.CanTransitionPublicChallenge(domain.PublicChallengeVerified, state) && verifiedAt != nil
		consumedAt = &now
	}
	if !allowed || c.Version == math.MaxUint64 {
		return domain.ErrConflict
	}
	row, err := tx.QueryRow(ctx, `DECLARE $id AS Utf8; DECLARE $version AS Uint64; DECLARE $state AS Utf8; DECLARE $attempts AS Uint64; DECLARE $now AS Timestamp; DECLARE $verified AS Timestamp?; DECLARE $consumed AS Timestamp?; DECLARE $empty AS Bytes;
UPDATE public_email_challenges SET state=$state,attempts=$attempts,code_hash=$empty,encrypted_code=$empty,code_nonce=$empty,wrapped_code_key=$empty,
code_kms_key_id='',code_encryption_algorithm='',mail_claim_token=NULL,mail_claim_until=NULL,verified_at=$verified,consumed_at=$consumed,updated_at=$now,version=version+1u
WHERE id=$id AND version=$version RETURNING version;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(c.ID).Param("$version").Uint64(c.Version).Param("$state").Text(string(state)).Param("$attempts").Uint64(c.Attempts).
			Param("$now").Timestamp(now).Param("$verified").Any(nullableTimestamp(verifiedAt)).Param("$consumed").Any(nullableTimestamp(consumedAt)).Param("$empty").Bytes([]byte{}).Build()))
	return checkPublicVersion(row, err, c.Version)
}

func registerPublicProductAccount(ctx context.Context, tx query.TxActor, c PublicEmailChallenge, identity EmailIdentity, verifiedAt, now time.Time) (ProductAccount, error) {
	profile, err := readProductAccount(ctx, tx, c.ProductID, identity.AccountID)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return ProductAccount{}, err
	}
	if errors.Is(err, domain.ErrNotFound) {
		profile = ProductAccount{ProductID: c.ProductID, AccountID: identity.AccountID, EmailIdentityID: identity.IdentityID, HolderRole: c.HolderRole, Status: "active", VerifiedAt: verifiedAt, CreatedAt: now, UpdatedAt: now, Version: 1}
	} else {
		if profile.Status != "active" || profile.EmailIdentityID != identity.IdentityID || profile.Version == math.MaxUint64 {
			return ProductAccount{}, domain.ErrNotFound
		}
		profile.HolderRole, profile.VerifiedAt, profile.UpdatedAt = c.HolderRole, verifiedAt, now
		profile.Version++
	}
	if err := tx.Exec(ctx, `DECLARE $product AS Utf8; DECLARE $account AS Utf8; DECLARE $identity AS Utf8; DECLARE $holder AS Utf8; DECLARE $country AS Utf8; DECLARE $region AS Utf8;
DECLARE $status AS Utf8; DECLARE $verified AS Timestamp; DECLARE $created AS Timestamp; DECLARE $updated AS Timestamp; DECLARE $version AS Uint64;
UPSERT INTO product_accounts(product_id,account_id,email_identity_id,holder_role,country,region,status,verified_at,created_at,updated_at,version)
VALUES($product,$account,$identity,$holder,$country,$region,$status,$verified,$created,$updated,$version);`,
		query.WithParameters(ydb.ParamsBuilder().Param("$product").Text(profile.ProductID).Param("$account").Text(profile.AccountID).Param("$identity").Text(profile.EmailIdentityID).
			Param("$holder").Text(profile.HolderRole).Param("$country").Text(profile.Country).Param("$region").Text(profile.Region).Param("$status").Text(profile.Status).
			Param("$verified").Timestamp(profile.VerifiedAt).Param("$created").Timestamp(profile.CreatedAt).Param("$updated").Timestamp(profile.UpdatedAt).Param("$version").Uint64(profile.Version).Build())); err != nil {
		return ProductAccount{}, err
	}
	return profile, nil
}

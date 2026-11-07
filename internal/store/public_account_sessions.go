package store

import (
	"bytes"
	"context"
	"encoding/hex"
	"math"
	"strconv"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

const accountSessionColumns = `id,product_id,account_id,installation_id,status,created_at,expires_at,revoked_at,version`
const productAccountColumns = `product_id,account_id,email_identity_id,holder_role,country,region,status,verified_at,created_at,updated_at,version`

func readAccountSession(ctx context.Context, executor query.Executor, id string) (s AccountSession, err error) {
	row, err := executor.QueryRow(ctx, `DECLARE $id AS Utf8; SELECT `+accountSessionColumns+` FROM account_sessions WHERE id=$id;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(id).Build()))
	if err != nil {
		return s, noRows(err)
	}
	var state string
	err = row.Scan(&s.ID, &s.ProductID, &s.AccountID, &s.InstallationID, &state, &s.CreatedAt, &s.ExpiresAt, &s.RevokedAt, &s.Version)
	s.State = domain.PublicSessionState(state)
	return s, err
}

func readProductAccount(ctx context.Context, executor query.Executor, product, account string) (p ProductAccount, err error) {
	row, err := executor.QueryRow(ctx, `DECLARE $product AS Utf8; DECLARE $account AS Utf8;
SELECT `+productAccountColumns+` FROM product_accounts WHERE product_id=$product AND account_id=$account;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$product").Text(product).Param("$account").Text(account).Build()))
	if err != nil {
		return p, noRows(err)
	}
	err = row.Scan(&p.ProductID, &p.AccountID, &p.EmailIdentityID, &p.HolderRole, &p.Country, &p.Region, &p.Status, &p.VerifiedAt, &p.CreatedAt, &p.UpdatedAt, &p.Version)
	return p, err
}

func insertAccountSession(ctx context.Context, tx query.TxActor, s AccountSession) error {
	if !domain.ValidUUID(s.ID) || !domain.ValidProductID(s.ProductID) || !domain.ValidUUID(s.AccountID) || !domain.ValidUUID(s.InstallationID) ||
		s.State != domain.PublicSessionActive || s.RevokedAt != nil || s.Version != 1 || s.CreatedAt.IsZero() || !s.ExpiresAt.After(s.CreatedAt) {
		return domain.ErrInvalid
	}
	return tx.Exec(ctx, `DECLARE $id AS Utf8; DECLARE $product AS Utf8; DECLARE $account AS Utf8; DECLARE $installation AS Utf8;
DECLARE $created AS Timestamp; DECLARE $expires AS Timestamp;
INSERT INTO account_sessions (`+accountSessionColumns+`) VALUES($id,$product,$account,$installation,'active',$created,$expires,NULL,1u);`,
		query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(s.ID).Param("$product").Text(s.ProductID).Param("$account").Text(s.AccountID).
			Param("$installation").Text(s.InstallationID).Param("$created").Timestamp(s.CreatedAt.UTC()).Param("$expires").Timestamp(s.ExpiresAt.UTC()).Build()))
}

func insertAccountRefresh(ctx context.Context, tx query.TxActor, r AccountRefresh) error {
	if len(r.Hash) != 32 || !domain.ValidUUID(r.SessionID) || r.Version != 1 || r.ConsumedAt != nil || r.IssuedAt.IsZero() || !r.ExpiresAt.After(r.IssuedAt) {
		return domain.ErrInvalid
	}
	return tx.Exec(ctx, `DECLARE $hash AS Bytes; DECLARE $session AS Utf8; DECLARE $issued AS Timestamp; DECLARE $expires AS Timestamp;
INSERT INTO account_refresh_tokens(token_hash,session_id,issued_at,expires_at,consumed_at,version) VALUES($hash,$session,$issued,$expires,NULL,1u);`,
		query.WithParameters(ydb.ParamsBuilder().Param("$hash").Bytes(r.Hash).Param("$session").Text(r.SessionID).
			Param("$issued").Timestamp(r.IssuedAt.UTC()).Param("$expires").Timestamp(r.ExpiresAt.UTC()).Build()))
}

func appendPublicAccountAudit(ctx context.Context, tx query.TxActor, id, product, session, actor, action, entity string, now time.Time) error {
	return tx.Exec(ctx, `DECLARE $id AS Utf8; DECLARE $product AS Utf8; DECLARE $session AS Utf8; DECLARE $actor AS Utf8;
DECLARE $action AS Utf8; DECLARE $entity AS Utf8; DECLARE $now AS Timestamp;
INSERT INTO public_account_audit(id,product_id,session_id,actor,action,entity_id,created_at) VALUES($id,$product,$session,$actor,$action,$entity,$now);`,
		query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(id).Param("$product").Text(product).Param("$session").Text(session).
			Param("$actor").Text(actor).Param("$action").Text(action).Param("$entity").Text(entity).Param("$now").Timestamp(now.UTC()).Build()))
}

func revokeAccountSessionTx(ctx context.Context, tx query.TxActor, s AccountSession, now time.Time, actor, reason string) error {
	switch reason {
	case "reauthentication", "self", "refresh_replay", "privacy_deletion":
	default:
		return domain.ErrInvalid
	}
	if s.State != domain.PublicSessionActive {
		return nil
	}
	if s.Version == math.MaxUint64 {
		return domain.ErrConflict
	}
	row, err := tx.QueryRow(ctx, `DECLARE $id AS Utf8; DECLARE $version AS Uint64; DECLARE $now AS Timestamp;
UPDATE account_sessions SET status='revoked',revoked_at=$now,version=version+1u WHERE id=$id AND version=$version RETURNING version;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(s.ID).Param("$version").Uint64(s.Version).Param("$now").Timestamp(now.UTC()).Build()))
	if err := checkPublicVersion(row, err, s.Version); err != nil {
		return err
	}
	return appendPublicAccountAudit(ctx, tx, "revoke-"+s.ID+"-"+strconv.FormatUint(s.Version, 10), s.ProductID, s.ID, actor, "session.revoked."+reason, s.ID, now)
}

// All authority is read in the same serializable transaction as its mutation.
func authorizedPublicAccountSession(ctx context.Context, tx query.TxActor, id, product string, now time.Time) (AccountSession, ProductAccount, error) {
	s, err := readAccountSession(ctx, tx, id)
	if err != nil {
		return AccountSession{}, ProductAccount{}, err
	}
	if s.ProductID != product || !domain.ValidPublicSession(now, s.ExpiresAt, s.State) || s.RevokedAt != nil {
		return AccountSession{}, ProductAccount{}, domain.ErrNotFound
	}
	row, err := tx.QueryRow(ctx, `DECLARE $account AS Utf8;
SELECT a.person_id FROM accounts AS a INNER JOIN persons AS p ON p.id=a.person_id
WHERE a.id=$account AND a.status='active' AND p.deleted_at IS NULL;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$account").Text(s.AccountID).Build()))
	if err != nil {
		return AccountSession{}, ProductAccount{}, noRows(err)
	}
	var person string
	if err := row.Scan(&person); err != nil {
		return AccountSession{}, ProductAccount{}, err
	}
	if pending, err := publicAccountDeletionPending(ctx, tx, person, s.InstallationID, product); err != nil {
		return AccountSession{}, ProductAccount{}, err
	} else if pending {
		return AccountSession{}, ProductAccount{}, domain.ErrNotFound
	}
	p, err := readProductAccount(ctx, tx, product, s.AccountID)
	if err != nil {
		return AccountSession{}, ProductAccount{}, err
	}
	if p.Status != "active" || p.VerifiedAt.Unix() <= 0 {
		return AccountSession{}, ProductAccount{}, domain.ErrNotFound
	}
	row, err = tx.QueryRow(ctx, `DECLARE $person AS Utf8; DECLARE $email AS Utf8; DECLARE $product AS Utf8; DECLARE $installation AS Utf8; DECLARE $session AS Utf8;
SELECT e.verified_at FROM email_identities AS e
INNER JOIN product_installations AS i ON i.person_id=e.person_id
INNER JOIN public_registration_flows AS f ON f.product_id=i.product_id AND f.installation_id=i.id
WHERE e.person_id=$person AND e.id=$email AND e.identity_namespace='account' AND e.linkage_scope='product' AND e.product_id=$product AND e.scope_key=$product
AND i.id=$installation AND i.product_id=$product AND i.disabled_at IS NULL AND f.session_id=$session;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$person").Text(person).Param("$email").Text(p.EmailIdentityID).
			Param("$product").Text(product).Param("$installation").Text(s.InstallationID).Param("$session").Text(s.ID).Build()))
	if err != nil {
		return AccountSession{}, ProductAccount{}, noRows(err)
	}
	var verified time.Time
	if err := row.Scan(&verified); err != nil {
		return AccountSession{}, ProductAccount{}, err
	}
	if verified.Unix() <= 0 {
		return AccountSession{}, ProductAccount{}, domain.ErrNotFound
	}
	return s, p, nil
}

func (s *Store) AuthorizedPublicAccountSession(ctx context.Context, id, product string) (AccountSession, ProductAccount, error) {
	if !domain.ValidUUID(id) || !domain.ValidProductID(product) {
		return AccountSession{}, ProductAccount{}, domain.ErrInvalid
	}
	var session AccountSession
	var profile ProductAccount
	err := s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		session, profile = AccountSession{}, ProductAccount{}
		var err error
		session, profile, err = authorizedPublicAccountSession(ctx, tx, id, product, s.now().UTC())
		return err
	})
	if err != nil {
		return AccountSession{}, ProductAccount{}, err
	}
	return session, profile, nil
}

func (s *Store) RotatePublicAccountRefresh(ctx context.Context, oldHash, newHash []byte) (AccountSession, ProductAccount, error) {
	if len(oldHash) != 32 || len(newHash) != 32 || bytes.Equal(oldHash, newHash) {
		return AccountSession{}, ProductAccount{}, domain.ErrInvalid
	}
	var session AccountSession
	var profile ProductAccount
	var replay bool
	err := s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		session, profile, replay = AccountSession{}, ProductAccount{}, false
		now := s.now().UTC()
		row, err := tx.QueryRow(ctx, `DECLARE $hash AS Bytes; SELECT session_id,issued_at,expires_at,consumed_at,version FROM account_refresh_tokens WHERE token_hash=$hash;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$hash").Bytes(oldHash).Build()))
		if err != nil {
			return noRows(err)
		}
		var r AccountRefresh
		if err := row.Scan(&r.SessionID, &r.IssuedAt, &r.ExpiresAt, &r.ConsumedAt, &r.Version); err != nil {
			return err
		}
		// Expired capabilities cannot mutate a family, even if previously used.
		if !now.Before(r.ExpiresAt) {
			return domain.ErrNotFound
		}
		stored, err := readAccountSession(ctx, tx, r.SessionID)
		if err != nil {
			return err
		}
		if r.ConsumedAt != nil {
			replay = true
			return revokeAccountSessionTx(ctx, tx, stored, now, "backend", "refresh_replay")
		}
		session, profile, err = authorizedPublicAccountSession(ctx, tx, stored.ID, stored.ProductID, now)
		if err != nil {
			return err
		}
		if r.Version == math.MaxUint64 || session.Version == math.MaxUint64 {
			return domain.ErrConflict
		}
		row, err = tx.QueryRow(ctx, `DECLARE $hash AS Bytes; DECLARE $version AS Uint64; DECLARE $now AS Timestamp;
UPDATE account_refresh_tokens SET consumed_at=$now,version=version+1u WHERE token_hash=$hash AND version=$version AND consumed_at IS NULL RETURNING version;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$hash").Bytes(oldHash).Param("$version").Uint64(r.Version).Param("$now").Timestamp(now).Build()))
		if err := checkPublicVersion(row, err, r.Version); err != nil {
			return err
		}
		if err := insertAccountRefresh(ctx, tx, AccountRefresh{Hash: newHash, SessionID: session.ID, IssuedAt: now, ExpiresAt: session.ExpiresAt, Version: 1}); err != nil {
			return err
		}
		row, err = tx.QueryRow(ctx, `DECLARE $id AS Utf8; DECLARE $version AS Uint64;
UPDATE account_sessions SET version=version+1u WHERE id=$id AND version=$version RETURNING version;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(session.ID).Param("$version").Uint64(session.Version).Build()))
		if err := checkPublicVersion(row, err, session.Version); err != nil {
			return err
		}
		session.Version++
		return appendPublicAccountAudit(ctx, tx, "refresh-"+hex.EncodeToString(newHash), session.ProductID, session.ID, "backend", "session.refreshed", session.ID, now)
	})
	if err != nil {
		return AccountSession{}, ProductAccount{}, err
	}
	if replay {
		return AccountSession{}, ProductAccount{}, domain.ErrNotFound
	}
	return session, profile, nil
}

func (s *Store) RevokePublicAccountSession(ctx context.Context, id, product string) error {
	if !domain.ValidUUID(id) || !domain.ValidProductID(product) {
		return domain.ErrInvalid
	}
	return s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		now := s.now().UTC()
		session, err := readAccountSession(ctx, tx, id)
		if err != nil {
			return err
		}
		if session.ProductID != product {
			return domain.ErrNotFound
		}
		return revokeAccountSessionTx(ctx, tx, session, now, "backend", "self")
	})
}

func (s *Store) UpdatePublicAccountProfile(ctx context.Context, id, product string, expectedVersion uint64, holder, country, region string) (ProductAccount, error) {
	if !domain.ValidUUID(id) || !domain.ValidProductID(product) || expectedVersion == math.MaxUint64 || !domain.ValidHolderRole(holder) {
		return ProductAccount{}, domain.ErrInvalid
	}
	country, region, err := domain.NormalizeDeclaredRegion(country, region)
	if err != nil {
		return ProductAccount{}, err
	}
	var profile ProductAccount
	err = s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		profile = ProductAccount{}
		now := s.now().UTC().Truncate(time.Microsecond)
		_, p, err := authorizedPublicAccountSession(ctx, tx, id, product, now)
		if err != nil {
			return err
		}
		if p.Version != expectedVersion {
			return domain.ErrConflict
		}
		row, err := tx.QueryRow(ctx, `DECLARE $product AS Utf8; DECLARE $account AS Utf8; DECLARE $version AS Uint64;
DECLARE $holder AS Utf8; DECLARE $country AS Utf8; DECLARE $region AS Utf8; DECLARE $now AS Timestamp;
UPDATE product_accounts SET holder_role=$holder,country=$country,region=$region,updated_at=$now,version=version+1u
WHERE product_id=$product AND account_id=$account AND version=$version RETURNING version;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$product").Text(product).Param("$account").Text(p.AccountID).Param("$version").Uint64(expectedVersion).
				Param("$holder").Text(holder).Param("$country").Text(country).Param("$region").Text(region).Param("$now").Timestamp(now).Build()))
		if err := checkPublicVersion(row, err, expectedVersion); err != nil {
			return err
		}
		p.HolderRole, p.Country, p.Region, p.UpdatedAt, p.Version = holder, country, region, now, p.Version+1
		profile = p
		return appendPublicAccountAudit(ctx, tx, "profile-"+product+"-"+p.AccountID+"-"+strconv.FormatUint(p.Version, 10), product, id, "backend", "profile.updated", p.AccountID, now)
	})
	if err != nil {
		return ProductAccount{}, err
	}
	return profile, nil
}

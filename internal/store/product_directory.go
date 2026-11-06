package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

const directoryAccountSelect = `SELECT pa.product_id,pa.account_id,pa.email_identity_id,pa.holder_role,pa.country,pa.region,pa.status,
pa.verified_at,pa.created_at,pa.updated_at,pa.version,a.person_id,e.identity_namespace,e.linkage_scope,e.scope_key,
e.encryption_algorithm,e.key_id,e.wrapped_data_key,e.email_nonce,e.encrypted_email
FROM product_accounts AS pa
INNER JOIN accounts AS a ON pa.account_id=a.id
INNER JOIN persons AS p ON a.person_id=p.id
INNER JOIN email_identities AS e ON pa.email_identity_id=e.id
WHERE pa.product_id=$product AND pa.status='active' AND a.status='active' AND p.deleted_at IS NULL
AND e.person_id=a.person_id AND e.product_id=$product AND e.identity_namespace='account'
AND e.linkage_scope='product' AND e.scope_key=$product
AND pa.verified_at>CAST(0 AS Timestamp) AND e.verified_at>CAST(0 AS Timestamp)`

// DirectoryAccounts returns private pagination candidates, NOT disclosure authority.
// Pending deletion is intentionally not filtered here: callers advance using the
// last candidate's root account ID and must call DirectoryAccount before decrypting.
func (s *Store) DirectoryAccounts(ctx context.Context, product, afterAccount string, limit uint64) ([]DirectoryAccount, error) {
	if !domain.ValidProductID(product) || (afterAccount != "" && !domain.ValidUUID(afterAccount)) || limit < 1 || limit > 50 {
		return nil, domain.ErrInvalid
	}
	var result []DirectoryAccount
	err := s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		result = nil
		rows, err := tx.QueryResultSet(ctx, `DECLARE $product AS Utf8; DECLARE $after AS Utf8; DECLARE $limit AS Uint64;
`+directoryAccountSelect+` AND pa.account_id>$after ORDER BY pa.account_id ASC LIMIT $limit;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$product").Text(product).Param("$after").Text(afterAccount).Param("$limit").Uint64(limit).Build()))
		if err != nil {
			return err
		}
		defer rows.Close(ctx)
		for row, err := range rows.Rows(ctx) {
			if err != nil {
				return err
			}
			account, err := scanDirectoryAccount(row)
			if err != nil {
				return err
			}
			result = append(result, account)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// DirectoryAccount authoritatively checks contact eligibility and reads account-
// scoped communication permissions in the same serializable transaction.
func (s *Store) DirectoryAccount(ctx context.Context, product, account string) (DirectoryAccount, error) {
	if !domain.ValidProductID(product) || !domain.ValidUUID(account) {
		return DirectoryAccount{}, domain.ErrInvalid
	}
	var result DirectoryAccount
	err := s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		result = DirectoryAccount{}
		row, err := tx.QueryRow(ctx, `DECLARE $product AS Utf8; DECLARE $account AS Utf8;
`+directoryAccountSelect+` AND pa.account_id=$account;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$product").Text(product).Param("$account").Text(account).Build()))
		if err != nil {
			return noRows(err)
		}
		result, err = scanDirectoryAccount(row)
		if err != nil {
			return err
		}
		pending, err := publicAccountDeletionPending(ctx, tx, result.PersonID, "", product)
		if err != nil {
			return err
		}
		if pending {
			return domain.ErrNotFound
		}
		return enrichDirectoryAccount(ctx, tx, &result)
	})
	if err != nil {
		return DirectoryAccount{}, err
	}
	return result, nil
}

func scanDirectoryAccount(row query.Row) (DirectoryAccount, error) {
	var a DirectoryAccount
	p := &a.Profile
	err := row.Scan(&p.ProductID, &p.AccountID, &p.EmailIdentityID, &p.HolderRole, &p.Country, &p.Region, &p.Status,
		&p.VerifiedAt, &p.CreatedAt, &p.UpdatedAt, &p.Version, &a.PersonID, &a.Namespace, &a.LinkageScope, &a.ScopeKey,
		&a.Email.Algorithm, &a.Email.KeyID, &a.Email.WrappedDataKey, &a.Email.Nonce, &a.Email.Data)
	if err != nil {
		return DirectoryAccount{}, err
	}
	if !domain.ValidUUID(p.AccountID) || !domain.ValidUUID(p.EmailIdentityID) || !domain.ValidUUID(a.PersonID) {
		return DirectoryAccount{}, domain.ErrNotFound
	}
	return a, nil
}

func enrichDirectoryAccount(ctx context.Context, tx query.TxActor, account *DirectoryAccount) error {
	params := ydb.ParamsBuilder().Param("$product").Text(account.Profile.ProductID).Param("$account").Text(account.Profile.AccountID).Build()
	account.TelemetryPreference = "unknown"
	row, err := tx.QueryRow(ctx, `DECLARE $product AS Utf8; DECLARE $account AS Utf8;
SELECT preference FROM telemetry_preferences WHERE subject_type='account' AND subject_id=$account AND product_id=$product;`, query.WithParameters(params))
	if err == nil {
		var preference string
		if err := row.Scan(&preference); err != nil {
			return err
		}
		if preference == "allowed" || preference == "denied" {
			account.TelemetryPreference = preference
		}
	} else if !errors.Is(err, query.ErrNoRows) {
		return err
	}
	account.Permissions = make(map[string]DirectoryPermission, 3)
	for _, kind := range []string{"news", "research", "service"} {
		permission := DirectoryPermission{Status: "unknown"}
		row, err := tx.QueryRow(ctx, `DECLARE $product AS Utf8; DECLARE $account AS Utf8; DECLARE $kind AS Utf8;
SELECT id,policy_version,status,recorded_at,created_at FROM consents
WHERE subject_type='account' AND subject_id=$account AND product_id=$product AND consent_type=$kind
ORDER BY recorded_at DESC,created_at DESC,id DESC LIMIT 1;`, query.WithParameters(ydb.ParamsBuilder().
			Param("$product").Text(account.Profile.ProductID).Param("$account").Text(account.Profile.AccountID).Param("$kind").Text("product_"+kind).Build()))
		if err == nil {
			var createdAt time.Time
			if err := row.Scan(&permission.ID, &permission.PolicyVersion, &permission.Status, &permission.RecordedAt, &createdAt); err != nil {
				return err
			}
			permission = validDirectoryPermission(permission, createdAt)
		} else if !errors.Is(err, query.ErrNoRows) {
			return err
		}
		account.Permissions[kind] = permission
	}
	return nil
}

func validDirectoryPermission(p DirectoryPermission, createdAt time.Time) DirectoryPermission {
	if !domain.ValidUUID(p.ID) || strings.TrimSpace(p.PolicyVersion) == "" || !p.RecordedAt.After(time.Unix(0, 0)) || !createdAt.After(time.Unix(0, 0)) ||
		(p.Status != "granted" && p.Status != "withdrawn") {
		return DirectoryPermission{Status: "unknown"}
	}
	return p
}

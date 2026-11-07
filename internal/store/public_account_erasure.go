package store

import (
	"context"
	"time"

	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

// public_auth_events deliberately survive erasure: opaque HMAC rate budgets
// expire after 48 hours, so deleting an installation cannot reset contact limits.
func erasePublicInstallationState(ctx context.Context, tx query.TxActor, installation string, product *string, _ time.Time) error {
	parameters := publicErasureScope(product, "$installation", installation)
	challenges, err := publicErasureIDs(ctx, tx, `DECLARE $all AS Bool; DECLARE $product AS Utf8; DECLARE $installation AS Utf8;
SELECT id,product_id,installation_id FROM public_email_challenges WHERE installation_id=$installation AND ($all OR product_id=$product);`, parameters)
	if err != nil {
		return err
	}
	for _, challenge := range challenges {
		if err := erasePublicChallenge(ctx, tx, challenge); err != nil {
			return err
		}
	}
	sessions, err := publicErasureIDs(ctx, tx, `DECLARE $all AS Bool; DECLARE $product AS Utf8; DECLARE $installation AS Utf8;
SELECT id,product_id,installation_id FROM account_sessions VIEW account_sessions_installation WHERE installation_id=$installation AND ($all OR product_id=$product);`, parameters)
	if err != nil {
		return err
	}
	for _, session := range sessions {
		if err := erasePublicSession(ctx, tx, session); err != nil {
			return err
		}
	}
	return tx.Exec(ctx, `DECLARE $all AS Bool; DECLARE $product AS Utf8; DECLARE $installation AS Utf8;
DELETE FROM public_registration_flows WHERE installation_id=$installation AND ($all OR product_id=$product);`, query.WithParameters(parameters))
}

func erasePublicPersonState(ctx context.Context, tx query.TxActor, person string, product *string, _ time.Time) error {
	identities, err := identityIDsForPerson(ctx, tx, person, product)
	if err != nil {
		return err
	}
	for _, identity := range identities {
		rows, err := tx.QueryResultSet(ctx, `DECLARE $identity AS Utf8; DECLARE $all AS Bool; DECLARE $product AS Utf8;
SELECT scope_key,blind_index_version,email_blind_index FROM email_blind_indexes
WHERE identity_id=$identity AND identity_namespace='account' AND linkage_scope='product' AND ($all OR scope_key=$product);`,
			query.WithParameters(publicErasureScope(product, "$identity", identity)))
		if err != nil {
			return err
		}
		// Collect keys before issuing writes on the same transaction.
		type emailKey struct {
			product string
			version uint64
			hash    []byte
		}
		var keys []emailKey
		for row, rowErr := range rows.Rows(ctx) {
			if rowErr != nil {
				rows.Close(ctx)
				return rowErr
			}
			var key emailKey
			if err := row.Scan(&key.product, &key.version, &key.hash); err != nil {
				rows.Close(ctx)
				return err
			}
			keys = append(keys, key)
		}
		if err := rows.Close(ctx); err != nil {
			return err
		}
		for _, key := range keys {
			challenges, err := publicErasureIDs(ctx, tx, `DECLARE $product AS Utf8; DECLARE $version AS Uint64; DECLARE $hash AS Bytes;
SELECT id,product_id,installation_id FROM public_email_challenges VIEW public_email_identity
WHERE product_id=$product AND email_blind_index_version=$version AND email_blind_index=$hash;`,
				ydb.ParamsBuilder().Param("$product").Text(key.product).Param("$version").Uint64(key.version).Param("$hash").Bytes(key.hash).Build())
			if err != nil {
				return err
			}
			for _, challenge := range challenges {
				if err := erasePublicChallenge(ctx, tx, challenge); err != nil {
					return err
				}
			}
		}
	}
	accounts, err := tx.QueryResultSet(ctx, `DECLARE $person AS Utf8; SELECT id FROM accounts WHERE person_id=$person;`, query.WithParameters(ydb.ParamsBuilder().Param("$person").Text(person).Build()))
	if err != nil {
		return err
	}
	var accountIDs []string
	for row, rowErr := range accounts.Rows(ctx) {
		if rowErr != nil {
			accounts.Close(ctx)
			return rowErr
		}
		var account string
		if err := row.Scan(&account); err != nil {
			accounts.Close(ctx)
			return err
		}
		accountIDs = append(accountIDs, account)
	}
	if err := accounts.Close(ctx); err != nil {
		return err
	}
	for _, account := range accountIDs {
		parameters := publicErasureScope(product, "$account", account)
		sessions, err := publicErasureIDs(ctx, tx, `DECLARE $all AS Bool; DECLARE $product AS Utf8; DECLARE $account AS Utf8;
SELECT id,product_id,installation_id FROM account_sessions VIEW account_sessions_account WHERE account_id=$account AND ($all OR product_id=$product);`, parameters)
		if err != nil {
			return err
		}
		for _, session := range sessions {
			if err := erasePublicSession(ctx, tx, session); err != nil {
				return err
			}
		}
		if err := tx.Exec(ctx, `DECLARE $all AS Bool; DECLARE $product AS Utf8; DECLARE $account AS Utf8;
DELETE FROM public_account_audit WHERE entity_id=$account AND ($all OR product_id=$product);
DELETE FROM product_accounts WHERE account_id=$account AND ($all OR product_id=$product);`, query.WithParameters(parameters)); err != nil {
			return err
		}
	}
	return nil
}

type publicErasureID struct{ id, product, installation string }

func publicErasureIDs(ctx context.Context, tx query.TxActor, statement string, parameters ydb.Params) ([]publicErasureID, error) {
	rows, err := tx.QueryResultSet(ctx, statement, query.WithParameters(parameters))
	if err != nil {
		return nil, err
	}
	defer rows.Close(ctx)
	var result []publicErasureID
	for row, rowErr := range rows.Rows(ctx) {
		if rowErr != nil {
			return nil, rowErr
		}
		var id publicErasureID
		if err := row.Scan(&id.id, &id.product, &id.installation); err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, nil
}

func erasePublicChallenge(ctx context.Context, tx query.TxActor, c publicErasureID) error {
	return tx.Exec(ctx, `DECLARE $id AS Utf8; DECLARE $product AS Utf8; DECLARE $installation AS Utf8;
DELETE FROM public_registration_flows WHERE product_id=$product AND installation_id=$installation AND challenge_id=$id AND session_id IS NULL;
DELETE FROM public_account_audit WHERE product_id=$product AND entity_id=$id;
DELETE FROM email_verifications WHERE id=$id AND product_id=$product AND installation_id=$installation;
DELETE FROM public_email_challenges WHERE id=$id AND product_id=$product AND installation_id=$installation;`, query.WithParameters(publicErasureParameters(c)))
}

func erasePublicSession(ctx context.Context, tx query.TxActor, s publicErasureID) error {
	return tx.Exec(ctx, `DECLARE $id AS Utf8; DECLARE $product AS Utf8; DECLARE $installation AS Utf8;
DELETE FROM public_registration_flows WHERE product_id=$product AND installation_id=$installation AND session_id=$id;
DELETE FROM account_refresh_tokens WHERE session_id=$id;
DELETE FROM public_account_audit WHERE product_id=$product AND session_id=$id;
DELETE FROM account_sessions WHERE id=$id AND product_id=$product AND installation_id=$installation;`, query.WithParameters(publicErasureParameters(s)))
}

func publicErasureParameters(id publicErasureID) ydb.Params {
	return ydb.ParamsBuilder().Param("$id").Text(id.id).Param("$product").Text(id.product).Param("$installation").Text(id.installation).Build()
}

func publicErasureScope(product *string, name, subject string) ydb.Params {
	value := ""
	if product != nil {
		value = *product
	}
	return ydb.ParamsBuilder().Param("$all").Bool(product == nil).Param("$product").Text(value).Param(name).Text(subject).Build()
}

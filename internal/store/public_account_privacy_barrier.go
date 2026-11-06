package store

import (
	"context"
	"errors"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

// A pending deletion must fence new online sessions before downstream erasure.
// Rejected/cancelled requests do not silently revoke local or online state.
func publicAccountDeletionPending(ctx context.Context, executor query.Executor, person, installation, product string) (bool, error) {
	row, err := executor.QueryRow(ctx, `DECLARE $person AS Utf8; DECLARE $installation AS Utf8; DECLARE $product AS Utf8;
SELECT id FROM privacy_requests WHERE request_type='deletion' AND status NOT IN ('cancelled','rejected','completed')
AND (scope='all' OR product_id=$product)
AND ((subject_type='person' AND subject_id=$person) OR (subject_type='installation' AND subject_id=$installation)) LIMIT 1;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$person").Text(person).Param("$installation").Text(installation).Param("$product").Text(product).Build()))
	if errors.Is(err, query.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var id string
	if err := row.Scan(&id); err != nil {
		return false, err
	}
	if !domain.ValidUUID(id) {
		return false, domain.ErrInvalid
	}
	return true, nil
}

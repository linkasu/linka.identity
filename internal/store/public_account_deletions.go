package store

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

type PublicAccountDeletion struct {
	SessionID, AccountID, ProductID, RequestID, StatusSecretHash string
	RequestedAt                                                  time.Time
}

func publicDeletionNamespace(product, requestID string) string {
	return "public-account-deletion:" + product + ":" + requestID
}

func validPublicDeletionKey(product, requestID, hash string) bool {
	decoded, err := hex.DecodeString(hash)
	return domain.ValidProductID(product) && domain.ValidUUID(requestID) && err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == hash
}

// Session authority and privacy fanout commit atomically, including concurrent revocation.
func (s *Store) CreatePublicAccountDeletion(ctx context.Context, input PublicAccountDeletion, products map[string]string) (PrivacyRequestStatus, error) {
	if !domain.ValidUUID(input.SessionID) || !domain.ValidUUID(input.AccountID) || !validPublicDeletionKey(input.ProductID, input.RequestID, input.StatusSecretHash) || products[input.ProductID] == "" || input.RequestedAt.IsZero() {
		return PrivacyRequestStatus{}, domain.ErrInvalid
	}
	var result PrivacyRequestStatus
	err := s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		result = PrivacyRequestStatus{}
		session, _, err := authorizedPublicAccountSession(ctx, tx, input.SessionID, input.ProductID, s.now().UTC())
		if err != nil {
			return err
		}
		if session.AccountID != input.AccountID {
			return domain.ErrNotFound
		}
		row, err := tx.QueryRow(ctx, `DECLARE $account AS Utf8; SELECT person_id FROM accounts WHERE id=$account;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$account").Text(session.AccountID).Build()))
		if err != nil {
			return noRows(err)
		}
		var person string
		if err := row.Scan(&person); err != nil {
			return err
		}
		result, _, err = s.createPrivacyRequest(ctx, tx, PrivacyRequest{
			Subject: Subject{Kind: "person", ID: person}, RequestType: "deletion", Scope: "product", ProductID: &input.ProductID,
			RequestedAt: input.RequestedAt, RequestedByWorkload: publicDeletionNamespace(input.ProductID, input.RequestID), IdempotencyKey: input.StatusSecretHash,
		}, products)
		return err
	})
	if err != nil {
		return PrivacyRequestStatus{}, err
	}
	return result, nil
}

// The status capability deliberately has no dependency on erased account state.
func (s *Store) PublicAccountDeletionStatus(ctx context.Context, requestID, product, hash string) (PrivacyRequestStatus, error) {
	if !validPublicDeletionKey(product, requestID, hash) {
		return PrivacyRequestStatus{}, domain.ErrInvalid
	}
	row, err := s.client.QueryRow(ctx, `DECLARE $workload AS Utf8; DECLARE $key AS Utf8; DECLARE $product AS Utf8;
SELECT r.id,r.request_type,r.scope,r.product_id,r.status,r.requested_at,r.completed_at
FROM privacy_idempotency AS i INNER JOIN privacy_requests AS r ON r.id=i.request_id
WHERE i.requested_by_workload=$workload AND i.idempotency_key=$key
AND r.request_type='deletion' AND r.scope='product' AND r.product_id=$product;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$workload").Text(publicDeletionNamespace(product, requestID)).Param("$key").Text(hash).Param("$product").Text(product).Build()),
		query.WithTxControl(query.SnapshotReadOnlyTxControl()))
	if err != nil {
		return PrivacyRequestStatus{}, noRows(err)
	}
	var result PrivacyRequestStatus
	if err := row.Scan(&result.ID, &result.RequestType, &result.Scope, &result.ProductID, &result.Status, &result.RequestedAt, &result.CompletedAt); err != nil {
		return PrivacyRequestStatus{}, err
	}
	return result, nil
}

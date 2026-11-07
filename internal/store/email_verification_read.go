package store

import (
	"context"
	"math"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

// EmailVerification reads encrypted backend state, never a public directory DTO.
func (s *Store) EmailVerification(ctx context.Context, id string) (EmailVerification, error) {
	if !domain.ValidUUID(id) {
		return EmailVerification{}, domain.ErrInvalid
	}
	return readEmailVerification(ctx, s.client, id, query.WithTxControl(query.SnapshotReadOnlyTxControl()))
}

func readEmailVerification(ctx context.Context, executor query.Executor, id string, options ...query.ExecuteOption) (EmailVerification, error) {
	options = append(options, query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(id).Build()))
	row, err := executor.QueryRow(ctx, `DECLARE $id AS Utf8;
SELECT product_id,installation_id,identity_namespace,age_category,guardian_relationship,link_across_products,
blind_index_version,email_blind_index,encryption_algorithm,key_id,wrapped_data_key,email_nonce,encrypted_email,
expires_at,verified_at,verified_by,evidence_id,processing_token,processing_at,version FROM email_verifications WHERE id=$id;`, options...)
	if err != nil {
		return EmailVerification{}, noRows(err)
	}
	v := EmailVerification{ID: id}
	var indexVersion uint64
	if err := row.Scan(&v.ProductID, &v.InstallationID, &v.Namespace, &v.AgeCategory, &v.GuardianRelationship, &v.LinkAcrossProducts,
		&indexVersion, &v.BlindIndex, &v.EncryptedEmail.Algorithm, &v.EncryptedEmail.KeyID, &v.EncryptedEmail.WrappedDataKey,
		&v.EncryptedEmail.Nonce, &v.EncryptedEmail.Data, &v.ExpiresAt, &v.VerifiedAt, &v.VerifiedBy, &v.EvidenceID,
		&v.ProcessingToken, &v.ProcessingAt, &v.Version); err != nil {
		return EmailVerification{}, err
	}
	if indexVersion > math.MaxInt {
		return EmailVerification{}, domain.ErrInvalid
	}
	v.BlindIndexVersion = int(indexVersion)
	return v, nil
}

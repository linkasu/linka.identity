package accountbroker

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/linka-cloud/linka.identity/internal/token"
)

type DeletionInput struct {
	RequestID    string `json:"request_id"`
	StatusSecret string `json:"status_secret"`
}

type DeletionStatusInput struct {
	RequestID string `json:"request_id"`
	ProductID string `json:"product_id"`
}

type DeletionStatus struct {
	ContractVersion int        `json:"contract_version"`
	Product         string     `json:"product"`
	RequestID       string     `json:"request_id"`
	Status          string     `json:"status"`
	RequestedAt     time.Time  `json:"requested_at"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
}

func deletionSecretHash(secret string) string {
	digest := sha256.Sum256([]byte("linka-public-account-deletion-status-v1\x00" + secret))
	return hex.EncodeToString(digest[:])
}

func (b *Broker) CreateDeletion(ctx context.Context, credential string, input DeletionInput) (DeletionStatus, error) {
	input.RequestID = strings.ToLower(input.RequestID)
	if !domain.ValidUUID(input.RequestID) || !validClientNonce(input.StatusSecret) {
		return DeletionStatus{}, domain.ErrInvalid
	}
	claims, err := b.signer.VerifyAccountAccess(credential)
	if err != nil || b.products[claims.Product] == "" {
		return DeletionStatus{}, ErrAccountCredential
	}
	session, _, err := b.repository.AuthorizedPublicAccountSession(ctx, claims.SessionID, claims.Product)
	if errors.Is(err, domain.ErrNotFound) {
		return DeletionStatus{}, ErrAccountCredential
	}
	if err != nil {
		return DeletionStatus{}, err
	}
	expected := b.pairwise.Subject(claims.Product, token.AccountAudience, "account", session.AccountID)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(claims.Subject)) != 1 {
		return DeletionStatus{}, ErrAccountCredential
	}
	result, err := b.repository.CreatePublicAccountDeletion(ctx, store.PublicAccountDeletion{
		SessionID: claims.SessionID, AccountID: session.AccountID, ProductID: claims.Product, RequestID: input.RequestID,
		StatusSecretHash: deletionSecretHash(input.StatusSecret), RequestedAt: b.now().UTC().Truncate(time.Microsecond),
	}, b.products)
	if errors.Is(err, domain.ErrNotFound) {
		return DeletionStatus{}, ErrAccountCredential
	}
	if err != nil {
		return DeletionStatus{}, err
	}
	return publicDeletionStatus(result, claims.Product, input.RequestID)
}

func (b *Broker) DeletionStatus(ctx context.Context, secret string, input DeletionStatusInput) (DeletionStatus, error) {
	if !validClientNonce(secret) {
		return DeletionStatus{}, ErrAccountCredential
	}
	input.RequestID = strings.ToLower(input.RequestID)
	if !domain.ValidUUID(input.RequestID) || !domain.ValidProductID(input.ProductID) {
		return DeletionStatus{}, domain.ErrInvalid
	}
	if b.products[input.ProductID] == "" {
		return DeletionStatus{}, domain.ErrNotFound
	}
	result, err := b.repository.PublicAccountDeletionStatus(ctx, input.RequestID, input.ProductID, deletionSecretHash(secret))
	if err != nil {
		return DeletionStatus{}, err
	}
	return publicDeletionStatus(result, input.ProductID, input.RequestID)
}

func publicDeletionStatus(result store.PrivacyRequestStatus, product, requestID string) (DeletionStatus, error) {
	if result.RequestType != "deletion" || result.Scope != "product" || result.ProductID == nil || *result.ProductID != product {
		return DeletionStatus{}, errors.New("invalid committed deletion context")
	}
	switch result.Status {
	case "requested", "processing", "completed", "rejected", "cancelled":
	default:
		return DeletionStatus{}, errors.New("invalid committed deletion status")
	}
	return DeletionStatus{ContractVersion: ContractVersion, Product: product, RequestID: requestID, Status: result.Status, RequestedAt: result.RequestedAt, CompletedAt: result.CompletedAt}, nil
}

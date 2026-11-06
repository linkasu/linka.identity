package service

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/cryptokit"
)

func TestPublicRegistrationPreparationDoesNotWriteOrGrantCrossProductLinkage(t *testing.T) {
	provider, err := cryptokit.NewLocalAESKeyProvider("test", bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	indexer, err := cryptokit.NewBlindIndexer(1, map[int][]byte{1: bytes.Repeat([]byte{2}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	s := NewIdentityService(nil, cryptokit.NewEnvelope(provider), indexer, false)
	now := time.Now().UTC().Truncate(time.Microsecond)
	verification, err := s.PreparePublicVerification(context.Background(), PublicVerificationInput{
		ID: "3499c1bc-e936-43af-a601-f98562dd0351", ProductID: "linka-type", Email: " Owner+Type@Example.Test ",
		InstallationID: "ac17879e-b16b-4a2d-b763-764230f51587", ExpiresAt: now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if verification.Namespace != "account" || verification.AgeCategory != "unknown" || verification.LinkAcrossProducts || verification.VerifiedAt != nil || verification.InstallationID == nil {
		t.Fatal("public preparation invented verification or cross-product consent")
	}
	plain, err := s.OpenVerificationEmail(context.Background(), verification)
	if err != nil || plain != "owner+type@example.test" {
		t.Fatalf("address was not protected with its verification context: %v", err)
	}
	identity, indexes, err := s.PreparePublicIdentity(context.Background(), verification, now)
	if err != nil || len(indexes) != 1 || identity.AccountID == "" || !identity.CreateAccount || identity.LinkageScope != "product" || identity.ScopeKey != "linka-type" || identity.AgeCategory != "unknown" {
		t.Fatalf("public registration preparation changed policy: %v", err)
	}
	if !bytes.Equal(identity.BlindIndex, verification.BlindIndex) {
		t.Fatal("verification and final identity use different normalization/scope")
	}
}

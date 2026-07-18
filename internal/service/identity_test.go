package service

import (
	"testing"

	"github.com/linka-cloud/linka.identity/internal/domain"
)

func TestDonationAndDefaultIdentityScopesAreProductLocal(t *testing.T) {
	service := &IdentityService{}
	for _, namespace := range []string{"account", "donation"} {
		scope, key, err := service.linkageScope(RegisterEmailIdentityInput{
			Namespace: namespace, ProductID: "plays", AgeCategory: "adult",
		})
		if err != nil || scope != "product" || key != "plays" {
			t.Fatalf("unexpected %s scope: %s %s %v", namespace, scope, key, err)
		}
	}
}

func TestDonationCannotBeGloballyLinked(t *testing.T) {
	service := &IdentityService{minorCrossProductLinking: true}
	scope, _, err := service.linkageScope(RegisterEmailIdentityInput{
		Namespace: "donation", ProductID: "donations", AgeCategory: "adult", LinkAcrossProducts: true,
	})
	if err != nil || scope != "product" {
		t.Fatalf("donation scope must remain product-local: %s %v", scope, err)
	}
}

func TestMinorGlobalLinkingRequiresFeatureFlag(t *testing.T) {
	service := &IdentityService{}
	_, _, err := service.linkageScope(RegisterEmailIdentityInput{
		Namespace: "account", ProductID: "plays", AgeCategory: "minor", LinkAcrossProducts: true,
	})
	if err != domain.ErrForbidden {
		t.Fatalf("expected forbidden, got %v", err)
	}
	service.minorCrossProductLinking = true
	scope, _, err := service.linkageScope(RegisterEmailIdentityInput{
		Namespace: "account", ProductID: "plays", AgeCategory: "minor", LinkAcrossProducts: true,
	})
	if err != nil || scope != "global" {
		t.Fatalf("expected explicitly enabled global scope, got %s %v", scope, err)
	}
}

func TestNormalizeEmailRejectsDisplayName(t *testing.T) {
	if _, err := normalizeEmail("User <user@example.test>"); err == nil {
		t.Fatal("expected display-name email to be rejected")
	}
	value, err := normalizeEmail(" User@Example.Test ")
	if err != nil || value != "user@example.test" {
		t.Fatalf("unexpected normalization: %q %v", value, err)
	}
}

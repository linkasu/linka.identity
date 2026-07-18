package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/ids"
	"github.com/linka-cloud/linka.identity/internal/pairwise"
	"github.com/linka-cloud/linka.identity/internal/service"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/linka-cloud/linka.identity/internal/token"
)

func (s *Server) createInstallation(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ProductID string `json:"product_id,omitempty"`
		Platform  string `json:"platform"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		s.fail(w, r, err)
		return
	}
	productID, audience, err := s.authorizeProduct(r.Context(), input.ProductID)
	platform, ok := domain.TrimmedWithin(input.Platform, 1, 64)
	if err != nil || !ok {
		if err == nil {
			err = domain.ErrInvalid
		}
		s.fail(w, r, err)
		return
	}
	rootID, err := ids.NewUUID()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	result, _, err := s.store.CreateInstallation(r.Context(), store.Installation{ID: rootID, ProductID: productID, Platform: platform})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	opaqueKey := s.pairwise.Subject(productID, audience, "installation", result.ID)
	if err := s.store.EnsureSubjectAlias(r.Context(), opaqueKey, productID, audience, "installation", result.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"installation_key": opaqueKey, "product": productID, "platform": result.Platform, "created_at": result.CreatedAt,
	})
}

func (s *Server) beginEmailVerification(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ProductID            string  `json:"product_id,omitempty"`
		Email                string  `json:"email"`
		IdentityNamespace    string  `json:"identity_namespace"`
		AgeCategory          string  `json:"age_category"`
		GuardianRelationship *string `json:"guardian_relationship,omitempty"`
		LinkAcrossProducts   bool    `json:"link_across_products,omitempty"`
		InstallationKey      *string `json:"installation_key,omitempty"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		s.fail(w, r, err)
		return
	}
	productID, audience, err := s.authorizeProduct(r.Context(), input.ProductID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var installationID *string
	if input.InstallationKey != nil {
		if !pairwise.Valid(*input.InstallationKey) {
			s.fail(w, r, domain.ErrInvalid)
			return
		}
		resolved, resolveErr := s.store.ResolveSubjectAlias(r.Context(), *input.InstallationKey, productID, audience)
		if resolveErr != nil || resolved.SubjectType != "installation" {
			s.fail(w, r, domain.ErrNotFound)
			return
		}
		installationID = &resolved.SubjectID
	}
	verificationID, expiresAt, err := s.identities.BeginEmailVerification(r.Context(), service.BeginEmailVerificationInput{
		ProductID: productID, Email: input.Email, Namespace: input.IdentityNamespace, AgeCategory: input.AgeCategory,
		GuardianRelationship: input.GuardianRelationship, LinkAcrossProducts: input.LinkAcrossProducts, InstallationID: installationID,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"verification_id": verificationID, "status": "pending", "expires_at": expiresAt})
}

func (s *Server) verifyEmailOwnership(w http.ResponseWriter, r *http.Request) {
	verificationID := r.PathValue("id")
	var input struct {
		ProductID  string `json:"product_id"`
		EvidenceID string `json:"evidence_id"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		s.fail(w, r, err)
		return
	}
	productID, _, err := s.authorizeProduct(r.Context(), input.ProductID)
	evidence, ok := domain.TrimmedWithin(input.EvidenceID, 1, 200)
	if err != nil || !domain.ValidUUID(verificationID) || !ok {
		if err == nil {
			err = domain.ErrInvalid
		}
		s.fail(w, r, err)
		return
	}
	if err := s.store.VerifyEmailOwnership(r.Context(), verificationID, productID, principal(r.Context()).ID, evidence, time.Now().UTC()); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"verification_id": verificationID, "status": "verified"})
}

func (s *Server) registerEmailIdentity(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ProductID      string `json:"product_id,omitempty"`
		VerificationID string `json:"verification_id"`
		CreateAccount  bool   `json:"create_account,omitempty"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		s.fail(w, r, err)
		return
	}
	productID, audience, err := s.authorizeProduct(r.Context(), input.ProductID)
	if err != nil || !domain.ValidUUID(input.VerificationID) {
		if err == nil {
			err = domain.ErrInvalid
		}
		s.fail(w, r, err)
		return
	}
	result, err := s.identities.CompleteEmailVerification(r.Context(), input.VerificationID, productID, input.CreateAccount)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	subjectType, rootID := "person", result.PersonID
	if result.AccountID != "" {
		subjectType, rootID = "account", result.AccountID
	}
	subjectKey := s.pairwise.Subject(productID, audience, subjectType, rootID)
	if err := s.store.EnsureSubjectAlias(r.Context(), subjectKey, productID, audience, subjectType, rootID); err != nil {
		s.fail(w, r, err)
		return
	}
	// Person aliases exist only to fan out privacy controls and are never returned.
	personKey := s.pairwise.Subject(productID, audience, "person", result.PersonID)
	if err := s.store.EnsureSubjectAlias(r.Context(), personKey, productID, audience, "person", result.PersonID); err != nil {
		s.fail(w, r, err)
		return
	}
	status := http.StatusOK
	if result.Created {
		status = http.StatusCreated
	}
	writeJSON(w, status, map[string]string{"subject_type": subjectType, "subject_key": subjectKey})
}

func (s *Server) issueToken(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ProductID   string `json:"product_id,omitempty"`
		SubjectType string `json:"subject_type"`
		SubjectKey  string `json:"subject_key"`
		TTLSeconds  int64  `json:"ttl_seconds,omitempty"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		s.fail(w, r, err)
		return
	}
	productID, audience, err := s.authorizeProduct(r.Context(), input.ProductID)
	if err != nil || !pairwise.Valid(input.SubjectKey) || input.TTLSeconds < 0 ||
		(input.SubjectType != "account" && input.SubjectType != "installation") {
		if err == nil {
			err = domain.ErrInvalid
		}
		s.fail(w, r, err)
		return
	}
	resolved, err := s.store.ResolveSubjectAlias(r.Context(), input.SubjectKey, productID, audience)
	if err != nil || resolved.SubjectType != input.SubjectType {
		s.fail(w, r, domain.ErrNotFound)
		return
	}
	if err := s.store.ResolveTokenSubject(r.Context(), productID, resolved.SubjectType, resolved.SubjectID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			s.fail(w, r, domain.ErrNotFound)
			return
		}
		s.fail(w, r, err)
		return
	}
	var personKey *string
	if resolved.SubjectType == "account" {
		value := s.pairwise.Subject(productID, audience, "person", resolved.PersonID)
		if err := s.store.EnsureSubjectAlias(r.Context(), value, productID, audience, "person", resolved.PersonID); err != nil {
			s.fail(w, r, err)
			return
		}
		personKey = &value
	}
	encoded, expiresAt, err := s.tokens.SignClaims(token.SignInput{
		Audience: audience, Product: productID, Subject: input.SubjectKey, SubjectType: input.SubjectType,
		Scopes: []string{"telemetry:write"}, PersonKey: personKey, TTL: time.Duration(input.TTLSeconds) * time.Second,
	})
	if err != nil {
		s.fail(w, r, domain.ErrInvalid)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"access_token": encoded, "token_type": "Bearer", "expires_at": expiresAt})
}

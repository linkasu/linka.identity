package httpapi

import (
	"net/http"
	"time"

	"github.com/linka-cloud/linka.identity/internal/authz"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/ids"
	"github.com/linka-cloud/linka.identity/internal/pairwise"
	"github.com/linka-cloud/linka.identity/internal/store"
)

func (s *Server) createConsent(w http.ResponseWriter, r *http.Request) {
	var input struct {
		SubjectType   string    `json:"subject_type"`
		SubjectKey    string    `json:"subject_key"`
		ProductID     string    `json:"product_id,omitempty"`
		ConsentType   string    `json:"consent_type"`
		PolicyVersion string    `json:"policy_version"`
		Status        string    `json:"status"`
		RecordedAt    time.Time `json:"recorded_at"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		s.fail(w, r, err)
		return
	}
	productID, audience, err := s.authorizeProduct(r.Context(), input.ProductID)
	consentType, typeOK := domain.TrimmedWithin(input.ConsentType, 1, 100)
	policyVersion, versionOK := domain.TrimmedWithin(input.PolicyVersion, 1, 100)
	if err != nil || !pairwise.Valid(input.SubjectKey) || !typeOK || !versionOK ||
		(input.Status != "granted" && input.Status != "withdrawn") || input.RecordedAt.IsZero() {
		if err == nil {
			err = domain.ErrInvalid
		}
		s.fail(w, r, err)
		return
	}
	resolved, err := s.store.ResolveSubjectAlias(r.Context(), input.SubjectKey, productID, audience)
	if err != nil || !subjectTypeMatches(input.SubjectType, resolved.SubjectType) {
		s.fail(w, r, domain.ErrNotFound)
		return
	}
	subject := rootSubject(resolved)
	id, err := ids.NewUUID()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.store.CreateConsent(r.Context(), store.Consent{
		ID: id, Subject: subject, ProductID: productID, ConsentType: consentType,
		PolicyVersion: policyVersion, Status: input.Status, RecordedAt: input.RecordedAt.UTC(),
	}); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "recorded_at": input.RecordedAt.UTC()})
}

func (s *Server) setTelemetryPreference(w http.ResponseWriter, r *http.Request) {
	var input struct {
		SubjectType string    `json:"subject_type"`
		SubjectKey  string    `json:"subject_key"`
		ProductID   string    `json:"product_id,omitempty"`
		Preference  string    `json:"preference"`
		RecordedAt  time.Time `json:"recorded_at"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		s.fail(w, r, err)
		return
	}
	productID, audience, err := s.authorizeProduct(r.Context(), input.ProductID)
	now := s.now().UTC()
	if err != nil || !pairwise.Valid(input.SubjectKey) ||
		(input.Preference != "allowed" && input.Preference != "denied") || input.RecordedAt.IsZero() ||
		input.RecordedAt.Before(now.Add(-24*time.Hour)) || input.RecordedAt.After(now.Add(5*time.Minute)) {
		if err == nil {
			err = domain.ErrInvalid
		}
		s.fail(w, r, err)
		return
	}
	resolved, err := s.store.ResolveSubjectAlias(r.Context(), input.SubjectKey, productID, audience)
	if err != nil || !subjectTypeMatches(input.SubjectType, resolved.SubjectType) {
		s.fail(w, r, domain.ErrNotFound)
		return
	}
	if err := s.store.SetTelemetryPreference(r.Context(), rootSubject(resolved), input.SubjectKey,
		productID, input.Preference, input.RecordedAt.UTC(), now); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"preference": input.Preference, "recorded_at": input.RecordedAt.UTC()})
}

func (s *Server) createPrivacyRequest(w http.ResponseWriter, r *http.Request) {
	var input struct {
		SubjectType     string  `json:"subject_type"`
		SubjectKey      string  `json:"subject_key"`
		RequestType     string  `json:"request_type"`
		Scope           string  `json:"scope"`
		ProductID       *string `json:"product_id,omitempty"`
		AnchorProductID string  `json:"anchor_product_id,omitempty"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		s.fail(w, r, err)
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if !pairwise.Valid(input.SubjectKey) || len(idempotencyKey) < 16 || len(idempotencyKey) > 128 || input.RequestType != "deletion" {
		s.fail(w, r, domain.ErrInvalid)
		return
	}
	workload := principal(r.Context())
	var productID *string
	var anchorProduct, audience string
	var err error
	if input.Scope == "product" && input.ProductID != nil {
		anchorProduct, audience, err = s.authorizeProduct(r.Context(), *input.ProductID)
		productID = &anchorProduct
	} else if input.Scope == "all" && input.ProductID == nil && workload.Has(authz.RolePrivacyGlobal) {
		anchorProduct = input.AnchorProductID
		audience, err = s.productAudience(anchorProduct)
	} else {
		err = domain.ErrForbidden
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	resolved, err := s.store.ResolveSubjectAlias(r.Context(), input.SubjectKey, anchorProduct, audience)
	if err != nil || !subjectTypeMatches(input.SubjectType, resolved.SubjectType) {
		s.fail(w, r, domain.ErrNotFound)
		return
	}
	if input.Scope == "all" && resolved.PersonID == "" {
		s.fail(w, r, domain.ErrForbidden)
		return
	}
	requestedAt := time.Now().UTC()
	request := store.PrivacyRequest{
		Subject: rootSubject(resolved), SubjectKey: input.SubjectKey, RequestType: input.RequestType, Scope: input.Scope,
		ProductID: productID, RequestedAt: requestedAt, RequestedByWorkload: workload.ID, IdempotencyKey: idempotencyKey,
	}
	result, created, err := s.store.CreatePrivacyRequest(r.Context(), request, s.products)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusAccepted
	}
	writeJSON(w, status, map[string]any{"id": result.ID, "status": result.Status, "requested_at": result.RequestedAt})
}

func (s *Server) getPrivacyRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !domain.ValidUUID(id) {
		s.fail(w, r, domain.ErrInvalid)
		return
	}
	result, err := s.store.GetPrivacyRequest(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) updatePrivacyRequestStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var input struct {
		Status    string `json:"status"`
		AuditNote string `json:"audit_note"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		s.fail(w, r, err)
		return
	}
	note, noteOK := domain.TrimmedWithin(input.AuditNote, 1, 1000)
	// Completion is exclusively orchestrator-controlled after downstream receipts and erasure.
	validStatus := input.Status == "processing" || input.Status == "rejected" || input.Status == "cancelled"
	if !domain.ValidUUID(id) || !noteOK || !validStatus {
		s.fail(w, r, domain.ErrInvalid)
		return
	}
	if err := s.store.UpdatePrivacyRequestStatus(r.Context(), store.PrivacyStatusUpdate{
		ID: id, Status: input.Status, Actor: principal(r.Context()).ID, AuditNote: note,
	}); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": input.Status})
}

func rootSubject(alias store.ResolvedAlias) store.Subject {
	if alias.PersonID != "" {
		return store.Subject{Kind: "person", ID: alias.PersonID}
	}
	return store.Subject{Kind: "installation", ID: alias.SubjectID}
}

func subjectTypeMatches(requested, resolved string) bool {
	return requested == resolved || (requested == "person" && resolved == "account")
}

func (s *Server) productAudience(product string) (string, error) {
	audience, ok := s.products[product]
	if !ok {
		return "", domain.ErrInvalid
	}
	return audience, nil
}

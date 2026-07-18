package httpapi

import (
	"net/http"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/ids"
	"github.com/linka-cloud/linka.identity/internal/pairwise"
	"github.com/linka-cloud/linka.identity/internal/store"
)

func (s *Server) createOrganizationSubmission(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ProductID     string `json:"product_id"`
		SubjectType   string `json:"subject_type"`
		SubjectKey    string `json:"subject_key"`
		SubmittedName string `json:"submitted_name"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		s.fail(w, r, err)
		return
	}
	name, ok := domain.TrimmedWithin(input.SubmittedName, 1, 240)
	productID, audience, authErr := s.authorizeProduct(r.Context(), input.ProductID)
	if !ok || authErr != nil || !pairwise.Valid(input.SubjectKey) ||
		(input.SubjectType != "person" && input.SubjectType != "installation") {
		if authErr == nil {
			authErr = domain.ErrInvalid
		}
		s.fail(w, r, authErr)
		return
	}
	resolved, err := s.store.ResolveSubjectAlias(r.Context(), input.SubjectKey, productID, audience)
	if err != nil || !subjectTypeMatches(input.SubjectType, resolved.SubjectType) {
		s.fail(w, r, domain.ErrNotFound)
		return
	}
	id, err := ids.NewUUID()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	submission := store.OrganizationSubmission{ID: id, ProductID: productID, SubmittedName: name}
	if resolved.PersonID != "" {
		submission.PersonID = &resolved.PersonID
	} else {
		submission.InstallationID = &resolved.SubjectID
	}
	if err := s.store.CreateOrganizationSubmission(r.Context(), submission); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "status": "pending"})
}

func (s *Server) createOrganization(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CanonicalName string `json:"canonical_name"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		s.fail(w, r, err)
		return
	}
	name, ok := domain.TrimmedWithin(input.CanonicalName, 1, 240)
	if !ok {
		s.fail(w, r, domain.ErrInvalid)
		return
	}
	id, err := ids.NewUUID()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.store.CreateOrganization(r.Context(), id, name); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "status": "active"})
}

func (s *Server) resolveOrganizationSubmission(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var input struct {
		Status         string  `json:"status"`
		OrganizationID *string `json:"organization_id"`
		AuditNote      string  `json:"audit_note"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		s.fail(w, r, err)
		return
	}
	note, noteOK := domain.TrimmedWithin(input.AuditNote, 1, 1000)
	validResolution := input.Status == "rejected" && input.OrganizationID == nil
	validResolution = validResolution || (input.Status == "matched" && input.OrganizationID != nil && domain.ValidUUID(*input.OrganizationID))
	if !domain.ValidUUID(id) || !noteOK || !validResolution {
		s.fail(w, r, domain.ErrInvalid)
		return
	}
	if err := s.store.ResolveOrganizationSubmission(r.Context(), id, input.Status, input.OrganizationID, principal(r.Context()).ID, note); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": input.Status})
}

func (s *Server) mergeOrganization(w http.ResponseWriter, r *http.Request) {
	sourceID := r.PathValue("id")
	var input struct {
		TargetOrganizationID string `json:"target_organization_id"`
		Reason               string `json:"reason"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		s.fail(w, r, err)
		return
	}
	reason, reasonOK := domain.TrimmedWithin(input.Reason, 1, 1000)
	if !domain.ValidUUID(sourceID) || !domain.ValidUUID(input.TargetOrganizationID) ||
		sourceID == input.TargetOrganizationID || !reasonOK {
		s.fail(w, r, domain.ErrInvalid)
		return
	}
	if err := s.store.MergeOrganization(r.Context(), sourceID, input.TargetOrganizationID, principal(r.Context()).ID, reason); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": sourceID, "status": "merged", "merged_into_id": input.TargetOrganizationID})
}

func (s *Server) createMembership(w http.ResponseWriter, r *http.Request) {
	var input struct {
		PersonKey      string     `json:"person_key"`
		OrganizationID string     `json:"organization_id"`
		ProductID      string     `json:"product_id"`
		RoleLabel      *string    `json:"role_label"`
		Status         string     `json:"status"`
		StartedAt      *time.Time `json:"started_at"`
		EndedAt        *time.Time `json:"ended_at"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		s.fail(w, r, err)
		return
	}
	productID, audience, authErr := s.authorizeProduct(r.Context(), input.ProductID)
	if authErr != nil || !pairwise.Valid(input.PersonKey) || !domain.ValidUUID(input.OrganizationID) ||
		(input.Status != "active" && input.Status != "inactive" && input.Status != "pending") ||
		(input.StartedAt != nil && input.EndedAt != nil && input.EndedAt.Before(*input.StartedAt)) {
		if authErr == nil {
			authErr = domain.ErrInvalid
		}
		s.fail(w, r, authErr)
		return
	}
	if input.RoleLabel != nil {
		trimmed, ok := domain.TrimmedWithin(*input.RoleLabel, 1, 120)
		if !ok {
			s.fail(w, r, domain.ErrInvalid)
			return
		}
		input.RoleLabel = &trimmed
	}
	resolved, err := s.store.ResolveSubjectAlias(r.Context(), input.PersonKey, productID, audience)
	if err != nil || resolved.PersonID == "" {
		s.fail(w, r, domain.ErrNotFound)
		return
	}
	id, err := ids.NewUUID()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.store.CreateMembership(r.Context(), store.Membership{
		ID: id, PersonID: resolved.PersonID, OrganizationID: input.OrganizationID,
		ProductID: productID, RoleLabel: input.RoleLabel, Status: input.Status,
		StartedAt: input.StartedAt, EndedAt: input.EndedAt,
	}); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id, "status": input.Status})
}

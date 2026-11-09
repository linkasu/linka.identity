package httpapi

import (
	"errors"
	"net/http"

	"github.com/linka-cloud/linka.identity/internal/accountbroker"
	"github.com/linka-cloud/linka.identity/internal/domain"
)

func (s *Server) createPublicAccountDeletion(w http.ResponseWriter, r *http.Request) {
	credential, input, ok := publicAccountRequest[accountbroker.DeletionInput](w, r)
	if !ok {
		return
	}
	result, err := s.publicAccounts.CreateDeletion(r.Context(), credential, input)
	if err != nil {
		s.failPublicAccount(w, err, false)
		return
	}
	writeJSON(w, http.StatusAccepted, result)
}

func (s *Server) publicAccountDeletionStatus(w http.ResponseWriter, r *http.Request) {
	credential, input, ok := publicAccountRequest[accountbroker.DeletionStatusInput](w, r)
	if !ok {
		return
	}
	result, err := s.publicAccounts.DeletionStatus(r.Context(), credential, input)
	if errors.Is(err, domain.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "not_found"})
		return
	}
	if err != nil {
		s.failPublicAccount(w, err, false)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

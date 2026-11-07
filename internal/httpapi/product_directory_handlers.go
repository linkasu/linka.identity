package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/linka-cloud/linka.identity/internal/authz"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/productdirectory"
)

type ProductDirectory interface {
	Query(context.Context, authz.Principal, productdirectory.QueryInput) (productdirectory.Page, error)
	Check(context.Context, authz.Principal, productdirectory.CheckInput) (productdirectory.Checks, error)
}

func (s *Server) queryProductDirectory(w http.ResponseWriter, r *http.Request) {
	var input *productdirectory.QueryInput
	if r.URL.RawQuery != "" || decodeJSON(w, r, &input) != nil || input == nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request"})
		return
	}
	result, err := s.directory.Query(r.Context(), principal(r.Context()), *input)
	if err != nil {
		s.failProductDirectory(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) checkProductDirectory(w http.ResponseWriter, r *http.Request) {
	var input *productdirectory.CheckInput
	if r.URL.RawQuery != "" || decodeJSON(w, r, &input) != nil || input == nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request"})
		return
	}
	result, err := s.directory.Check(r.Context(), principal(r.Context()), *input)
	if err != nil {
		s.failProductDirectory(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) failProductDirectory(w http.ResponseWriter, err error) {
	status, code := http.StatusServiceUnavailable, "directory_unavailable"
	switch {
	case errors.Is(err, domain.ErrInvalid):
		status, code = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, domain.ErrForbidden):
		status, code = http.StatusForbidden, "forbidden"
	case errors.Is(err, domain.ErrConflict):
		status, code = http.StatusConflict, "conflict"
	}
	writeJSON(w, status, errorResponse{Error: code})
}

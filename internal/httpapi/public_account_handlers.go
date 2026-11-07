package httpapi

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strconv"

	"github.com/linka-cloud/linka.identity/internal/accountbroker"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/installationbroker"
	"github.com/linka-cloud/linka.identity/internal/store"
)

type PublicAccountBroker interface {
	Begin(context.Context, string, accountbroker.ChallengeInput) (accountbroker.ChallengeResponse, error)
	Verify(context.Context, string, string, accountbroker.VerifyInput) (accountbroker.Registration, error)
	Refresh(context.Context, string) (accountbroker.Registration, error)
	Revoke(context.Context, string) error
	UpdateProfile(context.Context, string, accountbroker.ProfileInput) (accountbroker.Profile, error)
}

func (s *Server) publicAccountPreflight(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request"})
		return
	}
	s.publicPreflight(w, r)
}

func (s *Server) beginPublicAccountChallenge(w http.ResponseWriter, r *http.Request) {
	credential, input, ok := publicAccountRequest[accountbroker.ChallengeInput](w, r)
	if !ok {
		return
	}
	result, err := s.publicAccounts.Begin(r.Context(), credential, input)
	if err != nil {
		s.failPublicAccount(w, err, false)
		return
	}
	writeJSON(w, http.StatusAccepted, result)
}

func (s *Server) verifyPublicAccountChallenge(w http.ResponseWriter, r *http.Request) {
	credential, input, ok := publicAccountRequest[accountbroker.VerifyInput](w, r)
	if !ok {
		return
	}
	result, err := s.publicAccounts.Verify(r.Context(), credential, r.PathValue("id"), input)
	if err != nil {
		s.failPublicAccount(w, err, true)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) refreshPublicAccountSession(w http.ResponseWriter, r *http.Request) {
	credential, _, ok := publicAccountRequest[struct{}](w, r)
	if !ok {
		return
	}
	result, err := s.publicAccounts.Refresh(r.Context(), credential)
	if err != nil {
		s.failPublicAccount(w, err, false)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) revokePublicAccountSession(w http.ResponseWriter, r *http.Request) {
	credential, _, ok := publicAccountRequest[struct{}](w, r)
	if !ok {
		return
	}
	if err := s.publicAccounts.Revoke(r.Context(), credential); err != nil {
		s.failPublicAccount(w, err, false)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

func (s *Server) updatePublicAccountProfile(w http.ResponseWriter, r *http.Request) {
	credential, input, ok := publicAccountRequest[accountbroker.ProfileInput](w, r)
	if !ok {
		return
	}
	result, err := s.publicAccounts.UpdateProfile(r.Context(), credential, input)
	if err != nil {
		s.failPublicAccount(w, err, false)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func publicAccountRequest[T any](w http.ResponseWriter, r *http.Request) (string, T, bool) {
	var zero T
	credential, ok := bearerCredential(r)
	if !ok || len(r.Header.Values("Authorization")) != 1 {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid_credential"})
		return "", zero, false
	}
	var input *T
	if r.URL.RawQuery != "" || decodeJSONLimit(w, r, &input, maxPublicRequestBody) != nil || input == nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request"})
		return "", zero, false
	}
	return credential, *input, true
}

func (s *Server) failPublicAccount(w http.ResponseWriter, err error, challenge bool) {
	status, code := http.StatusServiceUnavailable, "account_unavailable"
	var limited *store.PublicRateLimitError
	switch {
	case errors.Is(err, installationbroker.ErrInvalidCredential), errors.Is(err, accountbroker.ErrAccountCredential):
		status, code = http.StatusUnauthorized, "invalid_credential"
	case errors.As(err, &limited):
		retry := math.Max(1, math.Ceil(limited.RetryAt.Sub(s.now()).Seconds()))
		w.Header().Set("Retry-After", strconv.FormatInt(int64(retry), 10))
		status, code = http.StatusTooManyRequests, "rate_limited"
	case errors.Is(err, domain.ErrNotFound):
		status, code = http.StatusUnauthorized, "invalid_credential"
		if challenge {
			status, code = http.StatusBadRequest, "challenge_rejected"
		}
	case errors.Is(err, domain.ErrInvalid):
		status, code = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, domain.ErrConflict):
		status, code = http.StatusConflict, "conflict"
	case errors.Is(err, domain.ErrForbidden):
		status, code = http.StatusForbidden, "forbidden"
	}
	writeJSON(w, status, errorResponse{Error: code})
}

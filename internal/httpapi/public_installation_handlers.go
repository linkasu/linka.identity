package httpapi

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/installationbroker"
)

const maxPublicRequestBody = 4 << 10

func (s *Server) registerPublicInstallation(w http.ResponseWriter, r *http.Request) {
	if !s.publicRegisterLimit.Allow() {
		w.Header().Set("Retry-After", "10")
		writeJSON(w, http.StatusTooManyRequests, errorResponse{Error: "rate_limited"})
		return
	}
	var input installationbroker.RegisterInput
	if err := decodeJSONLimit(w, r, &input, maxPublicRequestBody); err != nil {
		s.fail(w, r, err)
		return
	}
	result, err := s.publicBroker.Register(r.Context(), input)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (s *Server) refreshPublicInstallationToken(w http.ResponseWriter, r *http.Request) {
	var input struct{}
	if err := decodeJSONLimit(w, r, &input, maxPublicRequestBody); err != nil {
		s.fail(w, r, err)
		return
	}
	credential, ok := bearerCredential(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid_refresh_credential"})
		return
	}
	result, err := s.publicBroker.Refresh(r.Context(), credential)
	if errors.Is(err, installationbroker.ErrInvalidCredential) {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid_refresh_credential"})
		return
	}
	if errors.Is(err, domain.ErrForbidden) {
		writeJSON(w, http.StatusForbidden, errorResponse{Error: "telemetry_denied"})
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if result.Product == "linka-looks" {
		writeJSON(w, http.StatusOK, struct {
			installationbroker.TokenResponse
			*installationbroker.AccessToken
		}{result, &result.MetricsToken})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) setPublicTelemetryPreference(w http.ResponseWriter, r *http.Request) {
	var input installationbroker.PreferenceInput
	if err := decodeJSONLimit(w, r, &input, maxPublicRequestBody); err != nil {
		s.fail(w, r, err)
		return
	}
	credential, ok := bearerCredential(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid_refresh_credential"})
		return
	}
	result, err := s.publicBroker.SetPreference(r.Context(), credential, input)
	if errors.Is(err, installationbroker.ErrInvalidCredential) {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid_refresh_credential"})
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) publicPreflight(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getPublicTelemetryPreference(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		s.fail(w, r, domain.ErrInvalid)
		return
	}
	if r.Body != nil {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1))
		if err != nil || len(body) != 0 {
			s.fail(w, r, domain.ErrInvalid)
			return
		}
	}
	credential, ok := bearerCredential(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid_refresh_credential"})
		return
	}
	result, err := s.publicBroker.GetPreference(r.Context(), credential)
	if errors.Is(err, installationbroker.ErrInvalidCredential) {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid_refresh_credential"})
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, result)
}

func bearerCredential(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	value := r.Header.Get("Authorization")
	if !strings.HasPrefix(value, prefix) {
		return "", false
	}
	credential := strings.TrimSpace(strings.TrimPrefix(value, prefix))
	return credential, credential != "" && !strings.ContainsAny(credential, " \t\r\n") && len(credential) <= 4096
}

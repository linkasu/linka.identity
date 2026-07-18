package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/linka-cloud/linka.identity/internal/authz"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/ids"
	"github.com/linka-cloud/linka.identity/internal/pairwise"
	"github.com/linka-cloud/linka.identity/internal/service"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/linka-cloud/linka.identity/internal/token"
)

const maxRequestBody = 64 << 10

type Server struct {
	store         *store.Store
	identities    *service.IdentityService
	tokens        *token.Signer
	authenticator *authz.Authenticator
	pairwise      *pairwise.Generator
	products      map[string]string
	requireOutbox bool
	outboxMaxAge  time.Duration
	logger        *slog.Logger
	now           func() time.Time
}

type contextKey string

const requestIDKey contextKey = "request-id"
const principalKey contextKey = "principal"

func New(database *store.Store, identities *service.IdentityService, tokens *token.Signer, authenticator *authz.Authenticator,
	pairwiseIDs *pairwise.Generator, products map[string]string, requireOutbox bool, outboxMaxAge time.Duration, logger *slog.Logger) http.Handler {
	server := &Server{
		store: database, identities: identities, tokens: tokens,
		authenticator: authenticator, pairwise: pairwiseIDs, products: products,
		requireOutbox: requireOutbox, outboxMaxAge: outboxMaxAge, logger: logger, now: time.Now,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", server.health)
	mux.HandleFunc("GET /readyz", server.ready)
	mux.HandleFunc("GET /.well-known/jwks.json", server.jwks)
	mux.Handle("POST /v1/installations", server.require(authz.RoleProduct, http.HandlerFunc(server.createInstallation)))
	mux.Handle("POST /v1/email-verifications", server.require(authz.RoleProduct, http.HandlerFunc(server.beginEmailVerification)))
	mux.Handle("POST /v1/internal/email-verifications/{id}/verify", server.require(authz.RoleEmailVerifier, http.HandlerFunc(server.verifyEmailOwnership)))
	mux.Handle("POST /v1/email-identities", server.require(authz.RoleProduct, http.HandlerFunc(server.registerEmailIdentity)))
	mux.Handle("POST /v1/tokens", server.require(authz.RoleProduct, http.HandlerFunc(server.issueToken)))
	mux.Handle("POST /v1/organization-submissions", server.require(authz.RoleProduct, http.HandlerFunc(server.createOrganizationSubmission)))
	mux.Handle("POST /v1/memberships", server.require(authz.RoleProduct, http.HandlerFunc(server.createMembership)))
	mux.Handle("POST /v1/consents", server.require(authz.RoleProduct, http.HandlerFunc(server.createConsent)))
	mux.Handle("PUT /v1/telemetry-preferences", server.require(authz.RoleProduct, http.HandlerFunc(server.setTelemetryPreference)))
	mux.Handle("POST /v1/privacy-requests", server.require(authz.RoleProduct, http.HandlerFunc(server.createPrivacyRequest)))
	mux.Handle("POST /v1/internal/privacy-requests", server.require(authz.RolePrivacyGlobal, http.HandlerFunc(server.createPrivacyRequest)))
	mux.Handle("GET /v1/privacy-requests/{id}", server.require(authz.RolePrivacyAdmin, http.HandlerFunc(server.getPrivacyRequest)))
	mux.Handle("POST /v1/internal/privacy-requests/{id}/status", server.require(authz.RolePrivacyAdmin, http.HandlerFunc(server.updatePrivacyRequestStatus)))
	mux.Handle("POST /v1/internal/organizations", server.require(authz.RoleOrgAdmin, http.HandlerFunc(server.createOrganization)))
	mux.Handle("POST /v1/internal/organization-submissions/{id}/resolve", server.require(authz.RoleOrgAdmin, http.HandlerFunc(server.resolveOrganizationSubmission)))
	mux.Handle("POST /v1/internal/organizations/{id}/merge", server.require(authz.RoleOrgAdmin, http.HandlerFunc(server.mergeOrganization)))
	return server.middleware(mux)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ready(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	if s.requireOutbox {
		if err := s.store.OutboxReady(ctx, s.outboxMaxAge); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "outbox_unavailable"})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, s.tokens.JWKS())
}

func (s *Server) require(role authz.Role, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := s.authenticator.Authenticate(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
			return
		}
		if !principal.Has(role) {
			writeJSON(w, http.StatusForbidden, errorResponse{Error: "forbidden"})
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, principal)))
	})
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID, err := ids.NewUUID()
		if err != nil {
			requestID = "unavailable"
		}
		ctx := context.WithValue(r.Context(), requestIDKey, requestID)
		w.Header().Set("X-Request-ID", requestID)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		started := time.Now()
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("request panic", "request_id", requestID, "panic_type", fmt.Sprintf("%T", recovered), "stack", string(debug.Stack()))
				if !recorder.written {
					writeJSON(recorder, http.StatusInternalServerError, errorResponse{Error: "internal_error"})
				}
			}
			s.logger.Info("request completed", "request_id", requestID, "method", r.Method,
				"path", r.URL.Path, "status", recorder.status, "duration_ms", time.Since(started).Milliseconds())
		}()
		next.ServeHTTP(recorder, r.WithContext(ctx))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (w *statusRecorder) WriteHeader(status int) {
	w.status = status
	w.written = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecorder) Write(contents []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(contents)
}

type errorResponse struct {
	Error string `json:"error"`
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	status := http.StatusInternalServerError
	code := "internal_error"
	switch {
	case errors.Is(err, domain.ErrInvalid):
		status, code = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, domain.ErrForbidden):
		status, code = http.StatusForbidden, "forbidden"
	case errors.Is(err, domain.ErrNotFound):
		status, code = http.StatusNotFound, "not_found"
	case errors.Is(err, domain.ErrConflict):
		status, code = http.StatusConflict, "conflict"
	}
	if status == http.StatusInternalServerError {
		s.logger.Error("request failed", "request_id", requestID(r.Context()), "error_type", fmt.Sprintf("%T", err))
	}
	writeJSON(w, status, errorResponse{Error: code})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return domain.ErrInvalid
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return domain.ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return domain.ErrInvalid
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "no-store")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func requestID(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey).(string)
	return value
}

func principal(ctx context.Context) authz.Principal {
	value, _ := ctx.Value(principalKey).(authz.Principal)
	return value
}

func (s *Server) authorizeProduct(ctx context.Context, requested string) (string, string, error) {
	workload := principal(ctx)
	productID := requested
	if productID == "" {
		var ok bool
		productID, ok = workload.SingleProduct()
		if !ok {
			return "", "", domain.ErrInvalid
		}
	}
	audience, exists := s.products[productID]
	if !exists || !workload.AllowsProduct(productID) {
		return "", "", domain.ErrForbidden
	}
	return productID, audience, nil
}

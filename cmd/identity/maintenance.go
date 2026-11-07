package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"
)

func maintenanceHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", "60")
		w.Header().Set("Content-Type", "application/json")
		status, body := http.StatusServiceUnavailable, `{"error":"identity_maintenance"}`
		if r.Method == http.MethodGet {
			switch r.URL.Path {
			case "/healthz":
				status, body = http.StatusOK, `{"status":"ok","mode":"maintenance"}`
			case "/readyz":
				body = `{"status":"maintenance"}`
			}
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
}

func runMaintenance(ctx context.Context, listener net.Listener, logger *slog.Logger) error {
	server := &http.Server{
		Handler:           maintenanceHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	logger.Info("identity maintenance mode active")
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- server.Serve(listener) }()
	select {
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			return errors.New("serve maintenance HTTP failed")
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return errors.New("shutdown maintenance HTTP failed")
		}
		return nil
	}
}

package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMaintenanceHandler(t *testing.T) {
	paths := []string{"/healthz", "/healthz?probe=1", "/readyz", "/.well-known/jwks.json", "/public/installations", "/public/accounts", "/internal/workers/tick", "/v1/identity", "/unknown", "/healthz/"}
	methods := []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions, http.MethodTrace, http.MethodConnect}
	for _, method := range methods {
		for _, path := range paths {
			t.Run(method+" "+path, func(t *testing.T) {
				response := httptest.NewRecorder()
				maintenanceHandler().ServeHTTP(response, httptest.NewRequest(method, path, nil))
				status, body := http.StatusServiceUnavailable, `{"error":"identity_maintenance"}`
				if method == http.MethodGet {
					switch strings.Split(path, "?")[0] {
					case "/healthz":
						status, body = http.StatusOK, `{"status":"ok","mode":"maintenance"}`
					case "/readyz":
						body = `{"status":"maintenance"}`
					}
				}
				if response.Code != status || strings.TrimSpace(response.Body.String()) != body {
					t.Fatalf("response = %d %s, want %d %s", response.Code, response.Body.String(), status, body)
				}
				for key, value := range map[string]string{"Cache-Control": "no-store", "Retry-After": "60", "Content-Type": "application/json"} {
					if response.Header().Get(key) != value {
						t.Errorf("%s = %q, want %q", key, response.Header().Get(key), value)
					}
				}
			})
		}
	}
}

func TestRunMaintenanceStopsOnCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- runMaintenance(ctx, listener, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	client := &http.Client{Timeout: time.Second}
	defer client.CloseIdleConnections()
	response, err := client.Get("http://" + listener.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", response.StatusCode)
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("maintenance server did not stop")
	}
}

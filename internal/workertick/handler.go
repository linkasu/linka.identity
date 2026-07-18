package workertick

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

const Path = "/internal/workers/tick"

type Processor interface {
	Process(context.Context) error
}

type handler struct {
	processors []Processor
}

func New(outbox, privacyErasure, verificationCleanup Processor) http.Handler {
	return &handler{processors: []Processor{outbox, privacyErasure, verificationCleanup}}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	for _, processor := range h.processors {
		if err := processor.Process(ctx); err != nil {
			writeStatus(w, http.StatusServiceUnavailable, "retry")
			return
		}
	}
	writeStatus(w, http.StatusOK, "ok")
}

func writeStatus(w http.ResponseWriter, code int, status string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": status})
}

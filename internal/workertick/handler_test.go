package workertick

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

type processorFunc func(context.Context) error

func (f processorFunc) Process(ctx context.Context) error {
	return f(ctx)
}

func TestHandlerProcessesWorkersInOrder(t *testing.T) {
	var calls []string
	type contextKey struct{}
	processor := func(name string) Processor {
		return processorFunc(func(ctx context.Context) error {
			if got := ctx.Value(contextKey{}); got != "request" {
				t.Errorf("%s did not receive request context", name)
			}
			calls = append(calls, name)
			return nil
		})
	}
	handler := New(processor("outbox"), processor("privacy"), processor("verification"))
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, Path, nil)
	request = request.WithContext(context.WithValue(request.Context(), contextKey{}, "request"))

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d", response.Code, http.StatusOK)
	}
	if got, want := response.Body.String(), "{\"status\":\"ok\"}\n"; got != want {
		t.Fatalf("body: got %q, want %q", got, want)
	}
	if want := []string{"outbox", "privacy", "verification"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("call order: got %v, want %v", calls, want)
	}
}

func TestHandlerReturnsRetryWithoutErrorDetails(t *testing.T) {
	var calls []string
	handler := New(
		processorFunc(func(context.Context) error {
			calls = append(calls, "outbox")
			return nil
		}),
		processorFunc(func(context.Context) error {
			calls = append(calls, "privacy")
			return errors.New("secret@example.test root-id token")
		}),
		processorFunc(func(context.Context) error {
			calls = append(calls, "verification")
			return nil
		}),
	)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, Path, nil))

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if got, want := response.Body.String(), "{\"status\":\"retry\"}\n"; got != want {
		t.Fatalf("body: got %q, want %q", got, want)
	}
	for _, detail := range []string{"secret@example.test", "root-id", "token"} {
		if strings.Contains(response.Body.String(), detail) {
			t.Fatalf("response contains error detail %q", detail)
		}
	}
	if want := []string{"outbox", "privacy"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls after failure: got %v, want %v", calls, want)
	}
}

func TestHandlerRejectsOtherMethodsWithoutProcessing(t *testing.T) {
	called := false
	processor := processorFunc(func(context.Context) error {
		called = true
		return nil
	})
	handler := New(processor, processor, processor)

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(method, Path, nil))
		if response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s status: got %d, want %d", method, response.Code, http.StatusMethodNotAllowed)
		}
		if got := response.Header().Get("Allow"); got != http.MethodPost {
			t.Fatalf("%s Allow: got %q, want %q", method, got, http.MethodPost)
		}
	}
	if called {
		t.Fatal("processor was called for a non-POST request")
	}
}

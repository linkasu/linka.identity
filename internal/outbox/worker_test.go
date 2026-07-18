package outbox

import (
	"encoding/json"
	"testing"
	"time"
)

func TestRetryDelayIsBounded(t *testing.T) {
	if retryDelay(1) != time.Second {
		t.Fatalf("unexpected initial delay: %s", retryDelay(1))
	}
	if retryDelay(100) != 128*time.Second {
		t.Fatalf("unexpected bounded delay: %s", retryDelay(100))
	}
}

func TestCompletedReceiptRequiresTerminalSuccess(t *testing.T) {
	requestID := "10000000-0000-4000-8000-000000000001"
	for _, status := range []string{"pending", "processing", "retry"} {
		completed, err := completedReceipt(json.RawMessage(`{"request_id":"`+requestID+`","status":"`+status+`"}`), requestID)
		if err != nil || completed {
			t.Fatalf("status %s: completed=%v err=%v", status, completed, err)
		}
	}
	completed, err := completedReceipt(json.RawMessage(`{"request_id":"`+requestID+`","status":"completed"}`), requestID)
	if err != nil || !completed {
		t.Fatalf("completed receipt: completed=%v err=%v", completed, err)
	}
	if _, err := completedReceipt(json.RawMessage(`{"request_id":"`+requestID+`","status":"failed"}`), requestID); err == nil {
		t.Fatal("failed downstream receipt was accepted")
	}
	if _, err := completedReceipt(json.RawMessage(`{"request_id":"20000000-0000-4000-8000-000000000002","status":"completed"}`), requestID); err == nil {
		t.Fatal("mismatched request receipt was accepted")
	}
}

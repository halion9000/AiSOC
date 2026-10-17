package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beenuar/aisoc/services/ingest/internal/config"
)

// The 413 for an oversized batch printed string(rune(max)), a single Unicode character, instead of the number.
func TestOversizedBatchMessageNamesTheLimitAsANumber(t *testing.T) {
	cfg := &config.Config{TenantHeaderKey: "X-Tenant-ID", MaxBatchSize: 3}
	h := New(nil, nil, cfg)
	body := `{"connector_id":"c","connector_type":"t","events":[{},{},{},{}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/ingest", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "t1")
	rec := httptest.NewRecorder()
	h.IngestEvents(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "maximum of 3") {
		t.Fatalf("message should name the limit as a number, got %q", rec.Body.String())
	}
}

// /v1/ingest decoded an unbounded request body into memory.
func TestIngestRefusesAnOversizedBody(t *testing.T) {
	cfg := &config.Config{TenantHeaderKey: "X-Tenant-ID", MaxBatchSize: 1000}
	h := New(nil, nil, cfg)
	huge := `{"connector_id":"c","connector_type":"t","events":[{"x":"` + strings.Repeat("a", maxIngestBodyBytes+1024) + `"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/ingest", strings.NewReader(huge))
	req.Header.Set("X-Tenant-ID", "t1")
	rec := httptest.NewRecorder()
	h.IngestEvents(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 for a body over %d bytes", rec.Code, maxIngestBodyBytes)
	}
}

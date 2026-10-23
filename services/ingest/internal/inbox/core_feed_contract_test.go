package inbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// What CORE pushes for each alert (recorded by CORE's tests in docs/contracts/core-feed/generic-json.json, copied to services/api/tests/fixtures/core_feed/ by
// `node scripts/sync-contracts.mjs`) goes through the real generic-json template. The point: a field CORE sends under a name the template does not read is silently dropped
// (an alert without its incident id could never be matched to the vendor closing it, and an alert without a hostname has no entity), so every field the alert needs must come out.

type pushRecording struct {
	Route  string           `json:"route"`
	Method string           `json:"method"`
	Body   []map[string]any `json:"body"`
}

func TestGenericJSONTemplateReadsWhatCoreActuallyPushes(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "api", "tests", "fixtures", "core_feed", "generic-json.json"))
	if err != nil {
		t.Skipf("no recorded CORE push (run `node scripts/sync-contracts.mjs` in the CORE repository): %v", err)
	}
	var rec pushRecording
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("the recorded push is not valid JSON: %v", err)
	}
	if rec.Route != "generic-json" || len(rec.Body) == 0 {
		t.Fatalf("unexpected recording: route %q with %d records", rec.Route, len(rec.Body))
	}
	reg := NewRegistry()
	if err := reg.Load(filepath.Join("..", "normalizer", "templates")); err != nil {
		t.Fatalf("loading the templates: %v", err)
	}
	tmpl, err := reg.Get("generic-json")
	if err != nil {
		t.Fatalf("the generic-json template: %v", err)
	}

	const receivedAt = "2030-01-01T00:00:00Z"
	for _, record := range rec.Body {
		finding, _ := record["finding"].(map[string]any)
		uid, _ := finding["uid"].(string)
		out := tmpl.Apply(record, "tenant-1", "connector-1", receivedAt)

		if got := getNestedString(out, "finding.uid"); got != uid {
			t.Errorf("%s: the incident id did not reach finding.uid (got %q)", uid, got)
		}
		if got := getNestedString(out, "finding.title"); got != finding["title"] {
			t.Errorf("%s: the title did not reach finding.title (got %q)", uid, got)
		}
		if got := getNestedString(out, "time"); got == receivedAt || got == "" {
			t.Errorf("%s: the alert's own time was not used (got %q)", uid, got)
		}
		if id, _ := out["severity_id"].(int); id < 1 {
			t.Errorf("%s: severity %q was not understood (severity_id %v)", uid, record["severity"], out["severity_id"])
		}
		if getNestedString(out, "message") == "" {
			t.Errorf("%s: the message is missing", uid)
		}
		if host, ok := record["hostname"].(string); ok {
			if got := getNestedString(out, "device.name"); got != host {
				t.Errorf("%s: the hostname did not reach device.name (got %q)", uid, got)
			}
		}
		if user, ok := record["username"].(string); ok {
			if got := getNestedString(out, "actor.user.name"); got != user {
				t.Errorf("%s: the username did not reach actor.user.name (got %q)", uid, got)
			}
		}
		if ip, ok := record["src_ip"].(string); ok {
			if got := getNestedString(out, "src_endpoint.ip"); got != ip {
				t.Errorf("%s: the source address did not reach src_endpoint.ip (got %q)", uid, got)
			}
		}
		if _, ok := record["context"]; ok && getNested(out, "unmapped.context") == nil {
			t.Errorf("%s: the context did not reach unmapped.context", uid)
		}
	}
}

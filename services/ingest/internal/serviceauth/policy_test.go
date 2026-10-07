package serviceauth

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The routes of services/ingest/internal/server/server.go, written out by hand with how each must be treated. The test below also reads
// server.go and fails if it declares a route that is not listed here, so a new route cannot be added without someone classifying it.
var ingestRoutes = map[string]bool{ // full path -> exempt from the token
	"/health":                          true,
	"/metrics":                         true,
	"/v1/ingest":                       false,
	"/v1/ingest/batch":                 false,
	"/v1/ingest/k8s-audit/{tenant_id}": true,
	"/v1/inbox/cef":                    true,
	"/v1/inbox/hec":                    true,
	"/v1/inbox/email/{token}":          true,
	"/v1/inbox/{token}":                true,
	"/v1/graph_ws/stream":              false,
}

func concretise(p string) string {
	return regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(p, "abc123")
}

func TestIngestPolicyClassifiesEveryRoute(t *testing.T) {
	opts := IngestOptions()
	for route, wantExempt := range ingestRoutes {
		if got := opts.Exempt(concretise(route)); got != wantExempt {
			t.Errorf("%s: exempt=%v, want %v", route, got, wantExempt)
		}
	}
}

func TestNewIngestRoutesAreProtectedByDefault(t *testing.T) {
	opts := IngestOptions()
	for _, p := range []string{"/v1/anything-new", "/v1/ingest/other", "/v1/ingest/k8s-audit", "/v1/admin", "/debug/pprof/", "/"} {
		if opts.Exempt(p) {
			t.Errorf("%s must need the token", p)
		}
	}
}

func TestEveryRouteDeclaredInServerGoIsClassified(t *testing.T) {
	src, err := os.ReadFile("../server/server.go")
	if err != nil {
		t.Skip("server.go not alongside (isolated run): " + err.Error())
	}
	found := regexp.MustCompile(`r\.(?:Get|Post|Put|Patch|Delete|Handle)\(\s*"(/[^"]*)"`).FindAllStringSubmatch(string(src), -1)
	if len(found) < 8 {
		t.Fatalf("the route scan found only %d routes: it is stale", len(found))
	}
	for _, m := range found {
		literal, matched := m[1], false
		for full := range ingestRoutes {
			if strings.HasSuffix(full, literal) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("server.go declares %q, which ingestRoutes does not classify: decide whether it needs the token", literal)
		}
	}
	if !strings.Contains(string(src), "serviceauth.Protect(") {
		t.Error("server.go does not wrap its router with serviceauth.Protect")
	}
}

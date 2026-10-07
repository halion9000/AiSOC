package serviceauth

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

var enrichmentRoutes = map[string]bool{ // full path -> exempt from the token
	"/health":      true,
	"/enrich":      false,
	"/enrich/bulk": false,
}

func TestEnrichmentPolicyClassifiesEveryRoute(t *testing.T) {
	opts := EnrichmentOptions()
	for route, wantExempt := range enrichmentRoutes {
		if got := opts.Exempt(route); got != wantExempt {
			t.Errorf("%s: exempt=%v, want %v", route, got, wantExempt)
		}
	}
	for _, p := range []string{"/enrich/other", "/healthz", "/health/x", "/", "/admin"} {
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
	if len(found) < 3 {
		t.Fatalf("the route scan found only %d routes: it is stale", len(found))
	}
	for _, m := range found {
		if _, ok := enrichmentRoutes[m[1]]; !ok {
			t.Errorf("server.go declares %q, which enrichmentRoutes does not classify: decide whether it needs the token", m[1])
		}
	}
	if !strings.Contains(string(src), "serviceauth.Protect(") {
		t.Error("server.go does not wrap its router with serviceauth.Protect")
	}
}

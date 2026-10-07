// Package serviceauth protects a service's HTTP API with a bearer token.
//
// Why. The ingest and enrichment services answered every request with no authentication: ingest took the tenant from an X-Tenant-ID
// header and accepted events for ANY tenant, and enrichment spends commercial threat-intel vendor quota for anyone able to reach it. Their
// callers (the API, the connectors service, osquery-tls) now send "Authorization: Bearer <token>".
//
// Default deny. Every path needs the token unless the service's Options exempt it by name, so a route added later is protected without
// anyone remembering to protect it. Exemptions are for health/metrics and for routes that carry their own credential.
//
// Fail closed. With no token configured, only a development environment runs open (so a local stack keeps working); anything else
// answers 503. An unset environment variable means a plain local run; set-but-empty or unrecognised is NOT development, because a
// mistake must fail closed. The environment is read per request so a redeploy or a test can change it.
//
// Only the standard library is used on purpose: this package is wired in with one line and is tested in isolation.
package serviceauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

// Options describes one service's policy.
type Options struct {
	ServiceName    string   // used in messages, e.g. "ingest"
	TokenEnv       string   // environment variable holding the bearer token
	EnvironmentEnv string   // environment variable naming the environment (development, production, ...)
	ExemptPaths    []string // exact paths that need no token (health, metrics)
	ExemptPrefixes []string // path prefixes whose routes carry their own credential
}

var developmentEnvironments = map[string]bool{"development": true, "dev": true, "local": true, "test": true}

// IsDevelopment reports whether the named environment variable describes a local development run.
func IsDevelopment(envName string) bool {
	raw, set := os.LookupEnv(envName)
	if !set {
		return true
	}
	return developmentEnvironments[strings.ToLower(strings.TrimSpace(raw))]
}

// Exempt reports whether a request path needs no token. A path containing empty, "." or ".." segments is never exempt: the router may
// resolve it differently from a prefix match (for example /v1/inbox/../ingest must not ride on the /v1/inbox/ exemption).
func (o Options) Exempt(p string) bool {
	if p == "" || p[0] != '/' || strings.Contains(p, "//") || strings.Contains(p, "/./") || strings.Contains(p, "/../") ||
		strings.HasSuffix(p, "/.") || strings.HasSuffix(p, "/..") {
		return false
	}
	for _, exact := range o.ExemptPaths {
		if p == exact {
			return true
		}
	}
	for _, prefix := range o.ExemptPrefixes {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

func bearerMatches(header, token string) bool {
	scheme, value, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	// Hash both sides so the comparison is constant-time AND independent of the lengths.
	presented := sha256.Sum256([]byte(value))
	expected := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(presented[:], expected[:]) == 1
}

func writeError(w http.ResponseWriter, status int, message string, challenge bool) {
	w.Header().Set("Content-Type", "application/json")
	if challenge {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// Protect wraps next so that every request needs the service token, except what Options exempt. CORS preflight (OPTIONS) is passed
// through: browsers send it without credentials by specification and it carries no data. The ResponseWriter is passed through
// untouched, so handlers that hijack the connection (WebSocket upgrades) keep working.
func Protect(next http.Handler, opts Options) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions || opts.Exempt(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		token := strings.TrimSpace(os.Getenv(opts.TokenEnv))
		if token == "" {
			if IsDevelopment(opts.EnvironmentEnv) {
				next.ServeHTTP(w, r)
				return
			}
			writeError(w, http.StatusServiceUnavailable, opts.ServiceName+" service auth is not configured", false)
			return
		}
		if !bearerMatches(r.Header.Get("Authorization"), token) {
			writeError(w, http.StatusUnauthorized, "invalid or missing service token", true)
			return
		}
		next.ServeHTTP(w, r)
	})
}

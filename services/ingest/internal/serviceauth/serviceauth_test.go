package serviceauth

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testToken = "service-token-123"

var testOptions = Options{
	ServiceName:    "svc",
	TokenEnv:       "TEST_SVC_TOKEN",
	EnvironmentEnv: "TEST_SVC_ENVIRONMENT",
	ExemptPaths:    []string{"/health", "/metrics"},
	ExemptPrefixes: []string{"/v1/inbox/"},
}

// Compile-time proof that Protect accepts and returns what a router and http.Server use.
var _ http.Handler = Protect(http.NewServeMux(), Options{})

func call(t *testing.T, method, target string, headers map[string]string) (int, string, int) {
	t.Helper()
	reached := 0
	h := Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		w.WriteHeader(http.StatusOK)
	}), testOptions)
	req := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String(), reached
}

func configure(t *testing.T, token string, environment *string) {
	t.Helper()
	t.Setenv("TEST_SVC_TOKEN", token)
	if environment == nil {
		// t.Setenv has no "unset": clear it and restore afterwards so the variable is genuinely absent.
		t.Setenv("TEST_SVC_ENVIRONMENT", "x")
		unsetForTest(t, "TEST_SVC_ENVIRONMENT")
		return
	}
	t.Setenv("TEST_SVC_ENVIRONMENT", *environment)
}

func str(s string) *string { return &s }

func TestNoCredentialsIsRefusedAndTheHandlerIsNeverReached(t *testing.T) {
	configure(t, testToken, str("production"))
	code, body, reached := call(t, "POST", "/v1/ingest", nil)
	if code != http.StatusUnauthorized || reached != 0 || !strings.Contains(body, "invalid or missing service token") {
		t.Fatalf("got %d reached=%d body=%q", code, reached, body)
	}
}

func TestTheRightTokenIsAccepted(t *testing.T) {
	configure(t, testToken, str("production"))
	for _, h := range []string{"Bearer " + testToken, "bearer " + testToken, "BEARER " + testToken, "Bearer   " + testToken + "  "} {
		if code, _, reached := call(t, "POST", "/v1/ingest", map[string]string{"Authorization": h}); code != 200 || reached != 1 {
			t.Errorf("%q: got %d reached=%d", h, code, reached)
		}
	}
}

func TestOnlyTheExactTokenIsAccepted(t *testing.T) {
	configure(t, testToken, str("production"))
	for _, h := range []string{"Bearer " + testToken + "x", "Bearer " + testToken[:len(testToken)-1], "Bearer " + strings.Repeat("x", 500), "Basic " + testToken,
		testToken, "Bearer ", "Bearer", "", "Token " + testToken, "Bearer " + strings.ToUpper(testToken)} {
		if code, _, reached := call(t, "POST", "/v1/ingest", map[string]string{"Authorization": h}); code != 401 || reached != 0 {
			t.Errorf("%q: got %d reached=%d, want 401", h, code, reached)
		}
	}
}

func TestWithNoTokenAnythingButDevelopmentFailsClosed(t *testing.T) {
	for _, env := range []string{"production", "staging", "prod", "prodution", "", "  "} {
		configure(t, "", str(env))
		for _, headers := range []map[string]string{nil, {"Authorization": "Bearer " + testToken}} {
			code, body, reached := call(t, "POST", "/v1/ingest", headers)
			if code != http.StatusServiceUnavailable || reached != 0 || !strings.Contains(body, "auth is not configured") {
				t.Errorf("env %q: got %d reached=%d body=%q", env, code, reached, body)
			}
		}
	}
}

func TestAWhitespaceOnlyTokenCountsAsNotConfigured(t *testing.T) {
	configure(t, "   ", str("production"))
	if code, _, _ := call(t, "POST", "/v1/ingest", nil); code != http.StatusServiceUnavailable {
		t.Fatalf("got %d", code)
	}
}

func TestDevelopmentWithoutATokenStaysOpen(t *testing.T) {
	for _, env := range []*string{nil, str("development"), str("dev"), str("local"), str("test"), str("Development"), str(" DEV ")} {
		configure(t, "", env)
		if code, _, reached := call(t, "POST", "/v1/ingest", nil); code != 200 || reached != 1 {
			name := "<unset>"
			if env != nil {
				name = *env
			}
			t.Errorf("env %s: got %d reached=%d", name, code, reached)
		}
	}
}

func TestAConfiguredTokenIsEnforcedInDevelopmentToo(t *testing.T) {
	configure(t, testToken, str("development"))
	if code, _, _ := call(t, "POST", "/v1/ingest", nil); code != 401 {
		t.Fatalf("got %d", code)
	}
	if code, _, _ := call(t, "POST", "/v1/ingest", map[string]string{"Authorization": "Bearer " + testToken}); code != 200 {
		t.Fatalf("got %d", code)
	}
}

func TestExemptRoutesNeedNoTokenAndNoConfiguration(t *testing.T) {
	for _, env := range []string{"production", ""} {
		configure(t, "", str(env))
		for _, p := range []string{"/health", "/metrics", "/v1/inbox/abc", "/v1/inbox/email/abc"} {
			if code, _, reached := call(t, "POST", p, nil); code != 200 || reached != 1 {
				t.Errorf("env %q %s: got %d reached=%d", env, p, code, reached)
			}
		}
	}
}

func TestNearMissesOfTheExemptionsAreProtected(t *testing.T) {
	configure(t, testToken, str("production"))
	for _, p := range []string{"/healthz", "/health/", "/health/x", "/metrics/x", "/v1/inbox", "/v1/inboxx/abc", "/v1/ingest", "/", "/Health", "/V1/inbox/abc", "/v1/INBOX/abc"} {
		if code, _, reached := call(t, "POST", p, nil); code != 401 || reached != 0 {
			t.Errorf("%s: got %d reached=%d, want 401", p, code, reached)
		}
	}
}

func TestPathTricksCannotRideOnAnExemption(t *testing.T) {
	configure(t, testToken, str("production"))
	for _, p := range []string{"/v1/inbox/../ingest", "/v1/inbox/../../ingest", "/health/../v1/ingest", "//health", "/v1//inbox/abc", "/v1/inbox//abc", "/v1/inbox/./abc",
		"/v1/inbox/..", "/v1/inbox/abc/..", "/./health", "/health/."} {
		if testOptions.Exempt(p) {
			t.Errorf("%q must not be exempt", p)
		}
		if code, _, reached := call(t, "POST", p, nil); code != 401 || reached != 0 {
			t.Errorf("%q: got %d reached=%d, want 401", p, code, reached)
		}
	}
	// Targets httptest cannot even build as a request still must never count as exempt.
	for _, p := range []string{"health", "", "v1/inbox/abc", "*"} {
		if testOptions.Exempt(p) {
			t.Errorf("%q must not be exempt", p)
		}
	}
}

func TestCORSPreflightPassesWithoutCredentials(t *testing.T) {
	configure(t, testToken, str("production"))
	if code, _, reached := call(t, "OPTIONS", "/v1/ingest", nil); code != 200 || reached != 1 {
		t.Fatalf("got %d reached=%d", code, reached)
	}
	// ...but a real request to the same path is still protected
	if code, _, _ := call(t, "POST", "/v1/ingest", nil); code != 401 {
		t.Fatalf("got %d", code)
	}
}

func TestEveryMethodIsProtected(t *testing.T) {
	configure(t, testToken, str("production"))
	for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"} {
		if code, _, reached := call(t, m, "/v1/ingest", nil); code != 401 || reached != 0 {
			t.Errorf("%s: got %d reached=%d", m, code, reached)
		}
	}
}

func TestTheChallengeHeaderIsSetOn401(t *testing.T) {
	configure(t, testToken, str("production"))
	rec := httptest.NewRecorder()
	Protect(http.NotFoundHandler(), testOptions).ServeHTTP(rec, httptest.NewRequest("POST", "/v1/ingest", nil))
	if rec.Header().Get("WWW-Authenticate") != "Bearer" || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("headers: %v", rec.Header())
	}
}

// hijackWriter stands in for the real connection a WebSocket upgrade takes over.
type hijackWriter struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (h *hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	return nil, nil, nil
}

func TestTheResponseWriterIsPassedThroughSoWebSocketUpgradesStillWork(t *testing.T) {
	configure(t, testToken, str("production"))
	w := &hijackWriter{ResponseRecorder: httptest.NewRecorder()}
	h := Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("the wrapper hid the Hijacker interface: WebSocket upgrades would fail")
			return
		}
		_, _, _ = hj.Hijack()
	}), testOptions)
	req := httptest.NewRequest("GET", "/v1/graph_ws/stream", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	h.ServeHTTP(w, req)
	if !w.hijacked {
		t.Fatal("the handler never got to hijack the connection")
	}
}

func TestIsDevelopment(t *testing.T) {
	configure(t, "", nil)
	if !IsDevelopment("TEST_SVC_ENVIRONMENT") {
		t.Error("unset must be development")
	}
	for env, want := range map[string]bool{"development": true, "DEV": true, " local ": true, "test": true, "production": false, "": false, "  ": false, "prodution": false} {
		t.Setenv("TEST_SVC_ENVIRONMENT", env)
		if got := IsDevelopment("TEST_SVC_ENVIRONMENT"); got != want {
			t.Errorf("%q: got %v want %v", env, got, want)
		}
	}
}

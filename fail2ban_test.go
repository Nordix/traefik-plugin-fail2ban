package traefik_plugin_fail2ban //nolint:revive,stylecheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

// recordingHandler is a minimal http.Handler used as the "next" handler in
// tests. It records whether it was invoked and returns a fixed status code.
type recordingHandler struct {
	called     bool
	statusCode int
}

func (h *recordingHandler) ServeHTTP(responseWriter http.ResponseWriter, _ *http.Request) {
	h.called = true
	responseWriter.WriteHeader(h.statusCode)
}

// newTestPlugin builds a plugin instance from the default config, allowing the
// caller to tweak the config before the plugin is created.
func newTestPlugin(t *testing.T, next http.Handler, configure func(*Config)) http.Handler {
	t.Helper()

	config := CreateConfig()
	if configure != nil {
		configure(config)
	}

	plugin, err := New(context.Background(), next, config, "test-fail2ban")
	if err != nil {
		t.Fatalf("failed to create plugin: %v", err)
	}

	return plugin
}

// doRequest issues a GET request for the given path from the given remote
// address and returns the recorded response.
func doRequest(handler http.Handler, remoteAddr, path string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.RemoteAddr = remoteAddr
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	return recorder
}

func TestParseURLRegexps(t *testing.T) {
	// The second pattern is invalid and must be skipped rather than panic.
	regexps := parseURLRegexps([]string{"^/computer/", "["})

	if len(regexps) != 1 {
		t.Fatalf("expected 1 valid regexp (invalid pattern skipped), got %d", len(regexps))
	}

	if !regexps[0].MatchString("/computer/api") {
		t.Error("compiled regexp did not match the expected URL")
	}
}

func TestMatchURLRegexp(t *testing.T) {
	plugin := &Fail2Ban{}
	regexps := []*regexp.Regexp{
		regexp.MustCompile("^/allowed"),
		regexp.MustCompile("^/also-allowed"),
	}

	if reg := plugin.matchURLRegexp(regexps, "/allowed/thing"); reg == nil {
		t.Error("expected a match for /allowed/thing")
	}

	if reg := plugin.matchURLRegexp(regexps, "/nope"); reg != nil {
		t.Errorf("expected no match for /nope, got %q", reg.String())
	}

	if reg := plugin.matchURLRegexp(nil, "/allowed"); reg != nil {
		t.Error("expected no match against an empty list")
	}
}

func TestServeHTTPAllowURLPassesThrough(t *testing.T) {
	next := &recordingHandler{statusCode: http.StatusOK}
	plugin := newTestPlugin(t, next, func(c *Config) {
		c.URLRegexp.Allow = []string{"^/computer/"}
	})

	recorder := doRequest(plugin, "203.0.113.1:34567", "/computer/api/status")

	if !next.called {
		t.Error("expected allowed request to be passed to the next handler")
	}

	if recorder.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestServeHTTPDenyURLIsBlocked(t *testing.T) {
	next := &recordingHandler{statusCode: http.StatusOK}
	plugin := newTestPlugin(t, next, func(c *Config) {
		c.URLRegexp.Deny = []string{`^/wp-login\.php`}
	})

	recorder := doRequest(plugin, "203.0.113.2:34567", "/wp-login.php")

	if next.called {
		t.Error("expected denied request NOT to reach the next handler")
	}

	if recorder.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, recorder.Code)
	}
}

func TestServeHTTPAllowTakesPrecedenceOverDeny(t *testing.T) {
	next := &recordingHandler{statusCode: http.StatusOK}
	plugin := newTestPlugin(t, next, func(c *Config) {
		c.URLRegexp.Allow = []string{"^/shared"}
		c.URLRegexp.Deny = []string{"^/shared"}
	})

	recorder := doRequest(plugin, "203.0.113.3:34567", "/shared/resource")

	if !next.called {
		t.Error("expected request matching both allow and deny to be allowed")
	}

	if recorder.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestServeHTTPNoURLRulesPassThrough(t *testing.T) {
	next := &recordingHandler{statusCode: http.StatusOK}
	plugin := newTestPlugin(t, next, nil)

	recorder := doRequest(plugin, "203.0.113.4:34567", "/anything")

	if !next.called {
		t.Error("expected request to pass through when no URL rules are configured")
	}

	if recorder.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestServeHTTPDenyURLCountsTowardsBan(t *testing.T) {
	next := &recordingHandler{statusCode: http.StatusOK}
	plugin := newTestPlugin(t, next, func(c *Config) {
		c.URLRegexp.Deny = []string{"^/wp-login"}
		c.Rules.MaxRetries = 2
	})

	remoteAddr := "203.0.113.5:34567"

	// Two denied requests reach the ban threshold.
	for i := 0; i < 2; i++ {
		recorder := doRequest(plugin, remoteAddr, "/wp-login")
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("denied request %d: expected status %d, got %d", i+1, http.StatusForbidden, recorder.Code)
		}
	}

	// The IP is now banned, so even an unrelated path is blocked and never
	// reaches the backend.
	next.called = false
	recorder := doRequest(plugin, remoteAddr, "/unrelated")

	if next.called {
		t.Error("expected banned IP request NOT to reach the next handler")
	}

	if recorder.Code != http.StatusForbidden {
		t.Errorf("expected banned request status %d, got %d", http.StatusForbidden, recorder.Code)
	}
}

func TestServeHTTPAllowedURLNotCountedTowardsBan(t *testing.T) {
	next := &recordingHandler{statusCode: http.StatusOK}
	plugin := newTestPlugin(t, next, func(c *Config) {
		c.URLRegexp.Allow = []string{"^/widget"}
		c.Rules.MaxRetries = 2
	})

	remoteAddr := "203.0.113.6:34567"

	// Repeated hits on the allowed path must never accumulate strikes.
	for i := 0; i < 5; i++ {
		recorder := doRequest(plugin, remoteAddr, "/widget/status")
		if recorder.Code != http.StatusOK {
			t.Fatalf("allowed request %d: expected status %d, got %d", i+1, http.StatusOK, recorder.Code)
		}
	}

	// The IP must not be banned: a normal request still reaches the backend.
	next.called = false
	recorder := doRequest(plugin, remoteAddr, "/other")

	if !next.called {
		t.Error("expected non-banned IP request to reach the next handler")
	}

	if recorder.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

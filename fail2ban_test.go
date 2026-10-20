package traefik_plugin_fail2ban //nolint:revive,stylecheck

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
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

// TestIncrementTimesSeenIsAtomic guards the fix for the previous
// Store(Load()+1) implementation, which silently dropped increments under
// concurrency and therefore delayed bans past maxRetries.
func TestIncrementTimesSeenIsAtomic(t *testing.T) {
	entry := &CacheEntry{}

	var waitGroup sync.WaitGroup

	for i := 0; i < 100; i++ {
		waitGroup.Add(1)

		go func() {
			defer waitGroup.Done()

			for j := 0; j < 100; j++ {
				entry.IncrementTimesSeen()
			}
		}()
	}

	waitGroup.Wait()

	if got := entry.GetTimesSeen(); got != 10000 {
		t.Errorf("expected 10000 increments, got %d", got)
	}
}

func TestRecordStrikeCountsPerPathAndStatus(t *testing.T) {
	entry := &CacheEntry{}

	if count, tracked := entry.RecordStrike("/a", http.StatusNotFound); !tracked || count != 1 {
		t.Errorf("first strike: got count=%d tracked=%v, want 1/true", count, tracked)
	}

	if count, tracked := entry.RecordStrike("/a", http.StatusNotFound); !tracked || count != 2 {
		t.Errorf("second strike: got count=%d tracked=%v, want 2/true", count, tracked)
	}

	// Same path, different status is a distinct counter.
	if count, tracked := entry.RecordStrike("/a", http.StatusUnauthorized); !tracked || count != 1 {
		t.Errorf("different status: got count=%d tracked=%v, want 1/true", count, tracked)
	}

	strikes, truncated := entry.getStrikes()
	if truncated {
		t.Error("did not expect the cap to be reported as hit")
	}

	if len(strikes) != 2 {
		t.Errorf("expected 2 distinct keys, got %d", len(strikes))
	}
}

func TestRecordStrikeCapsDistinctKeys(t *testing.T) {
	entry := &CacheEntry{}

	for i := 0; i < maxTrackedStrikesKeys; i++ {
		if _, tracked := entry.RecordStrike(fmt.Sprintf("/path-%d", i), http.StatusNotFound); !tracked {
			t.Fatalf("key %d should have been tracked", i)
		}
	}

	if _, tracked := entry.RecordStrike("/one-too-many", http.StatusNotFound); tracked {
		t.Error("expected the key past the cap to be rejected")
	}

	strikes, truncated := entry.getStrikes()
	if len(strikes) != maxTrackedStrikesKeys {
		t.Errorf("expected %d tracked keys, got %d", maxTrackedStrikesKeys, len(strikes))
	}

	if !truncated {
		t.Error("expected truncated to be reported once the cap was exceeded")
	}

	// An already-tracked key must keep counting after the cap is reached.
	if count, tracked := entry.RecordStrike("/path-0", http.StatusNotFound); !tracked || count != 2 {
		t.Errorf("existing key after cap: got count=%d tracked=%v, want 2/true", count, tracked)
	}
}

func TestGetStrikesReturnsACopy(t *testing.T) {
	entry := &CacheEntry{}
	entry.RecordStrike("/a", http.StatusNotFound)

	snapshot, _ := entry.getStrikes()
	snapshot[strikeKey{Path: "/injected", Status: 500}] = 99

	if again, _ := entry.getStrikes(); len(again) != 1 {
		t.Errorf("mutating the snapshot changed the entry: got %d keys, want 1", len(again))
	}
}

func TestFormatStrikes(t *testing.T) {
	if got := formatStrikes(nil); got != "" {
		t.Errorf("expected empty string for no strikes, got %q", got)
	}

	strikes := map[strikeKey]uint32{
		{Path: "/b", Status: 404}: 1,
		{Path: "/a", Status: 404}: 1,
		{Path: "/c", Status: 500}: 5,
		{Path: "/a", Status: 401}: 1,
	}

	// Descending count, then path ascending, then status ascending.
	want := "/c:500=5,/a:401=1,/a:404=1,/b:404=1"
	if got := formatStrikes(strikes); got != want {
		t.Errorf("formatStrikes() = %q, want %q", got, want)
	}
}

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "drops the query string", raw: "/api/job?token=secret", want: "/api/job"},
		{name: "empty path becomes root", raw: "http://example.com", want: "/"},
		{name: "keeps control bytes percent-encoded", raw: "/a%0Ab", want: "/a%0Ab"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := url.Parse(test.raw)
			if err != nil {
				t.Fatalf("failed to parse %q: %v", test.raw, err)
			}

			if got := sanitizePath(parsed); got != test.want {
				t.Errorf("sanitizePath(%q) = %q, want %q", test.raw, got, test.want)
			}
		})
	}
}

func TestSanitizePathTruncatesLongPaths(t *testing.T) {
	parsed, err := url.Parse("/" + strings.Repeat("a", 200))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	got := sanitizePath(parsed)
	if len(got) != maxLoggedPathLength+len("...") {
		t.Errorf("expected length %d, got %d", maxLoggedPathLength+len("..."), len(got))
	}

	if !strings.HasSuffix(got, "...") {
		t.Errorf("expected a truncation marker, got %q", got)
	}
}

func TestIsDebugLevel(t *testing.T) {
	tests := map[string]bool{
		"DEBUG":    true,
		"debug":    true,
		"INFO":     false,
		"ERROR":    false,
		"":         false,
		"nonsense": false,
	}

	for level, want := range tests {
		if got := isDebugLevel(level); got != want {
			t.Errorf("isDebugLevel(%q) = %v, want %v", level, got, want)
		}
	}
}

func TestServeHTTPRecordsStrikesPerPathAtDebugLevel(t *testing.T) {
	next := &recordingHandler{statusCode: http.StatusNotFound}
	handler := newTestPlugin(t, next, func(c *Config) {
		c.LogLevel = "DEBUG"
		// High enough that the ban never interferes with the counting.
		c.Rules.MaxRetries = 100
	})

	plugin, ok := handler.(*Fail2Ban)
	if !ok {
		t.Fatalf("expected *Fail2Ban, got %T", handler)
	}

	doRequest(handler, "203.0.113.7:34567", "/a?token=secret")
	doRequest(handler, "203.0.113.7:34567", "/a")
	doRequest(handler, "203.0.113.7:34567", "/b")

	entry := plugin.cache.GetEntry("203.0.113.7")
	if entry == nil {
		t.Fatal("expected a cache entry for the client")
	}

	strikes, truncated := entry.getStrikes()
	if truncated {
		t.Error("did not expect the cap to be hit")
	}

	// Both /a requests collapse onto one key: the query string is dropped.
	if got := strikes[strikeKey{Path: "/a", Status: http.StatusNotFound}]; got != 2 {
		t.Errorf("expected 2 strikes for /a, got %d", got)
	}

	if got := strikes[strikeKey{Path: "/b", Status: http.StatusNotFound}]; got != 1 {
		t.Errorf("expected 1 strike for /b, got %d", got)
	}

	if got, want := formatStrikes(strikes), "/a:404=2,/b:404=1"; got != want {
		t.Errorf("formatStrikes() = %q, want %q", got, want)
	}
}

func TestServeHTTPDoesNotRecordStrikesBelowDebugLevel(t *testing.T) {
	next := &recordingHandler{statusCode: http.StatusNotFound}
	handler := newTestPlugin(t, next, func(c *Config) {
		c.LogLevel = "INFO"
		c.Rules.MaxRetries = 100
	})

	plugin, ok := handler.(*Fail2Ban)
	if !ok {
		t.Fatalf("expected *Fail2Ban, got %T", handler)
	}

	doRequest(handler, "203.0.113.8:34567", "/a")

	entry := plugin.cache.GetEntry("203.0.113.8")
	if entry == nil {
		t.Fatal("expected a cache entry for the client")
	}

	// The ban counter still moves; only the per-path detail is suppressed.
	if got := entry.GetTimesSeen(); got != 1 {
		t.Errorf("expected timesSeen to be 1, got %d", got)
	}

	if strikes, _ := entry.getStrikes(); len(strikes) != 0 {
		t.Errorf("expected no strike tracking at INFO level, got %d keys", len(strikes))
	}
}

func TestServeHTTPDeniedURLRecordsStrike(t *testing.T) {
	next := &recordingHandler{statusCode: http.StatusOK}
	handler := newTestPlugin(t, next, func(c *Config) {
		c.LogLevel = "DEBUG"
		c.URLRegexp.Deny = []string{`^/wp-login\.php`}
		c.Rules.MaxRetries = 100
	})

	plugin, ok := handler.(*Fail2Ban)
	if !ok {
		t.Fatalf("expected *Fail2Ban, got %T", handler)
	}

	doRequest(handler, "203.0.113.9:34567", "/wp-login.php")

	entry := plugin.cache.GetEntry("203.0.113.9")
	if entry == nil {
		t.Fatal("expected a cache entry for the client")
	}

	// A deny-rule hit is attributed to the plugin's own error code.
	strikes, _ := entry.getStrikes()
	if got := strikes[strikeKey{Path: "/wp-login.php", Status: http.StatusForbidden}]; got != 1 {
		t.Errorf("expected 1 strike for the denied path, got %d", got)
	}
}

// TestServeHTTPBanLogIncludesStrikes drives the ban through response-code
// strikes rather than a deny rule, which is the only path that reaches
// logBan. It therefore also exercises the variadic field spread, which the
// Yaegi interpreter handles differently from the compiler.
func TestServeHTTPBanLogIncludesStrikes(t *testing.T) {
	next := &recordingHandler{statusCode: http.StatusNotFound}
	handler := newTestPlugin(t, next, func(c *Config) {
		c.LogLevel = "DEBUG"
		c.Rules.MaxRetries = 2
	})

	plugin, ok := handler.(*Fail2Ban)
	if !ok {
		t.Fatalf("expected *Fail2Ban, got %T", handler)
	}

	remoteAddr := "203.0.113.10:34567"

	// Two 404s reach the threshold without tripping the ban check yet.
	for i := 0; i < 2; i++ {
		if recorder := doRequest(handler, remoteAddr, "/a"); recorder.Code != http.StatusNotFound {
			t.Fatalf("request %d: expected status %d, got %d", i+1, http.StatusNotFound, recorder.Code)
		}
	}

	entry := plugin.cache.GetEntry("203.0.113.10")
	if entry == nil {
		t.Fatal("expected a cache entry for the client")
	}

	if got, want := formatStrikes(mustStrikes(t, entry)), "/a:404=2"; got != want {
		t.Errorf("formatStrikes() = %q, want %q", got, want)
	}

	// The third request crosses the threshold: logBan runs, then the ban is
	// issued and the request is blocked before reaching the backend.
	next.called = false

	recorder := doRequest(handler, remoteAddr, "/b")
	if next.called {
		t.Error("expected the banned request NOT to reach the next handler")
	}

	if recorder.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, recorder.Code)
	}

	if !entry.IsBanned() {
		t.Error("expected the entry to be banned")
	}
}

// mustStrikes returns the entry's strike counters, failing if the cap was hit.
func mustStrikes(t *testing.T, entry *CacheEntry) map[strikeKey]uint32 {
	t.Helper()

	strikes, truncated := entry.getStrikes()
	if truncated {
		t.Fatal("did not expect the strike cap to be hit")
	}

	return strikes
}

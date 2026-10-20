// Package traefik_plugin_fail2ban plugin for traefik reverse proxy.
package traefik_plugin_fail2ban //nolint:revive,stylecheck

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zerodha/logf"
)

type configIPSpec struct {
	IP []string `yaml:"ip"`
}

// Config plugin configuration.
type Config struct {
	Enabled       bool            `yaml:"enabled"`
	AlwaysAllowed configIPSpec    `yaml:"alwaysAllowed"`
	AlwaysDenied  configIPSpec    `yaml:"alwaysDenied"`
	LogLevel      string          `yaml:"logLevel"`
	URLRegexp     configURLRegexp `yaml:"urlRegexp"`
	Rules         configRules     `yaml:"rules"`
}

type configURLRegexp struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

type configRules struct {
	FindTime   string         `yaml:"findTime"`
	BanTime    string         `yaml:"banTime"`
	MaxRetries uint32         `yaml:"maxRetries"`
	Response   configResponse `yaml:"response"`
}

type configResponse struct {
	StatusCodes []string `yaml:"statusCodes"`
	ErrorCode   int      `yaml:"errorCode"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Enabled:       true,
		AlwaysAllowed: configIPSpec{},
		AlwaysDenied:  configIPSpec{},
		LogLevel:      "INFO",
		URLRegexp:     configURLRegexp{},
		Rules: configRules{
			FindTime:   "10m",
			BanTime:    "3h",
			MaxRetries: 4,
			Response: configResponse{
				StatusCodes: strings.Split("400-499", ","),
				ErrorCode:   http.StatusForbidden,
			},
		},
	}
}

type responseRules struct {
	StatusCode *regexp.Regexp
}

// Fail2Ban plugin data structure.
type Fail2Ban struct {
	next                http.Handler
	name                string
	cache               *Cache
	logger              *logf.Logger
	enabled             bool
	staticAllowedIPNets []*net.IPNet
	staticDeniedIPNets  []*net.IPNet
	allowedURLRegexps   []*regexp.Regexp
	deniedURLRegexps    []*regexp.Regexp
	findTime            time.Duration
	banTime             time.Duration
	maxRetries          uint32
	responseRules       responseRules
	errorCode           int
	trackStrikes        bool
}

func parseConfigIPList(specs []string) []*net.IPNet {
	parsedIPNets := make([]*net.IPNet, 0, 10)

	for _, spec := range specs {
		if !strings.Contains(spec, "/") {
			if strings.Contains(spec, ":") {
				spec = fmt.Sprintf("%s/64", spec)
			} else {
				spec = fmt.Sprintf("%s/32", spec)
			}
		}
		_, ipNet, err := net.ParseCIDR(spec)
		if err != nil {
			fmt.Printf("Error: failed to parse IP network %q: %+v\n", spec, err)
			continue
		}

		parsedIPNets = append(parsedIPNets, ipNet)
	}

	return parsedIPNets
}

func parseURLRegexps(specs []string) []*regexp.Regexp {
	parsedRegexps := make([]*regexp.Regexp, 0, len(specs))

	for _, spec := range specs {
		reg, err := regexp.Compile(spec)
		if err != nil {
			fmt.Printf("Error: failed to compile URL regexp %q: %+v\n", spec, err)
			continue
		}

		parsedRegexps = append(parsedRegexps, reg)
	}

	return parsedRegexps
}

func parseDuration(spec string, fallback time.Duration) time.Duration {
	val, err := time.ParseDuration(spec)
	if err != nil {
		return fallback
	}

	return val
}

func removeDuplicates[T string | int](sliceList []T) []T {
	allKeys := make(map[T]bool)
	var list []T
	for _, item := range sliceList {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

func parseResponseRules(config configResponse) responseRules {
	var statusCodes []int
	for _, val := range config.StatusCodes {
		if strings.Contains(val, "-") {
			r := strings.Split(val, "-")
			a, _ := strconv.Atoi(r[0])
			b, _ := strconv.Atoi(r[1])
			for i := a; i <= b; i++ {
				statusCodes = append(statusCodes, i)
			}
		} else {
			a, _ := strconv.Atoi(val)
			statusCodes = append(statusCodes, a)
		}
	}
	sort.Ints(statusCodes)
	statusCodes = removeDuplicates[int](statusCodes)
	cleanedStatusCodes := make([]string, 0, 100)
	for _, k := range statusCodes {
		cleanedStatusCodes = append(cleanedStatusCodes, strconv.Itoa(k))
	}

	statusCodesRegex := regexp.MustCompile(fmt.Sprintf("^(%s)$", strings.Join(cleanedStatusCodes, "|")))

	return responseRules{
		StatusCode: statusCodesRegex,
	}
}

// New creates a Fail2Ban plugin instance.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &Fail2Ban{
		next:                next,
		name:                name,
		cache:               NewCache(),
		logger:              NewLogger(config.LogLevel),
		enabled:             config.Enabled,
		staticAllowedIPNets: parseConfigIPList(config.AlwaysAllowed.IP),
		staticDeniedIPNets:  parseConfigIPList(config.AlwaysDenied.IP),
		allowedURLRegexps:   parseURLRegexps(config.URLRegexp.Allow),
		deniedURLRegexps:    parseURLRegexps(config.URLRegexp.Deny),
		findTime:            parseDuration(config.Rules.FindTime, 10*time.Minute),
		banTime:             parseDuration(config.Rules.BanTime, 3*time.Hour),
		maxRetries:          config.Rules.MaxRetries,
		responseRules:       parseResponseRules(config.Rules.Response),
		errorCode:           config.Rules.Response.ErrorCode,
		trackStrikes:        isDebugLevel(config.LogLevel),
	}, nil
}

// maxLoggedPathLength bounds the path recorded per strike.
const maxLoggedPathLength = 120

// sanitizePath reduces a request URL to a bounded, log-safe path. The query
// string is dropped deliberately: it routinely carries tokens and would
// explode the cardinality of the strike map. EscapedPath keeps any control
// bytes percent-encoded so they cannot break the log line.
func sanitizePath(requestURL *url.URL) string {
	path := requestURL.EscapedPath()
	if path == "" {
		path = "/"
	}

	if len(path) > maxLoggedPathLength {
		path = path[:maxLoggedPathLength] + "..."
	}

	return path
}

// formatStrikes renders strike counters into one deterministic field,
// "/a:404=3,/b:401=1", ordered by descending count.
func formatStrikes(strikes map[strikeKey]uint32) string {
	type pair struct {
		key   strikeKey
		count uint32
	}

	pairs := make([]pair, 0, len(strikes))
	for key, count := range strikes {
		pairs = append(pairs, pair{key: key, count: count})
	}

	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count != pairs[j].count {
			return pairs[i].count > pairs[j].count
		}

		if pairs[i].key.Path != pairs[j].key.Path {
			return pairs[i].key.Path < pairs[j].key.Path
		}

		return pairs[i].key.Status < pairs[j].key.Status
	})

	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, fmt.Sprintf("%s:%d=%d", p.key.Path, p.key.Status, p.count))
	}

	return strings.Join(parts, ",")
}

// logBan emits the ban log line, including the accumulated per-path strike
// counters when strike tracking is enabled. The counters are the reason the
// client was banned; the URL of the request that happens to trip this check is
// deliberately not logged, since it is not one of the offending requests.
func (a *Fail2Ban) logBan(entry *CacheEntry, remoteIP, host string) {
	fields := []any{"remoteIP", remoteIP, "maxRetries", a.maxRetries, "host", host, "banTime", a.banTime, "findTime", a.findTime, "phase", "check_request", "status", "denied"}

	if a.trackStrikes {
		strikes, truncated := entry.getStrikes()
		fields = append(fields, "strikes", formatStrikes(strikes), "strikesTruncated", truncated)
	}

	a.logger.Info("Client has been banned.", fields...)
}

// matchURLRegexp returns the first regexp in the list that matches the given
// URL, or nil if none match.
func (a *Fail2Ban) matchURLRegexp(regexps []*regexp.Regexp, url string) *regexp.Regexp {
	for _, reg := range regexps {
		if reg.MatchString(url) {
			return reg
		}
	}

	return nil
}

// handleAllowedURL passes the request through untracked if it matches an allow
// rule. It returns true if the request was handled and the caller should stop.
func (a *Fail2Ban) handleAllowedURL(responseWriter http.ResponseWriter, request *http.Request, remoteIP, requestURL string) bool {
	reg := a.matchURLRegexp(a.allowedURLRegexps, requestURL)
	if reg == nil {
		return false
	}

	a.logger.Info("Request URL matched allow rule. Access granted without counting.", "remoteIP", remoteIP, "url", requestURL, "regexp", reg.String(), "phase", "check_request", "status", "granted")
	a.next.ServeHTTP(responseWriter, request)

	return true
}

// handleDeniedURL blocks the request and registers a strike if it matches a
// deny rule. It returns true if the request was handled and the caller should stop.
func (a *Fail2Ban) handleDeniedURL(responseWriter http.ResponseWriter, entry *CacheEntry, remoteIP, requestURL, requestPath string) bool {
	reg := a.matchURLRegexp(a.deniedURLRegexps, requestURL)
	if reg == nil {
		return false
	}

	entry.IncrementTimesSeen()
	if entry.GetTimesSeen() >= a.maxRetries {
		entry.IssueBan()
	}

	if a.trackStrikes {
		entry.RecordStrike(requestPath, a.errorCode)
	}

	a.logger.Info("Request URL matched deny rule. Access denied.", "remoteIP", remoteIP, "url", requestURL, "regexp", reg.String(), "timesSeen", entry.GetTimesSeen(), "phase", "check_request", "status", "denied")
	responseWriter.WriteHeader(a.errorCode)

	return true
}

func (a *Fail2Ban) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {
	if !a.enabled {
		a.logger.Debug("Handler is not enabled. Skipping.", "phase", "accept_request")
		a.next.ServeHTTP(responseWriter, request)
		return
	}
	a.logger.Debug("Handler is enabled. Analyzing request.", "phase", "accept_request")

	remoteIP, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		a.logger.Error("Failed to detect remoteIP from request.RemoteAddr.", "request.RemoteAddr", request.RemoteAddr, "phase", "accept_request")
		responseWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	for _, ipNet := range a.staticDeniedIPNets {
		a.logger.Debug("Checking if remoteIP is in static denied Netmask.", "remoteIP", remoteIP, "netmask", ipNet, "phase", "check_request")
		if ipNet.Contains(net.ParseIP(remoteIP)) {
			a.logger.Info("RemoteIP was found in staticDeniedIPNets. Access Denied.", "remoteIP", remoteIP, "staticDeniedIPNets", a.staticDeniedIPNets, "phase", "check_request", "status", "denied")
			responseWriter.WriteHeader(a.errorCode)
			return
		}
	}

	for _, ipNet := range a.staticAllowedIPNets {
		a.logger.Debug("Checking if remoteIP is in static allowed Netmask.", "remoteIP", remoteIP, "netmask", ipNet, "phase", "check_request")
		if ipNet.Contains(net.ParseIP(remoteIP)) {
			a.logger.Info("RemoteIP was found in staticAllowedIPNets. Access Granted.", "remoteIP", remoteIP, "staticAllowedIPNets", a.staticAllowedIPNets, "phase", "check_request", "status", "granted")
			a.next.ServeHTTP(responseWriter, request)
			return
		}
	}

	// URL allow rules take precedence over fail2ban counting: a matching
	// request is passed through without being tracked or counted.
	requestURL := request.URL.String()
	if a.handleAllowedURL(responseWriter, request, remoteIP, requestURL) {
		return
	}

	requestPath := sanitizePath(request.URL)

	requestTime := time.Now()
	a.cache.CleanEntries(a.findTime, a.banTime)
	a.cache.CleanEntryIfPossible(remoteIP, a.findTime, a.banTime, requestTime)
	entry := a.cache.CreateEntry(remoteIP, requestTime)

	if entry.GetTimesSeen() >= a.maxRetries && !entry.IsBanned() {
		a.logBan(entry, remoteIP, request.Host)
		entry.IssueBan()
	}

	if entry.IsBanned() {
		a.logger.Debug("Client is still banned.", "remoteIP", remoteIP, "phase", "check_request", "status", "denied")
		responseWriter.WriteHeader(a.errorCode)
		return
	}
	defer entry.SetLastSeen(requestTime)

	// URL deny rules block matching requests immediately and register a
	// strike towards the ban limit.
	if a.handleDeniedURL(responseWriter, entry, remoteIP, requestURL, requestPath) {
		return
	}

	// Response rules will be checked in the wrapped response writer
	wrappedResponseWriter := &ResponseWriter{
		ResponseWriter: responseWriter,
		logger:         a.logger,
		cacheEntry:     entry,
		rules:          a.responseRules,
		remoteIP:       remoteIP,
		path:           requestPath,
		trackStrikes:   a.trackStrikes,
	}

	// Continue serving request
	a.next.ServeHTTP(wrappedResponseWriter, request)
}

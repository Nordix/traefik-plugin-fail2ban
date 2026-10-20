package traefik_plugin_fail2ban //nolint:revive,stylecheck

import (
	"bufio"
	"net"
	"net/http"
	"strconv"

	"github.com/zerodha/logf"
)

// ResponseWriter wrapping original ResponseWriter with response check handling.
type ResponseWriter struct {
	http.ResponseWriter

	logger       *logf.Logger
	cacheEntry   *CacheEntry
	rules        responseRules
	remoteIP     string
	path         string
	trackStrikes bool
}

// WriteHeader wraps original WriteHeader whilst checking for response status code.
func (rw *ResponseWriter) WriteHeader(code int) {
	// Intercept WriteHeader to check for responseCode
	defer rw.ResponseWriter.WriteHeader(code)

	if rw.rules.StatusCode != nil {
		if rw.rules.StatusCode.MatchString(strconv.Itoa(code)) {
			rw.logger.Debug("Response Status Code matched rule. Incrementing.", "statusCodeRegexp", rw.rules.StatusCode, "responseStatusCode", code, "phase", "check_response", "status", "denied")
			rw.cacheEntry.IncrementTimesSeen()
			rw.recordStrike(code)
		} else {
			rw.logger.Debug("Response Status Code does not match rule. Skipping.", "statusCodeRegexp", rw.rules.StatusCode, "responseStatusCode", code, "phase", "check_response", "status", "granted")
		}
	}
}

// recordStrike attributes the response status to the request path, so that the
// ban log can later report which paths earned the strikes. It is a no-op
// unless strike tracking is enabled, and once the per-client key cap is hit.
func (rw *ResponseWriter) recordStrike(code int) {
	if !rw.trackStrikes {
		return
	}

	count, tracked := rw.cacheEntry.RecordStrike(rw.path, code)
	if !tracked {
		return
	}

	rw.logger.Debug("Strike recorded.", "remoteIP", rw.remoteIP, "path", rw.path, "responseStatus", code, "pathCount", count, "timesSeen", rw.cacheEntry.GetTimesSeen(), "phase", "check_response", "status", "denied")
}

// Hijack implements http.Hijacker interface method to support WebSockets and other protocols ...
func (rw *ResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := rw.ResponseWriter.(http.Hijacker)
	if !ok {
		rw.logger.Debug("ResponseWriter does not support hijacking", "phase", "check_response", "status", "error")
		return nil, nil, http.ErrNotSupported
	}
	return hijacker.Hijack()
}

// Write wraps original Write whilst checking for response body.
func (rw *ResponseWriter) Write(data []byte) (status int, err error) {
	// Intercept Write to check for response body
	defer func() {
		status, err = rw.ResponseWriter.Write(data)
	}()

	return 0, nil
}

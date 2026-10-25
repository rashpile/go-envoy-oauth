package filter

import (
	"net/url"
	"strings"
)

// removeQueryParam removes a specific query parameter from the path
func removeQueryParam(path string, paramToRemove string) string {
	if path == "" {
		return path
	}

	// Split path and query string
	idx := strings.Index(path, "?")
	if idx < 0 {
		return path // No query string
	}

	basePath := path[:idx]
	query := path[idx+1:]

	// Parse query parameters
	values, err := url.ParseQuery(query)
	if err != nil {
		return basePath // Return base path if query parsing fails
	}

	// Remove the parameter
	values.Del(paramToRemove)

	// Rebuild the path
	newQuery := values.Encode()
	if newQuery != "" {
		return basePath + "?" + newQuery
	}
	return basePath
}

// isExcludedPath reports whether path matches one of the excluded prefixes.
// The query string is ignored. A path with dot-segments, encoded separators,
// backslashes, ";" or "//" never matches: an upstream may resolve it to a
// different, protected path than the prefix suggests (issue #8).
func isExcludedPath(path string, excluded []string) bool {
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}
	if hasAmbiguousSegments(path) {
		return false
	}
	for _, ex := range excluded {
		if ex != "" && strings.HasPrefix(path, ex) {
			return true
		}
	}
	return false
}

// hasAmbiguousSegments reports whether path contains anything that upstreams
// may normalize differently from a plain prefix comparison.
func hasAmbiguousSegments(path string) bool {
	if strings.Contains(path, "//") || strings.ContainsAny(path, `\;`) {
		return true
	}
	lower := strings.ToLower(path)
	for _, enc := range []string{"%2e", "%2f", "%5c", "%00"} {
		if strings.Contains(lower, enc) {
			return true
		}
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// isSafeRelativePath reports whether s is a same-origin relative path that is
// safe to redirect to or link to. The explicit second-character check handles
// browser-normalised forms:
//
//	"//evil.com"  → protocol-relative
//	"///evil.com" → triple-slash (parsed as path by Go, but browser collapses)
//	"/\evil.com"  → backslash-normalised to // by Chromium
func isSafeRelativePath(s string) bool {
	parsed, err := url.Parse(s)
	if err != nil || parsed.Host != "" || parsed.Scheme != "" || !strings.HasPrefix(s, "/") {
		return false
	}
	return len(s) == 1 || (s[1] != '/' && s[1] != '\\')
}

// safeHomeURL returns a link target for the welcome page. A safe relative path
// is kept; an absolute http(s) URL on the request's own host is reduced to its
// path, query and fragment; anything else becomes "/" (issue #10).
func safeHomeURL(raw, host string) string {
	if isSafeRelativePath(raw) {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || host == "" || !strings.EqualFold(u.Host, host) {
		return "/"
	}
	rel := u.EscapedPath()
	if rel == "" {
		rel = "/"
	}
	if u.RawQuery != "" {
		rel += "?" + u.RawQuery
	}
	if u.Fragment != "" {
		rel += "#" + u.EscapedFragment()
	}
	if !isSafeRelativePath(rel) {
		return "/"
	}
	return rel
}

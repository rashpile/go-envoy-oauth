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

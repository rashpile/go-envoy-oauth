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

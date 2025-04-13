package filter

import (
	"strings"
)

// QueryHelper provides methods for working with query parameters
type QueryHelper struct{}

// NewQueryHelper creates a new query helper
func NewQueryHelper() *QueryHelper {
	return &QueryHelper{}
}

// ExtractQueryParams parses query parameters from a URL path
func (h *QueryHelper) ExtractQueryParams(path string) map[string]string {
	result := make(map[string]string)

	// Extract the query string portion
	queryString := h.getQueryStringFromPath(path)
	if queryString == "" {
		return result // No query parameters
	}

	// Parse the query string into a map
	return h.parseQueryString(queryString)
}

// getQueryStringFromPath extracts just the query string portion from a path
func (h *QueryHelper) getQueryStringFromPath(path string) string {
	// Find the position of the query string marker
	queryPos := strings.Index(path, "?")
	if queryPos == -1 {
		return "" // No query parameters
	}

	// Extract the query string without the leading '?'
	return path[queryPos+1:]
}

// parseQueryString converts a query string into a map of parameter names to values
func (h *QueryHelper) parseQueryString(queryString string) map[string]string {
	result := make(map[string]string)

	// Split the query string by '&' to get individual parameters
	params := strings.Split(queryString, "&")
	for _, param := range params {
		h.parseQueryParameter(param, result)
	}

	return result
}

// parseQueryParameter parses a single query parameter and adds it to the result map
func (h *QueryHelper) parseQueryParameter(param string, result map[string]string) {
	// Skip empty parameters
	if param == "" {
		return
	}

	// Split each parameter by '=' to get key-value pairs
	keyValue := strings.SplitN(param, "=", 2)
	if len(keyValue) == 2 {
		result[keyValue[0]] = keyValue[1]
	} else if len(keyValue) == 1 {
		// Handle parameters without values
		result[keyValue[0]] = ""
	}
}

// GetQueryAPIKey extracts the API key from query parameters
func (h *QueryHelper) GetQueryAPIKey(config *Config, header FilterHeader) (string, bool) {
	// Skip if query param auth is disabled
	if config.APIKeyQueryParam == "" {
		return "", false
	}

	fullPath := header.Path()
	queryParams := h.ExtractQueryParams(fullPath)
	queryValue, queryExists := queryParams[config.APIKeyQueryParam]
	return queryValue, queryExists && queryValue != ""
}

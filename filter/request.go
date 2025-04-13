package filter

import "github.com/envoyproxy/envoy/contrib/golang/common/go/api"

type FilterHeader interface {
	Path() string
}

type filterRequestFactory struct {
	config    *Config
	callbacks api.FilterCallbackHandler
	header    api.RequestHeaderMap
}

func (f *filterRequestFactory) HeaderApiKey() (string, bool) {
	if f.config.APIKeyHeader == "" {
		return "", false
	}
	headerKey, headerExists := f.header.Get(f.config.APIKeyHeader)
	return headerKey, headerExists && headerKey != ""
}

func (f *filterRequestFactory) CookieApiKey() (string, bool) {
	h := NewCookieHelper(f.config.CookieSettings)
	cookieKey, cookieExists := h.GetCookieAPIKey(f.config, f.header)
	return cookieKey, cookieExists
}

func (f *filterRequestFactory) QueryApiKey() (string, bool) {
	h := NewQueryHelper()
	queryKey, queryExists := h.GetQueryAPIKey(f.config, f.header)
	return queryKey, queryExists
}

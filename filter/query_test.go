package filter

import (
	"reflect"
	"testing"
)

func TestQueryHelper_ExtractQueryParams(t *testing.T) {
	tests := []struct {
		name string
		path string
		want map[string]string
	}{
		{
			name: "no query params",
			path: "/api/v1/resource",
			want: map[string]string{},
		},
		{
			name: "single query param",
			path: "/api/v1/resource?key=value",
			want: map[string]string{"key": "value"},
		},
		{
			name: "multiple query params",
			path: "/api/v1/resource?key1=value1&key2=value2",
			want: map[string]string{"key1": "value1", "key2": "value2"},
		},
		{
			name: "param without value",
			path: "/api/v1/resource?key1=value1&flag",
			want: map[string]string{"key1": "value1", "flag": ""},
		},
		{
			name: "empty query string",
			path: "/api/v1/resource?",
			want: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewQueryHelper()
			got := h.ExtractQueryParams(tt.path)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("QueryHelper.ExtractQueryParams() = %v, want %v", got, tt.want)
			}
		})
	}
}

// mockHeaderMap implements the minimal RequestHeaderMap interface needed for testing
type mockHeaderMap struct {
	path string
}

func (m mockHeaderMap) Path() string {
	return m.path
}

func (m mockHeaderMap) Get(key string) (string, bool) {
	return "", false
}

func (m mockHeaderMap) Values(key string) []string {
	return nil
}

func (m mockHeaderMap) Set(key, value string) {
}

func (m mockHeaderMap) Add(key, value string) {
}

func (m mockHeaderMap) Del(key string) {
}

func TestQueryHelper_GetQueryAPIKey(t *testing.T) {

	// Add methods to satisfy the RequestHeaderMap interface
	// These need to be defined as methods on the mockHeaderMap type
	// outside of the test function to avoid syntax errors


	tests := []struct {
		name            string
		config          *Config
		path            string
		wantKey         string
		wantKeyExists   bool
	}{
		{
			name: "key exists",
			config: &Config{
				APIKeyQueryParam: "api-key",
			},
			path:          "/api/v1/resource?api-key=12345",
			wantKey:       "12345",
			wantKeyExists: true,
		},
		{
			name: "key doesn't exist",
			config: &Config{
				APIKeyQueryParam: "api-key",
			},
			path:          "/api/v1/resource?other-param=value",
			wantKey:       "",
			wantKeyExists: false,
		},
		{
			name: "query param auth disabled",
			config: &Config{
				APIKeyQueryParam: "",
			},
			path:          "/api/v1/resource?api-key=12345",
			wantKey:       "",
			wantKeyExists: false,
		},
		{
			name: "empty key value",
			config: &Config{
				APIKeyQueryParam: "api-key",
			},
			path:          "/api/v1/resource?api-key=",
			wantKey:       "",
			wantKeyExists: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewQueryHelper()
			header := mockHeaderMap{path: tt.path}
			gotKey, gotExists := h.GetQueryAPIKey(tt.config, header)

			if gotKey != tt.wantKey {
				t.Errorf("QueryHelper.GetQueryAPIKey() key = %v, want %v", gotKey, tt.wantKey)
			}
			if gotExists != tt.wantKeyExists {
				t.Errorf("QueryHelper.GetQueryAPIKey() exists = %v, want %v", gotExists, tt.wantKeyExists)
			}
		})
	}
}

package session

import (
	"net/http"
	"testing"
)

type mockHeaderMap struct {
	headers map[string]string
}

func newMockHeaderMap() *mockHeaderMap {
	return &mockHeaderMap{
		headers: make(map[string]string),
	}
}

func (m *mockHeaderMap) Get(key string) (string, bool) {
	val, ok := m.headers[key]
	return val, ok
}

func (m *mockHeaderMap) Set(key, value string) {
	m.headers[key] = value
}

func (m *mockHeaderMap) Del(key string) {
	delete(m.headers, key)
}

func (m *mockHeaderMap) Range(f func(key, value string) bool) {
	for k, v := range m.headers {
		if !f(k, v) {
			break
		}
	}
}

func (m *mockHeaderMap) RangeWithCopy(f func(key, value string) bool) {
	m.Range(f)
}

func (m *mockHeaderMap) GetRaw(key string) string {
	val, _ := m.headers[key]
	return val
}

func (m *mockHeaderMap) GetAllHeaders() map[string][]string {
	result := make(map[string][]string)
	for k, v := range m.headers {
		result[k] = []string{v}
	}
	return result
}

func (m *mockHeaderMap) GetCopy() map[string][]string {
	return m.GetAllHeaders()
}

func (m *mockHeaderMap) GetAll(key string) []string {
	if val, ok := m.headers[key]; ok {
		return []string{val}
	}
	return nil
}

func (m *mockHeaderMap) Add(key, value string) {
	m.headers[key] = value
}

func (m *mockHeaderMap) Values(key string) []string {
	return m.GetAll(key)
}

func (m *mockHeaderMap) ByteSize() uint64 {
	return 0
}

func (m *mockHeaderMap) Host() string {
	host, _ := m.Get("host")
	return host
}

func (m *mockHeaderMap) Path() string {
	return "/"
}

func (m *mockHeaderMap) Method() string {
	return "GET"
}

func (m *mockHeaderMap) Scheme() string {
	return "https"
}

func (m *mockHeaderMap) Protocol() string {
	return "HTTP/1.1"
}

func (m *mockHeaderMap) Url() string {
	return ""
}

func (m *mockHeaderMap) RequestId() string {
	return ""
}

func (m *mockHeaderMap) SetHost(host string) {
	m.Set("host", host)
}

func (m *mockHeaderMap) SetPath(path string) {
}

func (m *mockHeaderMap) SetMethod(method string) {
}

func (m *mockHeaderMap) SetUrl(url string) {
}

func (m *mockHeaderMap) SetRaw(key string, value []byte) {
	m.Set(key, string(value))
}

func TestGetDomainFromHeaders(t *testing.T) {
	tests := []struct {
		name           string
		configDomain   string
		headers        map[string]string
		expectedDomain string
	}{
		{
			name:         "explicit config domain takes precedence",
			configDomain: "example.com",
			headers: map[string]string{
				"host":              "localhost:8080",
				"x-forwarded-host": "proxy.com",
			},
			expectedDomain: "example.com",
		},
		{
			name:         "x-forwarded-host used when no config domain",
			configDomain: "",
			headers: map[string]string{
				"host":              "localhost:8080",
				"x-forwarded-host": "app.example.com",
			},
			expectedDomain: "app.example.com",
		},
		{
			name:         "x-forwarded-host with port stripped",
			configDomain: "",
			headers: map[string]string{
				"x-forwarded-host": "app.example.com:443",
			},
			expectedDomain: "app.example.com",
		},
		{
			name:         "host header used when no x-forwarded-host",
			configDomain: "",
			headers: map[string]string{
				"host": "myapp.com",
			},
			expectedDomain: "myapp.com",
		},
		{
			name:         "host header with port stripped",
			configDomain: "",
			headers: map[string]string{
				"host": "myapp.com:8080",
			},
			expectedDomain: "myapp.com",
		},
		{
			name:         "localhost returns empty domain",
			configDomain: "",
			headers: map[string]string{
				"host": "localhost:8080",
			},
			expectedDomain: "",
		},
		{
			name:         "127.0.0.1 returns empty domain",
			configDomain: "",
			headers: map[string]string{
				"host": "127.0.0.1:8080",
			},
			expectedDomain: "",
		},
		{
			name:         "private IP returns empty domain",
			configDomain: "",
			headers: map[string]string{
				"host": "192.168.1.100:8080",
			},
			expectedDomain: "",
		},
		{
			name:           "no domain when headers missing",
			configDomain:   "",
			headers:        map[string]string{},
			expectedDomain: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultCookieConfig()
			config.Domain = tt.configDomain

			cm, err := NewCookieManager(nil, nil, config)
			if err != nil {
				t.Fatalf("Failed to create cookie manager: %v", err)
			}

			header := newMockHeaderMap()
			for k, v := range tt.headers {
				header.Set(k, v)
			}

			domain := cm.getDomainFromHeaders(header)
			if domain != tt.expectedDomain {
				t.Errorf("Expected domain %q, got %q", tt.expectedDomain, domain)
			}
		})
	}
}

func TestSetCookieWithDynamicDomain(t *testing.T) {
	tests := []struct {
		name           string
		configDomain   string
		headers        map[string]string
		expectedDomain string
		expectNoDomain bool
	}{
		{
			name:         "cookie with x-forwarded-host",
			configDomain: "",
			headers: map[string]string{
				"x-forwarded-host": "app.example.com",
			},
			expectedDomain: "app.example.com",
			expectNoDomain: false,
		},
		{
			name:         "cookie with localhost host header",
			configDomain: "",
			headers: map[string]string{
				"host": "localhost:3000",
			},
			expectedDomain: "",
			expectNoDomain: true,
		},
		{
			name:         "cookie with proper domain",
			configDomain: "",
			headers: map[string]string{
				"host": "app.example.com:443",
			},
			expectedDomain: "app.example.com",
			expectNoDomain: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultCookieConfig()
			config.Domain = tt.configDomain
			config.Name = "test_session"
			config.Path = "/"
			config.MaxAge = 3600
			config.Secure = true
			config.HTTPOnly = true
			config.SameSite = http.SameSiteLaxMode

			cm, err := NewCookieManager(nil, nil, config)
			if err != nil {
				t.Fatalf("Failed to create cookie manager: %v", err)
			}

			header := newMockHeaderMap()
			for k, v := range tt.headers {
				header.Set(k, v)
			}

			err = cm.SetCookie(header, "test-value-123")
			if err != nil {
				t.Errorf("SetCookie failed: %v", err)
			}

			setCookie, ok := header.Get("set-cookie")
			if !ok {
				t.Error("set-cookie header not found")
			}

			if tt.expectNoDomain {
				if contains(setCookie, "Domain=") {
					t.Errorf("Expected no Domain attribute in cookie, but found it in: %q", setCookie)
				}
			} else if tt.expectedDomain != "" {
				expectedContains := "Domain=" + tt.expectedDomain
				if !contains(setCookie, expectedContains) {
					t.Errorf("Expected cookie to contain %q, got %q", expectedContains, setCookie)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
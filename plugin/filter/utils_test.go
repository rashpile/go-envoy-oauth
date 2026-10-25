package filter

import "testing"

func TestIsExcludedPath(t *testing.T) {
	excluded := []string{"/share", "/pub-", "/llms.txt"}
	tests := []struct {
		path string
		want bool
	}{
		{"/share", true},
		{"/share/abc", true},
		{"/share/abc?x=1", true},
		{"/pub-site/index.html", true},
		{"/llms.txt", true},
		{"/llms.txt?v=2", true},
		{"/private", false},
		{"/", false},
		{"/?/share", false},

		// dot-segments and encodings that upstreams may resolve elsewhere
		{"/share/../private", false},
		{"/share/..", false},
		{"/pub-x/../app/index.html", false},
		{"/share/./x", false},
		{"/llms.txt/%2e%2e/api", false},
		{"/llms.txt/%2E%2E/api", false},
		{"/share%2f..%2fprivate", false},
		{"/share%5c..%5cprivate", false},
		{`/share\..\private`, false},
		{"/share/..;/private", false},
		{"/share//..//private", false},
		{"/share%00/private", false},
	}
	for _, tt := range tests {
		if got := isExcludedPath(tt.path, excluded); got != tt.want {
			t.Errorf("isExcludedPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestIsExcludedPathIgnoresEmptyEntries(t *testing.T) {
	if isExcludedPath("/anything", []string{""}) {
		t.Error("an empty exclude entry must not match every path")
	}
}

// TestParsedConfigHasNoImplicitExclusions verifies that a config without
// exclude_paths protects every path, including /health (issue #8).
func TestParsedConfigHasNoImplicitExclusions(t *testing.T) {
	conf, err := (&Parser{}).parseRawConfig(buildAny(t, baseConfig()))
	if err != nil {
		t.Fatalf("parseRawConfig: %v", err)
	}
	if len(conf.ExcludePaths) != 0 {
		t.Errorf("default ExcludePaths = %v, want none", conf.ExcludePaths)
	}
	f := &Filter{config: conf}
	for _, p := range []string{"/health", "/health/../admin", "/healthz"} {
		if f.isPathExcluded(p, "any-cluster") {
			t.Errorf("isPathExcluded(%q) = true with default config, want false", p)
		}
	}
}

func TestIsSafeRelativePath(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"/", true},
		{"/app/page?x=1#top", true},
		{"", false},
		{"app", false},
		{"//other.example", false},
		{"///other.example", false},
		{`/\other.example`, false},
		{"https://other.example/", false},
		{"javascript:alert(1)", false},
		{"data:text/html,x", false},
	}
	for _, tt := range tests {
		if got := isSafeRelativePath(tt.in); got != tt.want {
			t.Errorf("isSafeRelativePath(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestSafeHomeURL(t *testing.T) {
	const host = "app.example.com"
	tests := []struct {
		in   string
		want string
	}{
		{"/dashboard?tab=1", "/dashboard?tab=1"},
		{"https://app.example.com/dashboard?tab=1#x", "/dashboard?tab=1#x"},
		{"https://APP.example.com", "/"},
		{"http://app.example.com/a", "/a"},
		{"https://other.example.com/dashboard", "/"},
		{"https://app.example.com.other.example/", "/"},
		{"javascript:alert(1)", "/"},
		{"JavaScript:alert(1)", "/"},
		{"data:text/html,x", "/"},
		{"//other.example.com/", "/"},
		{"", "/"},
	}
	for _, tt := range tests {
		if got := safeHomeURL(tt.in, host); got != tt.want {
			t.Errorf("safeHomeURL(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	if got := safeHomeURL("https://app.example.com/a", ""); got != "/" {
		t.Errorf("safeHomeURL without host = %q, want /", got)
	}
}

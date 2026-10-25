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

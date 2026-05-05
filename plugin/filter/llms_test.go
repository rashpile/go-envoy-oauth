package filter

import (
	"strings"
	"testing"
)

// TestLLMsTxtBodyNonEmpty verifies that the embedded markdown was actually
// bundled into the binary and is not an empty string.
func TestLLMsTxtBodyNonEmpty(t *testing.T) {
	if llmsTxtBody == "" {
		t.Fatal("llmsTxtBody is empty; go:embed did not bundle plugin/filter/llms.txt")
	}
}

// TestLLMsTxtBodyHasH1 verifies the bundled markdown starts with the expected
// H1 title. A canary against accidentally embedding the wrong file.
func TestLLMsTxtBodyHasH1(t *testing.T) {
	want := "# go-envoy-oauth — Integration Guide for Agents"
	if !strings.Contains(llmsTxtBody, want) {
		t.Errorf("llmsTxtBody missing expected H1 %q", want)
	}
}

// TestLLMsTxtVersionStamped verifies that init() substituted {{VERSION}}
// for the actual Version string, and that the literal placeholder is gone.
func TestLLMsTxtVersionStamped(t *testing.T) {
	if strings.Contains(llmsTxtBody, "{{VERSION}}") {
		t.Error("llmsTxtBody still contains literal {{VERSION}}; init() did not substitute")
	}
	if !strings.Contains(llmsTxtBody, Version) {
		t.Errorf("llmsTxtBody does not contain Version %q after substitution", Version)
	}
}

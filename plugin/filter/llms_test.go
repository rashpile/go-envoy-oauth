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

// TestLLMsTxtReplyGET verifies the helper returns 200 with markdown content,
// the configured cache header, and text/plain content-type for GET.
func TestLLMsTxtReplyGET(t *testing.T) {
	status, body, headers := llmsTxtReply("GET")

	if status != 200 {
		t.Errorf("status: got %d, want 200", status)
	}
	if body != llmsTxtBody {
		t.Error("body: helper returned a different string than llmsTxtBody")
	}

	gotCT := headers["content-type"]
	if len(gotCT) != 1 || gotCT[0] != "text/plain; charset=utf-8" {
		t.Errorf("content-type: got %v, want [text/plain; charset=utf-8]", gotCT)
	}

	gotCC := headers["cache-control"]
	if len(gotCC) != 1 || gotCC[0] != "public, max-age=3600" {
		t.Errorf("cache-control: got %v, want [public, max-age=3600]", gotCC)
	}

	if _, hasAllow := headers["allow"]; hasAllow {
		t.Error("GET response should not carry an Allow header")
	}
}

// TestLLMsTxtReplyPOST verifies the helper returns 405 with Allow: GET for
// non-GET methods.
func TestLLMsTxtReplyPOST(t *testing.T) {
	status, body, headers := llmsTxtReply("POST")

	if status != 405 {
		t.Errorf("status: got %d, want 405", status)
	}
	if body != "Method Not Allowed" {
		t.Errorf("body: got %q, want %q", body, "Method Not Allowed")
	}

	gotAllow := headers["allow"]
	if len(gotAllow) != 1 || gotAllow[0] != "GET" {
		t.Errorf("allow: got %v, want [GET]", gotAllow)
	}

	gotCT := headers["content-type"]
	if len(gotCT) != 1 || gotCT[0] != "text/plain; charset=utf-8" {
		t.Errorf("content-type: got %v, want [text/plain; charset=utf-8]", gotCT)
	}

	if _, hasCC := headers["cache-control"]; hasCC {
		t.Error("405 response should not carry Cache-Control")
	}
}

// TestLLMsTxtReplyOtherMethods covers HEAD, PUT, DELETE, PATCH, OPTIONS to
// confirm the method allow-list is strict (only GET).
func TestLLMsTxtReplyOtherMethods(t *testing.T) {
	for _, m := range []string{"HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"} {
		status, _, _ := llmsTxtReply(m)
		if status != 405 {
			t.Errorf("method %s: got status %d, want 405", m, status)
		}
	}
}

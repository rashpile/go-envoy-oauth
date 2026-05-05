package filter

import (
	_ "embed"
	"strings"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
)

//go:embed llms.txt
var llmsTxtTemplate string

// llmsTxtBody is the rendered /oauth/llms.txt response body. Computed once
// at process init by substituting {{VERSION}} in the embedded template with
// the build-time Version string. Held as a single in-memory string and
// served verbatim on every request.
var llmsTxtBody string

func init() {
	llmsTxtBody = strings.ReplaceAll(llmsTxtTemplate, "{{VERSION}}", Version)
}

// llmsTxtReply returns the status code, body, and headers for a
// /oauth/llms.txt request with the given HTTP method. Pure function —
// no SDK dependency — to keep it unit-testable without mocking the
// callback handler.
func llmsTxtReply(method string) (int, string, map[string][]string) {
	if method != "GET" {
		return 405, "Method Not Allowed", map[string][]string{
			"content-type": {"text/plain; charset=utf-8"},
			"allow":        {"GET"},
		}
	}
	return 200, llmsTxtBody, map[string][]string{
		"content-type":  {"text/plain; charset=utf-8"},
		"cache-control": {"public, max-age=3600"},
	}
}

// handleLLMsTxt serves the /oauth/llms.txt agent-integration guide.
func (f *Filter) handleLLMsTxt(header api.RequestHeaderMap) api.StatusType {
	method, _ := header.Get(":method")
	status, body, headers := llmsTxtReply(method)
	return f.recordAndSendLocalReply(status, body, headers, -1, "")
}

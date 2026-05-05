package filter

import (
	_ "embed"
	"strings"
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

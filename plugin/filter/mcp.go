package filter

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"go.uber.org/zap"
)

// clusterMCP returns the mcp block of the given cluster, or nil.
func (f *Filter) clusterMCP(cluster string) *MCPConfig {
	if clusterConfig, ok := f.config.Clusters[cluster]; ok {
		return clusterConfig.MCP
	}
	return nil
}

// mcpIssuer returns the issuer of the cluster's provider, which is the
// authorization server MCP clients must sign in with. Legacy single-provider
// configs have no providers map and use the top-level issuer_url.
func (f *Filter) mcpIssuer() string {
	if p, ok := f.config.Providers[f.resolveProviderName()]; ok && p.IssuerURL != "" {
		return p.IssuerURL
	}
	return f.config.IssuerURL
}

// mcpMetadataReply returns the status code, body, and headers for an RFC 9728
// protected resource metadata request. Pure function, like llmsTxtReply.
func mcpMetadataReply(method string, mcp *MCPConfig, issuer string) (int, string, map[string][]string) {
	if method != "GET" {
		return 405, "Method Not Allowed", map[string][]string{
			"content-type": {"text/plain; charset=utf-8"},
			"allow":        {"GET"},
		}
	}
	body, _ := json.Marshal(struct {
		Resource               string   `json:"resource"`
		AuthorizationServers   []string `json:"authorization_servers"`
		BearerMethodsSupported []string `json:"bearer_methods_supported"`
	}{
		Resource:               mcp.Resource,
		AuthorizationServers:   []string{issuer},
		BearerMethodsSupported: []string{"header"},
	})
	return 200, string(body), map[string][]string{
		"content-type":  {"application/json"},
		"cache-control": {"public, max-age=3600"},
	}
}

// handleMCPMetadata serves the protected resource metadata without authentication.
func (f *Filter) handleMCPMetadata(header api.RequestHeaderMap, mcp *MCPConfig) api.StatusType {
	method, _ := header.Get(":method")
	f.logger.Debug("Serving MCP protected resource metadata",
		zap.String("resource", mcp.Resource),
		zap.String("trace_id", f.getTraceID(header)))
	status, body, headers := mcpMetadataReply(method, mcp, f.mcpIssuer())
	return f.recordAndSendLocalReply(status, body, headers, -1, "")
}

// matchesMCPPath reports whether path is the guarded MCP path or below it.
// Ambiguous paths never match: see isAmbiguousMCPPath.
func matchesMCPPath(path string, mcp *MCPConfig) bool {
	base := stripQuery(path)
	if hasAmbiguousSegments(base) {
		return false
	}
	return base == mcp.Path || strings.HasPrefix(base, mcp.Path+"/")
}

// isAmbiguousMCPPath reports whether path starts with the MCP path but
// contains segments (";", encoded separators, dot-segments) an upstream may
// normalize to a different endpoint. Such requests are refused outright:
// authenticating them with an MCP token would let that token reach non-MCP
// endpoints, and sending them to cookie auth would put cookies on /mcp.
func isAmbiguousMCPPath(path string, mcp *MCPConfig) bool {
	base := stripQuery(path)
	return strings.HasPrefix(base, mcp.Path) && hasAmbiguousSegments(base)
}

// mcpChallengeHeaders builds the RFC 9728 401 challenge pointing MCP clients
// at the protected resource metadata.
func mcpChallengeHeaders(metadataURL string, tokenSent bool) map[string][]string {
	challenge := `Bearer resource_metadata="` + metadataURL + `"`
	if tokenSent {
		challenge += `, error="invalid_token"`
	}
	return map[string][]string{
		"content-type":     {"text/plain"},
		"www-authenticate": {challenge},
	}
}

// handleMCPAuth authenticates a request to the MCP path with a bearer token
// whose aud contains the configured resource. Cookies and API keys are not
// consulted and the client is never redirected: MCP clients follow the
// WWW-Authenticate challenge instead.
func (f *Filter) handleMCPAuth(header api.RequestHeaderMap, mcp *MCPConfig, traceID string) api.StatusType {
	token := f.extractBearerToken(header)
	if token == "" {
		f.logger.Debug("MCP request without bearer token",
			zap.String("trace_id", traceID))
		f.recordClusterAuthFailure()
		return f.recordAndSendLocalReply(401, "Unauthorized",
			mcpChallengeHeaders(mcp.MetadataURL, false), -1, "mcp_unauthorized")
	}

	h, err := f.getProviderHandler()
	if err != nil {
		f.logger.Error("Failed to resolve provider handler for MCP token validation",
			zap.String("trace_id", traceID),
			zap.Error(err))
		f.recordClusterAuthFailure()
		return f.recordAndSendLocalReply(503, "Identity provider unavailable",
			map[string][]string{"content-type": {"text/plain"}}, -1, "provider_unavailable")
	}

	sess, err := h.ValidateBearerTokenForResource(context.Background(), token, mcp.Resource)
	if err != nil {
		f.logger.Debug("MCP bearer token rejected",
			zap.String("resource", mcp.Resource),
			zap.String("trace_id", traceID),
			zap.Error(err))
		f.recordClusterAuthFailure()
		return f.recordAndSendLocalReply(401, "Unauthorized",
			mcpChallengeHeaders(mcp.MetadataURL, true), -1, "mcp_invalid_token")
	}

	if !f.isUserPermitted(sess) {
		username, _ := sess.Claims["preferred_username"].(string)
		f.logger.Info("Access denied: user not permitted",
			zap.String("user", strings.ToLower(strings.TrimSpace(username))),
			zap.String("cluster", f.cluster),
			zap.String("trace_id", traceID),
			zap.String("action", "DENY"))
		return f.recordAndSendLocalReply(403, "Forbidden",
			map[string][]string{"content-type": {"text/plain"}}, -1, "mcp_forbidden")
	}

	return f.handleAuthSuccess(header, sess)
}

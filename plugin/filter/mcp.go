package filter

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/rashpile/go-envoy-oauth/plugin/oauth"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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
		ScopesSupported        []string `json:"scopes_supported,omitempty"`
	}{
		Resource:               mcp.Resource,
		AuthorizationServers:   []string{issuer},
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        mcp.Scopes,
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

// Reasons an /mcp request is rejected outside token validation. Token
// rejections use the oauth.Reason* classes.
const (
	mcpReasonNoToken        = "no_token"
	mcpReasonUserNotAllowed = "user_not_allowed"
	mcpReasonAmbiguousPath  = "ambiguous_path"
	mcpReasonProviderDown   = "provider_down"
)

// mcpErrorDescriptions are the fixed error_description texts sent to the
// client (RFC 6750 section 3). They name the reason class only; the
// validator's error text stays in the gateway log.
var mcpErrorDescriptions = map[string]string{
	oauth.ReasonVerifyFailed: "token verification failed",
	oauth.ReasonClaimsDecode: "token claims could not be decoded",
	oauth.ReasonNoSubject:    "token has no sub claim",
}

// mcpChallengeHeaders builds the RFC 9728 401 challenge pointing MCP clients
// at the protected resource metadata, plus the scopes to request when the
// cluster lists them. reason is empty when no token was sent, otherwise the
// class the token was rejected with.
func mcpChallengeHeaders(mcp *MCPConfig, reason string) map[string][]string {
	challenge := `Bearer resource_metadata="` + mcp.MetadataURL + `"`
	if len(mcp.Scopes) > 0 {
		challenge += `, scope="` + strings.Join(mcp.Scopes, " ") + `"`
	}
	if reason != "" {
		desc, ok := mcpErrorDescriptions[reason]
		if !ok {
			desc = mcpErrorDescriptions[oauth.ReasonVerifyFailed]
		}
		challenge += `, error="invalid_token", error_description="` + desc + `"`
	}
	return map[string][]string{
		"content-type":     {"text/plain"},
		"www-authenticate": {challenge},
	}
}

// mcpRejection describes a refused /mcp request for the operator log.
// azp, iss and aud are the only token claims it may carry.
type mcpRejection struct {
	status int
	reason string
	err    error
	azp    string
	iss    string
	aud    []string
}

// tokenRejection classifies a token validation error.
func tokenRejection(err error) mcpRejection {
	r := mcpRejection{status: 401, reason: oauth.ReasonVerifyFailed, err: err}
	var rte *oauth.ResourceTokenError
	if errors.As(err, &rte) {
		r.reason, r.azp, r.iss, r.aud = rte.Reason, rte.Azp, rte.Iss, rte.Aud
	}
	return r
}

// logMCPRejection writes the one line per refused /mcp request that tells an
// operator why it got 400/401/403/503. A request without a token is the
// normal first step of the MCP sign-in, so it logs at Info; the rest at Warn.
func (f *Filter) logMCPRejection(header api.RequestHeaderMap, r mcpRejection, traceID string) {
	host, _ := header.Get(":authority")
	path, _ := header.Get(":path")
	fields := []zap.Field{
		zap.String("host", host),
		zap.String("path", sanitizePathForLogging(path)),
		zap.Int("status", r.status),
		zap.String("reason", r.reason),
		zap.String("trace_id", traceID),
	}
	if r.err != nil {
		fields = append(fields, zap.Error(r.err))
	}
	if r.azp != "" {
		fields = append(fields, zap.String("azp", r.azp))
	}
	if r.iss != "" {
		fields = append(fields, zap.String("iss", r.iss))
	}
	if len(r.aud) > 0 {
		fields = append(fields, zap.Strings("aud", r.aud))
	}
	level := zapcore.WarnLevel
	if r.reason == mcpReasonNoToken {
		level = zapcore.InfoLevel
	}
	f.logger.Log(level, "MCP request rejected", fields...)
}

// handleMCPAuth authenticates a request to the MCP path with a bearer token
// whose aud contains the configured resource. Cookies and API keys are not
// consulted and the client is never redirected: MCP clients follow the
// WWW-Authenticate challenge instead.
func (f *Filter) handleMCPAuth(ctx context.Context, header api.RequestHeaderMap, mcp *MCPConfig, traceID string) api.StatusType {
	token := f.extractBearerToken(header)
	if token == "" {
		f.logMCPRejection(header, mcpRejection{status: 401, reason: mcpReasonNoToken}, traceID)
		f.recordClusterAuthFailure()
		return f.recordAndSendLocalReply(401, "Unauthorized",
			mcpChallengeHeaders(mcp, ""), -1, "mcp_unauthorized")
	}

	h, err := f.getProviderHandler()
	if err != nil {
		f.logMCPRejection(header, mcpRejection{status: 503, reason: mcpReasonProviderDown, err: err}, traceID)
		f.recordClusterAuthFailure()
		return f.recordAndSendLocalReply(503, "Identity provider unavailable",
			map[string][]string{"content-type": {"text/plain"}}, -1, "provider_unavailable")
	}

	sess, err := h.ValidateBearerTokenForResource(ctx, token, mcp.Resource)
	if err != nil {
		r := tokenRejection(err)
		f.logMCPRejection(header, r, traceID)
		f.recordClusterAuthFailure()
		return f.recordAndSendLocalReply(401, "Unauthorized",
			mcpChallengeHeaders(mcp, r.reason), -1, "mcp_invalid_token")
	}

	if !f.isUserPermitted(sess) {
		r := mcpRejection{status: 403, reason: mcpReasonUserNotAllowed}
		r.azp, _ = sess.Claims["azp"].(string)
		r.iss, _ = sess.Claims["iss"].(string)
		r.aud, _ = sess.Claims["aud"].([]string)
		f.logMCPRejection(header, r, traceID)
		return f.recordAndSendLocalReply(403, "Forbidden",
			map[string][]string{"content-type": {"text/plain"}}, -1, "mcp_forbidden")
	}

	return f.handleAuthSuccess(header, sess)
}

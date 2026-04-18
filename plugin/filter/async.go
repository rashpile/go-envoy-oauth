package filter

import (
	"context"
	"time"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/rashpile/go-envoy-oauth/plugin/oauth"
	"github.com/rashpile/go-envoy-oauth/plugin/session"
	"go.uber.org/zap"
)

const asyncOperationTimeout = 30 * time.Second

func (f *Filter) handleAsyncDecodeHeaders(
	header api.RequestHeaderMap, path string, traceID string,
	callback func(header api.RequestHeaderMap, path string, traceID string) api.StatusType) api.StatusType {
	ctx, cancel := context.WithTimeout(context.Background(), asyncOperationTimeout)
	go func() {
		defer cancel()
		defer func() {
			if r := recover(); r != nil {
				f.logger.Error("Panic in async decode headers",
					zap.String("trace_id", traceID),
					zap.Any("panic", r))
				f.handleRedirect("/", "")
			}
		}()

		done := make(chan api.StatusType, 1)
		go func() {
			done <- callback(header, path, traceID)
		}()

		select {
		case status := <-done:
			switch status {
			case api.LocalReply:
				// Local reply was sent successfully
			case api.Continue:
				f.callbacks.DecoderFilterCallbacks().Continue(api.Continue)
			default:
				f.logger.Warn("Unexpected status in async handler",
					zap.String("trace_id", traceID),
					zap.Int("status", int(status)))
			}
		case <-ctx.Done():
			f.logger.Error("Async operation timeout",
				zap.String("trace_id", traceID),
				zap.String("path", path))
			f.handleAuthFailure(504, "Gateway Timeout")
		}
	}()
	return api.Running
}

func (f *Filter) handleAsyncValidateSession(
	header api.RequestHeaderMap, session *session.Session,
	path string, traceID string,
	callback func(header api.RequestHeaderMap, session *session.Session) api.StatusType) api.StatusType {

	go func() {
		defer func() {
			if r := recover(); r != nil {
				f.logger.Error("Panic in async callback", zap.Any("panic", r))
				f.handleRedirect("/", "")
			}
		}()

		sessionHandler, err := f.getProviderHandler()
		if err != nil {
			f.logger.Error("Failed to resolve provider for async session validation",
				zap.String("trace_id", traceID),
				zap.Error(err))
			f.errorHandler.HandleIDPUnavailable()
			return
		}
		if err := sessionHandler.ValidateSession(session); err != nil {
			f.handleUnauthenticatedRequest(header, path, traceID, err, "Session validation failed")
			return
		}
		status := callback(header, session)
		switch status {
		case api.LocalReply:
			// Local reply was sent successfully
		case api.Continue:
			f.callbacks.DecoderFilterCallbacks().Continue(api.Continue)
		default:
			f.logger.Warn("Unexpected status in session validation",
				zap.String("trace_id", traceID),
				zap.Int("status", int(status)))
		}

	}()
	return api.Running
}

func (f *Filter) handleAsyncCallback(header api.RequestHeaderMap, query string, traceID string, handler oauth.OAuthHandler) api.StatusType {
	go func() {
		// Add panic recovery
		defer func() {
			if r := recover(); r != nil {
				f.logger.Error("Panic in async callback", zap.Any("panic", r))
				f.handleRedirect("/", "")
			}
		}()
		err := handler.HandleCallback(header, query)
		if err != nil {
			f.logger.Error("Failed to handle OAuth callback",
				zap.String("trace_id", traceID),
				zap.Error(err))
			// Redirect to home instead of showing error page (e.g. expired session/state)
			f.handleRedirect("/", "")
			return
		}

		// Get the session ID from the set-cookie header
		sessionID, exists := header.Get("set-cookie")
		if !exists || sessionID == "" {
			f.logger.Error("Failed to get session cookie",
				zap.String("trace_id", traceID),
				zap.Error(err))
			// Redirect to home instead of showing error page
			f.handleRedirect("/", "")
			return
		}

		// Get the redirect URI from the location header
		redirectURI, exists := header.Get("location")
		if !exists || redirectURI == "" {
			redirectURI = "/"
		}

		f.handleRedirect(redirectURI, sessionID)
		// SendLocalReply already called inside handleRedirect
	}()
	return api.Running // Tell Envoy we're processing async
}

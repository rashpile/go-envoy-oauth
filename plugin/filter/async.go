package filter

import (
	"context"
	"fmt"
	"time"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
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
				f.handleAuthFailure(500, "Internal Server Error")
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

func (f *Filter) handleAsyncOAuthHandler(
	header api.RequestHeaderMap,
	traceID string, path string,
	callback func(header api.RequestHeaderMap, path string, traceID string) api.StatusType) api.StatusType {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				f.logger.Error("Panic in async callback", zap.Any("panic", r))
				f.handleAuthFailure(500, "Internal Server Error")
			}
		}()

		f.mu.Lock()
		// Double check after acquiring lock
		if f.oauthHandler == nil {
			// Check if we should retry or if we're still in backoff
			if !f.config.RetryManager.ShouldRetry() {
				f.mu.Unlock()
				retryInfo := f.config.RetryManager.GetRetryInfo()
				f.logger.Debug("OAuth handler creation in backoff period",
					zap.String("trace_id", traceID),
					zap.String("retry_info", retryInfo))
				f.errorHandler.HandleIDPUnavailable()
				return
			}

			f.logger.Debug("Attempting to create OAuth handler",
				zap.String("trace_id", traceID))
			_, err := f.createOAuthHandler(f.config, f.cookieManager)
			if err != nil {
				f.mu.Unlock()
				f.logger.Warn("Failed to create OAuth handler on-demand",
					zap.String("error", err.Error()))
				// Record the error for retry management
				f.config.RetryManager.RecordError(fmt.Errorf("OAuth provider unavailable: %v", err))
				f.errorHandler.HandleIDPUnavailable()
				return
			}
			// Success! Clear any previous errors
			f.config.RetryManager.ClearError()
			f.logger.Debug("OAuth handler created successfully after retry",
				zap.String("trace_id", traceID))
		}
		f.mu.Unlock()
		status := callback(header, path, traceID)
		switch status {
		case api.LocalReply:
			// Local reply was sent successfully
		case api.Continue:
			f.callbacks.DecoderFilterCallbacks().Continue(api.Continue)
		default:
			f.logger.Warn("Unexpected status in OAuth handler",
				zap.String("trace_id", traceID),
				zap.Int("status", int(status)))
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
				f.handleAuthFailure(500, "Internal Server Error")
			}
		}()

		if err := f.oauthHandler.ValidateSession(session); err != nil {
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

func (f *Filter) handleAsyncCallback(header api.RequestHeaderMap, query string, traceID string) api.StatusType {
	go func() {
		// Add panic recovery
		defer func() {
			if r := recover(); r != nil {
				f.logger.Error("Panic in async callback", zap.Any("panic", r))
				f.handleAuthFailure(500, "Internal Server Error")
			}
		}()
		err := f.oauthHandler.HandleCallback(header, query)
		if err != nil {
			f.logger.Error("Failed to handle OAuth callback",
				zap.String("trace_id", traceID),
				zap.Error(err))
			f.handleAuthFailure(400, "Bad Request: Invalid OAuth callback")
			// Don't need to return anything - SendLocalReply already called
			return
		}

		// Get the session ID from the set-cookie header
		sessionID, exists := header.Get("set-cookie")
		if !exists || sessionID == "" {
			f.logger.Error("Failed to get session cookie",
				zap.String("trace_id", traceID),
				zap.Error(err))
			f.handleAuthFailure(500, "Internal Server Error: Failed to get session cookie")
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

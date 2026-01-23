package filter

import (
	"fmt"
	"sync"
	"time"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"go.uber.org/zap"
)

// ErrorHandler manages error responses and IDP unavailability
type ErrorHandler struct {
	logger    *zap.Logger
	callbacks api.FilterCallbackHandler
}

// NewErrorHandler creates a new error handler
func NewErrorHandler(logger *zap.Logger, callbacks api.FilterCallbackHandler) *ErrorHandler {
	return &ErrorHandler{
		logger:    logger,
		callbacks: callbacks,
	}
}

// HandleIDPUnavailable returns a user-friendly error page when IDP is unavailable
func (eh *ErrorHandler) HandleIDPUnavailable() api.StatusType {
	eh.logger.Warn("Identity Provider is temporarily unavailable")

	html := `<!DOCTYPE html>
<html>
<head>
    <title>Service Temporarily Unavailable</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: #f5f5f5;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .error-container {
            text-align: center;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            max-width: 500px;
        }
        h1 {
            color: #e74c3c;
            margin-bottom: 20px;
        }
        p {
            color: #666;
            line-height: 1.6;
            margin-bottom: 20px;
        }
        .retry-info {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
        }
        .retry-button {
            display: inline-block;
            margin-top: 20px;
            padding: 12px 24px;
            background-color: #007bff;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            transition: background-color 0.3s;
        }
        .retry-button:hover {
            background-color: #0056b3;
        }
    </style>
</head>
<body>
    <div class="error-container">
        <h1>Service Temporarily Unavailable</h1>
        <p>We're unable to connect to the authentication service at the moment. This is usually temporary and should be resolved shortly.</p>
        <div class="retry-info">
            <p><strong>What you can try:</strong></p>
            <ul style="text-align: left; color: #666;">
                <li>Wait a few moments and refresh the page</li>
                <li>Check your internet connection</li>
                <li>Clear your browser cache and cookies</li>
            </ul>
        </div>
        <a href="javascript:location.reload()" class="retry-button">Retry</a>
    </div>
</body>
</html>`

	headers := map[string][]string{
		"Content-Type":  {"text/html; charset=utf-8"},
		"Cache-Control": {"no-cache, no-store, must-revalidate"},
	}

	eh.callbacks.DecoderFilterCallbacks().SendLocalReply(
		503,               // Service Unavailable
		html,              // HTML body
		headers,           // headers
		-1,                // grpcStatus
		"idp_unavailable", // details
	)

	return api.LocalReply
}

// HandleAuthFailure creates appropriate response for authentication failures
func (eh *ErrorHandler) HandleAuthFailure(statusCode int, message string) api.StatusType {
	eh.logger.Debug("Authentication failure",
		zap.Int("status_code", statusCode),
		zap.String("message", message))

	headers := map[string][]string{
		"content-type":     {"text/plain"},
		"www-authenticate": {"Bearer"},
	}

	eh.callbacks.DecoderFilterCallbacks().SendLocalReply(
		statusCode,     // responseCode
		message,        // bodyText
		headers,        // headers
		-1,             // grpcStatus
		"auth_failure", // details
	)

	return api.LocalReply
}

// HandleAccessDenied returns the access denied page
func (eh *ErrorHandler) HandleAccessDenied() api.StatusType {
	eh.logger.Info("Rendering access denied page")

	html := `<!DOCTYPE html>
<html>
<head>
    <title>Access Denied</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: #f5f5f5;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .error-container {
            text-align: center;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            max-width: 500px;
        }
        h1 {
            color: #e74c3c;
            margin-bottom: 20px;
        }
        p {
            color: #666;
            line-height: 1.6;
            margin-bottom: 20px;
        }
        .info-box {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
            text-align: left;
        }
        .button {
            display: inline-block;
            margin-top: 20px;
            padding: 12px 24px;
            background-color: #007bff;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            transition: background-color 0.3s;
            margin-right: 10px;
        }
        .button:hover {
            background-color: #0056b3;
        }
        .button.secondary {
            background-color: #6c757d;
        }
        .button.secondary:hover {
            background-color: #545b62;
        }
    </style>
</head>
<body>
    <div class="error-container">
        <h1>Access Denied</h1>
        <p>You don't have permission to access this resource.</p>
        <div class="info-box">
            <p><strong>What you can do:</strong></p>
            <ul style="color: #666;">
                <li>Contact your administrator to request access</li>
                <li>Verify you're using the correct account</li>
                <li>Try logging in with a different account</li>
            </ul>
        </div>
        <a href="/" class="button">Go Home</a>
        <a href="/oauth/logout" class="button secondary">Switch Account</a>
    </div>
</body>
</html>`

	headers := map[string][]string{
		"Content-Type":  {"text/html; charset=utf-8"},
		"Cache-Control": {"no-cache, no-store, must-revalidate"},
	}

	eh.callbacks.DecoderFilterCallbacks().SendLocalReply(
		403,              // Forbidden
		html,             // HTML body
		headers,          // headers
		-1,               // grpcStatus
		"access_denied",  // details
	)

	return api.LocalReply
}

// IDPRetryManager manages retry logic for IDP unavailability
type IDPRetryManager struct {
	handlerError      error
	handlerErrorTime  time.Time
	handlerRetryAfter time.Duration
	mu                sync.RWMutex // Protects all fields for thread safety
}

// NewIDPRetryManager creates a new IDP retry manager
func NewIDPRetryManager() *IDPRetryManager {
	return &IDPRetryManager{}
}

// ShouldRetry checks if we should retry IDP connection
func (rm *IDPRetryManager) ShouldRetry() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if rm.handlerError == nil {
		return true
	}
	return time.Since(rm.handlerErrorTime) >= rm.handlerRetryAfter
}

// RecordError records an IDP connection error with exponential backoff
func (rm *IDPRetryManager) RecordError(err error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.handlerError = err
	rm.handlerErrorTime = time.Now()

	// Exponential backoff: start at 5 seconds, double each time, max 5 minutes
	if rm.handlerRetryAfter == 0 {
		rm.handlerRetryAfter = 5 * time.Second
	} else {
		rm.handlerRetryAfter *= 2
		if rm.handlerRetryAfter > 5*time.Minute {
			rm.handlerRetryAfter = 5 * time.Minute
		}
	}
}

// ClearError clears the error state
func (rm *IDPRetryManager) ClearError() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.handlerError = nil
	rm.handlerErrorTime = time.Time{}
	rm.handlerRetryAfter = 0
}

// GetError returns the current error
func (rm *IDPRetryManager) GetError() error {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	return rm.handlerError
}

// GetRetryInfo returns formatted retry information
func (rm *IDPRetryManager) GetRetryInfo() string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if rm.handlerError == nil {
		return ""
	}
	nextRetry := rm.handlerErrorTime.Add(rm.handlerRetryAfter)
	return fmt.Sprintf("Next retry in %v (at %v)",
		time.Until(nextRetry).Round(time.Second),
		nextRetry.Format("15:04:05"))
}
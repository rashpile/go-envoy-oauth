# Envoy Go Plugin Development Guide

## Asynchronous Filter Processing

### Overview

Envoy Go filters support asynchronous processing using goroutines with the `api.Running` status. This pattern is crucial for operations that may block or take significant time, such as OAuth callbacks that involve external HTTP calls.

### When to Use Async Processing

**Use async processing for:**
- External HTTP/API calls (OAuth token exchange, user info fetching)
- Database queries or other I/O operations
- Long-running computations
- Operations that would block Envoy worker threads

**Avoid async processing for:**
- Simple header/cookie validation
- Fast in-memory lookups
- Operations that complete in microseconds

### How It Works

1. **Return `api.Running`**: Tells Envoy the filter is still processing
2. **Launch goroutine**: Performs the async work
3. **Call callbacks**: Use `SendLocalReply()` or `Continue()` to complete the request

### Implementation Pattern

```go
func (f *Filter) DecodeHeaders(header api.RequestHeaderMap, endStream bool) api.StatusType {
    // Quick synchronous checks first
    if !needsAsyncProcessing(header) {
        return api.Continue
    }

    // Launch async processing
    go func() {
        // CRITICAL: Add panic recovery
        defer func() {
            if r := recover(); r != nil {
                f.logger.Error("Panic in async processing", zap.Any("panic", r))
                f.callbacks.SendLocalReply(500, "Internal Server Error", nil, 0, "panic")
            }
        }()

        // Perform async work
        result, err := performAsyncOperation()
        if err != nil {
            f.callbacks.SendLocalReply(500, err.Error(), nil, 0, "error")
            return
        }

        // Complete the request
        f.callbacks.Continue(api.Continue)
        // OR send a response
        f.callbacks.SendLocalReply(200, result, headers, 0, "success")
    }()

    return api.Running
}
```

### Critical Requirements

1. **Always complete the request**: You MUST call either `SendLocalReply()` or `Continue()` to complete request processing
2. **Panic recovery**: Always use defer/recover in goroutines to prevent crashes
3. **Store callbacks**: Keep the `api.FilterCallbackHandler` reference in your filter struct
4. **No return values in goroutines**: The goroutine's return values are ignored

### OAuth Callback Example

The OAuth callback handler uses async processing because it:
- Makes external HTTP calls to the identity provider
- Exchanges authorization codes for tokens
- Fetches user information

```go
func (f *Filter) handleAsyncCallback(header api.RequestHeaderMap, query string, traceID string) api.StatusType {
    go func() {
        defer func() {
            if r := recover(); r != nil {
                f.logger.Error("Panic in OAuth callback",
                    zap.String("trace_id", traceID),
                    zap.Any("panic", r))
                f.handleAuthFailure(500, "Internal Server Error")
            }
        }()

        // Exchange code for token (external HTTP call)
        err := f.oauthHandler.HandleCallback(header, query)
        if err != nil {
            f.logger.Error("OAuth callback failed",
                zap.String("trace_id", traceID),
                zap.Error(err))
            f.handleAuthFailure(400, "Invalid OAuth callback")
            return
        }

        // Get session cookie and redirect URL
        sessionID, _ := header.Get("set-cookie")
        redirectURI, _ := header.Get("location")
        if redirectURI == "" {
            redirectURI = "/"
        }

        // Send redirect response with session cookie
        f.handleRedirect(redirectURI, sessionID)
    }()

    return api.Running
}
```

### Avoiding Deadlocks

When using async processing in service-to-service scenarios (Service A → Envoy → Service B → Envoy → Service C):

**Problem**: Synchronous processing can exhaust Envoy worker threads, causing resource deadlocks.

**Solution**: Use async processing for operations that:
- Make upstream HTTP calls
- Wait for external responses
- Could block worker threads

### Performance Considerations

1. **Goroutine overhead**: Each goroutine has a small memory overhead (~2KB stack)
2. **Context switching**: OS thread scheduling costs when switching between goroutines
3. **Memory copies**: Data passed between C++ and Go involves copying

### Common Pitfalls

1. **Forgetting to complete requests**: Not calling `SendLocalReply()` or `Continue()` leaves requests hanging
2. **Missing panic recovery**: Panics in goroutines crash the entire filter
3. **Using wrong status**: Returning `api.Continue` instead of `api.Running` when launching goroutines
4. **Accessing request data after completion**: Headers/body may be invalid after the request completes

### Debugging Tips

1. Add trace IDs to all async operations for correlation
2. Log before launching goroutines and when completing requests
3. Monitor goroutine counts to detect leaks
4. Use timeouts for external calls to prevent hanging requests

### References

- [Envoy Go SDK Documentation](https://www.envoyproxy.io/docs/envoy/latest/start/sandboxes/golang)
- [Envoy Filter Status Types](https://github.com/envoyproxy/envoy/blob/main/contrib/golang/common/go/api/type.go)
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

### Critical: Avoiding Worker Thread Deadlocks

#### The Circular Dependency Problem

A critical deadlock scenario occurs when the OAuth provider (e.g., Keycloak) is behind the same Envoy proxy that performs authentication:

```
User Request → Envoy:8081 → Backend (requires auth)
                ↓
         OAuth Callback triggered
                ↓
         Filter calls http://localhost:8081/auth/token
                ↓
         Request goes BACK to Envoy:8081
                ↓
         Envoy routes to Keycloak
                ↓
         ⚠️ DEADLOCK: All worker threads busy waiting for OAuth
```

#### Why This Causes a Deadlock

1. **Envoy uses a fixed pool of worker threads** (default: number of CPU cores)
2. **Synchronous OAuth callback** holds Worker Thread #1 while making HTTP call to IdP
3. **IdP request needs a worker thread** but all threads are busy with OAuth callbacks
4. **Result**: 60+ second timeout and request failure

#### Why `exclude: true` Doesn't Prevent This

Even if Keycloak routes have `exclude: true` in configuration:
```yaml
clients:
  - id: keycloak
    address: keycloak
    exclude: true  # This skips auth, but...
```

The deadlock occurs **before** the exclusion check can run - the request needs a worker thread to even enter the filter where the check happens.

#### Solution: Async Processing

The async implementation solves this by immediately freeing worker threads:

```go
func (f *Filter) handleAsyncCallback(...) api.StatusType {
    go func() {
        // OAuth HTTP calls happen in goroutine
        // Worker thread is already freed
        err := f.oauthHandler.HandleCallback(header, query)
        // ...
    }()
    return api.Running  // Frees worker thread immediately!
}
```

**Result**: Worker threads are available for the OAuth provider requests, breaking the deadlock cycle.

#### Alternative Solutions

If async processing is not feasible:
1. **Increase worker threads**: `envoy --concurrency 8` (or higher)
2. **Direct IdP connection**: Configure `ISSUER_URL` to bypass Envoy (e.g., `http://keycloak:8080` instead of `http://localhost:8081`)
3. **Separate Envoy instance**: Use different Envoy proxy for IdP traffic

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
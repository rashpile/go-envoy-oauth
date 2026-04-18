package filter

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rashpile/go-envoy-oauth/plugin/metrics"
	"github.com/rashpile/go-envoy-oauth/plugin/oauth"
	"github.com/rashpile/go-envoy-oauth/plugin/session"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

// ProviderRegistry holds one OAuthHandler per named provider.
// Phase 5 (HLTH-01, HLTH-03): handlers are initialized concurrently via
// errgroup.Group.SetLimit(5). Providers whose initial OIDC discovery fails are
// registered as *oauth.DownHandler (D-01); Parse() still completes normally
// (partial-startup tolerance, supersedes Phase 2 D-07).
type ProviderRegistry struct {
	handlers       map[string]oauth.OAuthHandler
	mu             sync.RWMutex
	logger         *zap.Logger
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
}

// initConcurrencyLimit bounds simultaneous OIDC discovery attempts (D-11).
// Not configurable in v1.0 — sensible for typical 2-10 provider deployments.
const initConcurrencyLimit = 5

// initOverallTimeout wraps the entire InitAll fan-out (D-12). Reuses the same
// 30-second value as asyncOperationTimeout in async.go.
const initOverallTimeout = 30 * time.Second

// NewProviderRegistry creates an empty ProviderRegistry with a cancellable
// shutdown context that refresher goroutines (Plan 03) will consume.
func NewProviderRegistry(logger *zap.Logger) *ProviderRegistry {
	ctx, cancel := context.WithCancel(context.Background())
	return &ProviderRegistry{
		handlers:       make(map[string]oauth.OAuthHandler),
		logger:         logger,
		shutdownCtx:    ctx,
		shutdownCancel: cancel,
	}
}

// Register adds a handler to the registry under the given provider name.
// Intended for use during initialization (InitAll) and in tests.
func (r *ProviderRegistry) Register(name string, handler oauth.OAuthHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[name] = handler
}

// GetHandler returns the handler for the named provider. Returns nil and an
// error if no handler is registered under that name.
func (r *ProviderRegistry) GetHandler(name string) (oauth.OAuthHandler, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.handlers[name]
	if !ok {
		return nil, fmt.Errorf("provider %q not found in registry", name)
	}
	return h, nil
}

// ShutdownContext returns the registry-owned context that Plan 03's refresher
// goroutines must consume. Cancelled by Shutdown().
func (r *ProviderRegistry) ShutdownContext() context.Context {
	return r.shutdownCtx
}

// Shutdown cancels the registry's shutdown context, signalling any background
// goroutines (e.g., Plan 03 refreshers) to stop.
//
// Envoy's Go filter SDK has no config-object destroy callback (per Research
// Pitfall 4). The filter pipeline must call Shutdown() explicitly on config
// supersession, or accept bounded goroutine leak on config reload.
func (r *ProviderRegistry) Shutdown() {
	r.shutdownCancel()
}

// providerInitResult captures the outcome of a single provider init goroutine.
type providerInitResult struct {
	name    string
	handler oauth.OAuthHandler
	err     error
}

// InitAll initializes one OAuthHandler per entry in providers concurrently
// using errgroup.Group.SetLimit(5) (HLTH-01). A provider whose OIDC discovery
// fails is registered as *oauth.DownHandler (HLTH-03, D-01).
//
// The method ALWAYS returns nil for OIDC-discovery failures. It returns a
// non-nil error only for structural problems (cookie manager creation).
//
// Each provider's cookie manager uses a clone of cookieConfig with
// Name = "<base>_<providerName>" (D-01 from Phase 3).
func (r *ProviderRegistry) InitAll(
	providers map[string]ProviderConfig,
	sessionStore session.SessionStore,
	cookieConfig *session.CookieConfig,
) error {
	if len(providers) == 0 {
		return nil
	}

	initCtx, cancel := context.WithTimeout(context.Background(), initOverallTimeout)
	defer cancel()

	// Pre-build cookie managers synchronously. Cookie-manager failures are
	// config-shape problems (not IDP availability), so they DO propagate as
	// hard errors — matching the pre-Phase-5 contract.
	type providerJob struct {
		name          string
		cfg           *oauth.OIDCConfig
		cookieManager *session.CookieManager
	}
	jobs := make([]providerJob, 0, len(providers))
	for name, pc := range providers {
		providerCookieConfig := cookieConfig.Clone()
		providerCookieConfig.Name = cookieConfig.Name + "_" + name
		cm, err := session.NewCookieManager(nil, nil, providerCookieConfig)
		if err != nil {
			return fmt.Errorf("provider %q: failed to create cookie manager: %w", name, err)
		}
		jobs = append(jobs, providerJob{
			name: name,
			cfg: &oauth.OIDCConfig{
				ProviderName: name,
				IssuerURL:    pc.IssuerURL,
				ClientID:     pc.ClientID,
				ClientSecret: pc.ClientSecret,
				RedirectURL:  pc.RedirectURL,
				Scopes:       pc.Scopes,
			},
			cookieManager: cm,
		})
	}

	// Plain errgroup.Group + SetLimit — NOT WithContext (Pitfall 1 in research).
	// WithContext cancels siblings on first error; we need every goroutine to
	// complete independently for partial-startup tolerance (HLTH-03, D-09).
	var g errgroup.Group
	g.SetLimit(initConcurrencyLimit)

	results := make([]providerInitResult, len(jobs))
	start := time.Now()

	for i, job := range jobs {
		i, job := i, job // capture loop vars
		g.Go(func() error {
			// Respect the 30s deadline on the init context. If the context is
			// already done when this goroutine starts (rare — slow scheduler),
			// record a context error and move on.
			if err := initCtx.Err(); err != nil {
				results[i] = providerInitResult{name: job.name, err: fmt.Errorf("init context expired before start: %w", err)}
				return nil
			}

			// NewOAuthHandler performs OIDC discovery synchronously; it does
			// not accept a context today. Wrap it in a result channel so we
			// can honor initCtx cancellation.
			done := make(chan providerInitResult, 1)
			go func() {
				h, err := oauth.NewOAuthHandler(job.cfg, sessionStore, job.cookieManager, r.logger)
				done <- providerInitResult{name: job.name, handler: h, err: err}
			}()

			select {
			case res := <-done:
				results[i] = res
			case <-initCtx.Done():
				// Deadline fired — try a non-blocking drain first. If the inner
				// goroutine completed just as the deadline fired, use its result
				// rather than recording a spurious timeout and starting a recovery
				// loop for a provider that actually succeeded.
				select {
				case res := <-done:
					results[i] = res
				default:
					results[i] = providerInitResult{
						name: job.name,
						err:  fmt.Errorf("OIDC discovery exceeded init timeout: %w", initCtx.Err()),
					}
				}
			}
			return nil // per-provider errors are captured, never propagated
		})
	}

	_ = g.Wait() // never returns error (all goroutines return nil)

	// Register handlers (success → real handler; failure → DownHandler).
	// For every successfully created handler, start a background JWKS refresher
	// goroutine (HLTH-04). The goroutine consumes the registry's shutdown context
	// so it stops when Shutdown() is called.
	var readyCount, downCount int
	for i, res := range results {
		if res.err != nil {
			r.logger.Warn("provider init failed, registering as down",
				zap.String("provider", res.name),
				zap.Error(res.err))
			r.Register(res.name, &oauth.DownHandler{ProviderName: res.name})
			metrics.UpdateIDPState(res.name, "down")
			r.startDownHandlerRecovery(res.name, jobs[i].cfg, sessionStore, jobs[i].cookieManager)
			downCount++
		} else {
			r.Register(res.name, res.handler)
			// Initial "ready" state already emitted by NewOAuthHandler.
			// Start background refresher for live handlers only.
			if impl, ok := res.handler.(*oauth.OAuthHandlerImpl); ok {
				impl.StartRefresher(r.shutdownCtx)
			}
			readyCount++
		}
	}

	r.logger.Info("provider registry init complete",
		zap.Int("ready", readyCount),
		zap.Int("down", downCount),
		zap.Int("total", len(jobs)),
		zap.Int64("duration_ms", time.Since(start).Milliseconds()))

	return nil
}

// startDownHandlerRecovery spawns a background goroutine that retries
// NewOAuthHandler for a provider whose initial OIDC discovery failed.
// On success it atomically swaps the DownHandler for the live handler and
// starts the JWKS refresher. Uses the same exponential backoff schedule as the
// JWKS refresher (InitialBackoff → MaxBackoff with ±20% jitter).
func (r *ProviderRegistry) startDownHandlerRecovery(
	name string,
	cfg *oauth.OIDCConfig,
	sessionStore session.SessionStore,
	cookieManager *session.CookieManager,
) {
	go func() {
		backoff := oauth.InitialBackoff
		for {
			select {
			case <-r.shutdownCtx.Done():
				r.logger.Info("down-handler recovery cancelled",
					zap.String("provider", name))
				return
			case <-time.After(backoff):
			}

			r.logger.Info("retrying OIDC discovery for down provider",
				zap.String("provider", name),
				zap.Duration("backoff", backoff))

			h, err := oauth.NewOAuthHandler(cfg, sessionStore, cookieManager, r.logger)
			if err != nil {
				r.logger.Warn("down-provider recovery attempt failed",
					zap.String("provider", name),
					zap.Error(err))
				backoff = oauth.JitteredBackoff(backoff)
				continue
			}

			r.mu.Lock()
			r.handlers[name] = h
			r.mu.Unlock()

			if impl, ok := h.(*oauth.OAuthHandlerImpl); ok {
				impl.StartRefresher(r.shutdownCtx)
			}

			r.logger.Info("down-provider recovery succeeded, handler is live",
				zap.String("provider", name))
			return
		}
	}()
}

package filter

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"go.uber.org/zap"
)

// asyncDecoderCallbacks mimics the SDK for async tests. When destroyed is set,
// SendLocalReply panics the way the real SDK does once the downstream stream
// is gone. RecoverPanic reports what it recovered on the recovered channel.
type asyncDecoderCallbacks struct {
	api.DecoderFilterCallbacks
	destroyed bool
	recovered chan interface{}
	replied   chan int
	continued chan struct{}
}

func newAsyncDecoderCallbacks(destroyed bool) *asyncDecoderCallbacks {
	return &asyncDecoderCallbacks{
		destroyed: destroyed,
		recovered: make(chan interface{}, 4),
		replied:   make(chan int, 4),
		continued: make(chan struct{}, 4),
	}
}

func (c *asyncDecoderCallbacks) SendLocalReply(code int, _ string, _ map[string][]string, _ int64, _ string) {
	if c.destroyed {
		panic("golang filter has been destroyed")
	}
	c.replied <- code
}

func (c *asyncDecoderCallbacks) Continue(api.StatusType) { c.continued <- struct{}{} }

func (c *asyncDecoderCallbacks) RecoverPanic() {
	if r := recover(); r != nil {
		c.recovered <- r
	}
}

type asyncCallbacks struct {
	api.FilterCallbackHandler
	decoder *asyncDecoderCallbacks
}

func (c *asyncCallbacks) DecoderFilterCallbacks() api.DecoderFilterCallbacks { return c.decoder }

type failingCallbackHandler struct{ mockOAuthHandler }

func (h *failingCallbackHandler) HandleCallback(_ api.RequestHeaderMap, _ string) error {
	return errors.New("code exchange failed")
}

func waitRecovered(t *testing.T, dec *asyncDecoderCallbacks) interface{} {
	t.Helper()
	select {
	case r := <-dec.recovered:
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("RecoverPanic did not recover a panic within 2s")
		return nil
	}
}

// TestAsyncCallbackSurvivesDestroyedStream verifies that a reply attempted after
// the client went away is absorbed by RecoverPanic instead of re-panicking
// inside the recover block and killing the Envoy process (issue #8).
func TestAsyncCallbackSurvivesDestroyedStream(t *testing.T) {
	dec := newAsyncDecoderCallbacks(true)
	f := &Filter{
		config:    &OAuthConfig{Clusters: map[string]ClusterConfig{}},
		callbacks: &asyncCallbacks{decoder: dec},
		logger:    zap.NewNop(),
	}

	if got := f.handleAsyncCallback(&capturingHeaderMap{headers: map[string]string{}}, "state=s&code=c", "s", "trace", &failingCallbackHandler{}); got != api.Running {
		t.Fatalf("handleAsyncCallback = %v, want api.Running", got)
	}
	if r := waitRecovered(t, dec); r != "golang filter has been destroyed" {
		t.Errorf("recovered %v, want the destroyed-stream panic", r)
	}
}

// TestAsyncDecodeHeadersRecoversCallbackPanic verifies that a panic inside the
// async callback (for example in the API-key exchange) is recovered in the
// goroutine that raised it and does not leave the outer goroutine waiting for
// the timeout.
func TestAsyncDecodeHeadersRecoversCallbackPanic(t *testing.T) {
	dec := newAsyncDecoderCallbacks(false)
	f := &Filter{
		config:    &OAuthConfig{Clusters: map[string]ClusterConfig{}},
		callbacks: &asyncCallbacks{decoder: dec},
		logger:    zap.NewNop(),
	}

	got := f.handleAsyncDecodeHeaders(&capturingHeaderMap{headers: map[string]string{}}, "/private", "trace",
		func(context.Context, api.RequestHeaderMap, string, string) api.StatusType {
			var s []byte
			_ = s[:32] // same failure shape as the old API-key cache key
			return api.Continue
		})
	if got != api.Running {
		t.Fatalf("handleAsyncDecodeHeaders = %v, want api.Running", got)
	}
	waitRecovered(t, dec)

	select {
	case code := <-dec.replied:
		t.Errorf("unexpected local reply %d after recovered panic", code)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestAsyncTimeoutReplyIsTheOnlyReply verifies that when the async timeout
// answers 504, the callback's context is cancelled and its late reply is
// dropped instead of answering the stream a second time.
func TestAsyncTimeoutReplyIsTheOnlyReply(t *testing.T) {
	old := asyncOperationTimeout
	asyncOperationTimeout = 50 * time.Millisecond
	t.Cleanup(func() { asyncOperationTimeout = old })

	dec := &captureDecoderCallbacks{done: make(chan struct{}, 4)}
	f := buildCallbackFilter(&captureCallbacks{decoder: dec})
	release := make(chan struct{})
	cancelled := make(chan struct{})

	got := f.handleAsyncDecodeHeaders(&capturingHeaderMap{headers: map[string]string{}}, "/private", "trace",
		func(ctx context.Context, _ api.RequestHeaderMap, _ string, _ string) api.StatusType {
			<-ctx.Done()
			close(cancelled)
			<-release
			return f.recordAndSendLocalReply(401, "late", nil, -1, "late")
		})
	if got != api.Running {
		t.Fatalf("handleAsyncDecodeHeaders = %v, want api.Running", got)
	}

	select {
	case <-dec.done:
	case <-time.After(2 * time.Second):
		t.Fatal("no timeout reply within 2s")
	}
	if dec.statusCode != 504 {
		t.Fatalf("status = %d, want 504", dec.statusCode)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("callback context was not cancelled by the timeout")
	}

	close(release)
	select {
	case <-dec.done:
		t.Errorf("a second reply reached the stream (status %d)", dec.statusCode)
	case <-time.After(200 * time.Millisecond):
	}
	if dec.replies != 1 {
		t.Errorf("SendLocalReply calls = %d, want 1", dec.replies)
	}
}

// TestErrorHandlerRespectsReplyGate verifies that the error pages share the
// filter's one-reply-per-stream gate.
func TestErrorHandlerRespectsReplyGate(t *testing.T) {
	dec := &captureDecoderCallbacks{}
	f, err := NewFilter(&OAuthConfig{Clusters: map[string]ClusterConfig{}}, &captureCallbacks{decoder: dec})
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}

	f.recordAndSendLocalReply(401, "first", nil, -1, "first")
	f.errorHandler.HandleAuthFailure(500, "second")
	f.errorHandler.HandleIDPUnavailable()
	f.errorHandler.HandleAccessDenied()

	if dec.replies != 1 || dec.statusCode != 401 {
		t.Errorf("replies = %d, last status = %d; want only the first 401", dec.replies, dec.statusCode)
	}
}

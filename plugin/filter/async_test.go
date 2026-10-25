package filter

import (
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
		func(api.RequestHeaderMap, string, string) api.StatusType {
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

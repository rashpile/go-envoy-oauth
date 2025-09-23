package filter

import (
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
)

type RequestState struct {
	finished atomic.Bool
}

func NewRequestState() *RequestState {
	return &RequestState{}
}

func (state *RequestState) IsFinished() bool {
	return state.finished.Load()
}

func CallbackError(callbacks *api.FilterCallbackHandler, appError error, statusCode int) {
	state := NewRequestState()
	SafeSendLocalReply(
		callbacks,
		state,
		statusCode,
		fmt.Sprintf(`{"message":"%s"}`, appError.Error()),
		map[string][]string{
			"Content-Type": {"application/json"},
		},
		0,
		"local_reply",
	)
}
func CallbackReply(callbacks *api.FilterCallbackHandler, body string) {
	state := NewRequestState()
	SafeSendLocalReply(
		callbacks,
		state,
		http.StatusOK,
		body,
		map[string][]string{
			"Content-Type": {"application/json"},
		},
		0,
		"",
	)
}

func CallbackRedirect(callbacks *api.FilterCallbackHandler, url string, cookieValue string) {
	state := NewRequestState()
	SafeSendLocalReply(
		callbacks,
		state,
		http.StatusFound,
		"",
		map[string][]string{
			"Location":     {url},
			"Content-Type": {"text/html"},
			"Set-Cookie":   {cookieValue},
		},
		0,
		"",
	)
}
func SafeSendLocalReply(callbacks *api.FilterCallbackHandler,
	state *RequestState,
	statusCode int,
	body string,
	headers map[string][]string,
	grpcStatus int64,
	details string) {

	// Skip if request is already finished
	if state != nil && state.IsFinished() {
		return
	}

	defer (*callbacks).DecoderFilterCallbacks().RecoverPanic()

	(*callbacks).DecoderFilterCallbacks().SendLocalReply(statusCode, body, headers, grpcStatus, details)
}

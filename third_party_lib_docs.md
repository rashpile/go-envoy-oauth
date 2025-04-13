# Go Lang Envoy Filter API
package api

import "google.golang.org/protobuf/types/known/anypb"

type (
	// PassThroughStreamEncoderFilter provides the no-op implementation of the StreamEncoderFilter interface.
	PassThroughStreamEncoderFilter struct{}
	// PassThroughStreamDecoderFilter provides the no-op implementation of the StreamDecoderFilter interface.
	PassThroughStreamDecoderFilter struct{}
	// PassThroughStreamFilter provides the no-op implementation of the StreamFilter interface.
	PassThroughStreamFilter struct {
		PassThroughStreamDecoderFilter
		PassThroughStreamEncoderFilter
	}

	// EmptyDownstreamFilter provides the no-op implementation of the DownstreamFilter interface
	EmptyDownstreamFilter struct{}
	// EmptyUpstreamFilter provides the no-op implementation of the UpstreamFilter interface
	EmptyUpstreamFilter struct{}

	// PassThroughHttpTcpBridge provides the no-op implementation of the HttpTcpBridge interface
	PassThroughHttpTcpBridge struct{}
)

// request
type StreamDecoderFilter interface {
	DecodeHeaders(RequestHeaderMap, bool) StatusType
	DecodeData(BufferInstance, bool) StatusType
	DecodeTrailers(RequestTrailerMap) StatusType
}

func (*PassThroughStreamDecoderFilter) DecodeHeaders(RequestHeaderMap, bool) StatusType {
	return Continue
}

func (*PassThroughStreamDecoderFilter) DecodeData(BufferInstance, bool) StatusType {
	return Continue
}

func (*PassThroughStreamDecoderFilter) DecodeTrailers(RequestTrailerMap) StatusType {
	return Continue
}

// response
type StreamEncoderFilter interface {
	EncodeHeaders(ResponseHeaderMap, bool) StatusType
	EncodeData(BufferInstance, bool) StatusType
	EncodeTrailers(ResponseTrailerMap) StatusType
}

func (*PassThroughStreamEncoderFilter) EncodeHeaders(ResponseHeaderMap, bool) StatusType {
	return Continue
}

func (*PassThroughStreamEncoderFilter) EncodeData(BufferInstance, bool) StatusType {
	return Continue
}

func (*PassThroughStreamEncoderFilter) EncodeTrailers(ResponseTrailerMap) StatusType {
	return Continue
}

type StreamFilter interface {
	// http request
	StreamDecoderFilter
	// response stream
	StreamEncoderFilter

	// log
	OnLog(RequestHeaderMap, RequestTrailerMap, ResponseHeaderMap, ResponseTrailerMap)
	OnLogDownstreamStart(RequestHeaderMap)
	OnLogDownstreamPeriodic(RequestHeaderMap, RequestTrailerMap, ResponseHeaderMap, ResponseTrailerMap)

	// destroy filter
	OnDestroy(DestroyReason)
	OnStreamComplete()
}

func (*PassThroughStreamFilter) OnLog(RequestHeaderMap, RequestTrailerMap, ResponseHeaderMap, ResponseTrailerMap) {
}

func (*PassThroughStreamFilter) OnLogDownstreamStart(RequestHeaderMap) {
}

func (*PassThroughStreamFilter) OnLogDownstreamPeriodic(RequestHeaderMap, RequestTrailerMap, ResponseHeaderMap, ResponseTrailerMap) {
}

func (*PassThroughStreamFilter) OnDestroy(DestroyReason) {
}

func (*PassThroughStreamFilter) OnStreamComplete() {
}

type StreamFilterConfigParser interface {
	// Parse the proto message to any Go value, and return error to reject the config.
	// This is called when Envoy receives the config from the control plane.
	// Also, you can define Metrics through the callbacks, and the callbacks will be nil when parsing the route config.
	Parse(any *anypb.Any, callbacks ConfigCallbackHandler) (interface{}, error)
	// Merge the two configs(filter level config or route level config) into one.
	// May merge multi-level configurations, i.e. filter level, virtualhost level, router level and weighted cluster level,
	// into a single one recursively, by invoking this method multiple times.
	Merge(parentConfig interface{}, childConfig interface{}) interface{}
}

type StreamFilterFactory func(config interface{}, callbacks FilterCallbackHandler) StreamFilter

// stream info
// refer https://github.com/envoyproxy/envoy/blob/main/envoy/stream_info/stream_info.h
type StreamInfo interface {
	GetRouteName() string
	FilterChainName() string
	// Protocol return the request's protocol.
	Protocol() (string, bool)
	// ResponseCode return the response code.
	ResponseCode() (uint32, bool)
	// ResponseCodeDetails return the response code details.
	ResponseCodeDetails() (string, bool)
	// AttemptCount return the number of times the request was attempted upstream.
	AttemptCount() uint32
	// Get the dynamic metadata of the request
	DynamicMetadata() DynamicMetadata
	// DownstreamLocalAddress return the downstream local address.
	DownstreamLocalAddress() string
	// DownstreamRemoteAddress return the downstream remote address.
	DownstreamRemoteAddress() string
	// UpstreamLocalAddress return the upstream local address.
	UpstreamLocalAddress() (string, bool)
	// UpstreamRemoteAddress return the upstream remote address.
	UpstreamRemoteAddress() (string, bool)
	// UpstreamClusterName return the upstream host cluster.
	UpstreamClusterName() (string, bool)
	// FilterState return the filter state interface.
	FilterState() FilterState
	// VirtualClusterName returns the name of the virtual cluster which got matched
	VirtualClusterName() (string, bool)
	// WorkerID returns the ID of the Envoy worker thread
	WorkerID() uint32
	// Some fields in stream info can be fetched via GetProperty
	// For example, startTime() is equal to GetProperty("request.time")
}

type StreamFilterCallbacks interface {
	StreamInfo() StreamInfo

	// ClearRouteCache clears the route cache for the current request, and filtermanager will re-fetch the route in the next filter.
	// Please be careful to invoke it, since filtermanager will raise an 404 route_not_found response when failed to re-fetch a route.
	ClearRouteCache()
	// RefreshRouteCache works like ClearRouteCache, but it will re-fetch the route immediately.
	RefreshRouteCache()
	Log(level LogType, msg string)
	LogLevel() LogType
	// GetProperty fetch Envoy attribute and return the value as a string.
	// The list of attributes can be found in https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/advanced/attributes.
	// If the fetch succeeded, a string will be returned.
	// If the value is a timestamp, it is returned as a timestamp string like "2023-07-31T07:21:40.695646+00:00".
	// If the fetch failed (including the value is not found), an error will be returned.
	//
	// The error can be one of:
	// * ErrInternalFailure
	// * ErrSerializationFailure (Currently, fetching attributes in List/Map type are unsupported)
	// * ErrValueNotFound
	GetProperty(key string) (string, error)
	// TODO add more for filter callbacks
}

// FilterProcessCallbacks is the interface for filter to process request/response in decode/encode phase.
type FilterProcessCallbacks interface {
	// Continue or SendLocalReply should be last API invoked, no more code after them.
	Continue(StatusType)
	SendLocalReply(responseCode int, bodyText string, headers map[string][]string, grpcStatus int64, details string)
	// RecoverPanic recover panic in defer and terminate the request by SendLocalReply with 500 status code.
	RecoverPanic()
	// AddData add extra data when processing headers/trailers.
	// For example, turn a headers only request into a request with a body, add more body when processing trailers, and so on.
	// The second argument isStreaming supplies if this caller streams data or buffers the full body.
	AddData(data []byte, isStreaming bool)
	// InjectData inject the content of slice data via Envoy StreamXXFilterCallbacks's injectXXDataToFilterChaininjectData.
	InjectData(data []byte)
}

type DecoderFilterCallbacks interface {
	FilterProcessCallbacks
}

type EncoderFilterCallbacks interface {
	FilterProcessCallbacks
}

type FilterCallbackHandler interface {
	StreamFilterCallbacks
	// DecoderFilterCallbacks could only be used in DecodeXXX phases.
	DecoderFilterCallbacks() DecoderFilterCallbacks
	// EncoderFilterCallbacks could only be used in EncodeXXX phases.
	EncoderFilterCallbacks() EncoderFilterCallbacks
}

type DynamicMetadata interface {
	Get(filterName string) map[string]interface{}
	Set(filterName string, key string, value interface{})
}

type DownstreamFilter interface {
	// Called when a connection is first established.
	OnNewConnection() FilterStatus
	// Called when data is read on the connection.
	OnData(buffer []byte, endOfStream bool) FilterStatus
	// Callback for connection events.
	OnEvent(event ConnectionEvent)
	// Called when data is to be written on the connection.
	OnWrite(buffer []byte, endOfStream bool) FilterStatus
}

func (*EmptyDownstreamFilter) OnNewConnection() FilterStatus {
	return NetworkFilterContinue
}

func (*EmptyDownstreamFilter) OnData(buffer []byte, endOfStream bool) FilterStatus {
	return NetworkFilterContinue
}

func (*EmptyDownstreamFilter) OnEvent(event ConnectionEvent) {
}

func (*EmptyDownstreamFilter) OnWrite(buffer []byte, endOfStream bool) FilterStatus {
	return NetworkFilterContinue
}

type UpstreamFilter interface {
	// Called when a connection is available to process a request/response.
	OnPoolReady(cb ConnectionCallback)
	// Called when a pool error occurred and no connection could be acquired for making the request.
	OnPoolFailure(poolFailureReason PoolFailureReason, transportFailureReason string)
	// Invoked when data is delivered from the upstream connection.
	OnData(buffer []byte, endOfStream bool)
	// Callback for connection events.
	OnEvent(event ConnectionEvent)
}

func (*EmptyUpstreamFilter) OnPoolReady(cb ConnectionCallback) {
}

func (*EmptyUpstreamFilter) OnPoolFailure(poolFailureReason PoolFailureReason, transportFailureReason string) {
}

func (*EmptyUpstreamFilter) OnData(buffer []byte, endOfStream bool) FilterStatus {
	return NetworkFilterContinue
}

func (*EmptyUpstreamFilter) OnEvent(event ConnectionEvent) {
}

type ConnectionCallback interface {
	// StreamInfo returns the stream info of the connection
	StreamInfo() StreamInfo
	// Write data to the connection.
	Write(buffer []byte, endStream bool)
	// Close the connection.
	Close(closeType ConnectionCloseType)
	// EnableHalfClose only for upstream connection
	EnableHalfClose(enabled bool)
}

type StateType int

const (
	StateTypeReadOnly StateType = 0
	StateTypeMutable  StateType = 1
)

type LifeSpan int

const (
	LifeSpanFilterChain LifeSpan = 0
	LifeSpanRequest     LifeSpan = 1
	LifeSpanConnection  LifeSpan = 2
	LifeSpanTopSpan     LifeSpan = 3
)

type StreamSharing int

const (
	None                             StreamSharing = 0
	SharedWithUpstreamConnection     StreamSharing = 1
	SharedWithUpstreamConnectionOnce StreamSharing = 2
)

type FilterState interface {
	SetString(key, value string, stateType StateType, lifeSpan LifeSpan, streamSharing StreamSharing)
	GetString(key string) string
}

type MetricType uint32

const (
	Counter   MetricType = 0
	Gauge     MetricType = 1
	Histogram MetricType = 2
)

type ConfigCallbacks interface {
	// Define a metric, for different MetricType, name must be different,
	// for same MetricType, the same name will share a metric.
	DefineCounterMetric(name string) CounterMetric
	DefineGaugeMetric(name string) GaugeMetric
	// TODO Histogram
}

type ConfigCallbackHandler interface {
	ConfigCallbacks
}

type CounterMetric interface {
	Increment(offset int64)
	Get() uint64
	Record(value uint64)
}

type GaugeMetric interface {
	Increment(offset int64)
	Get() uint64
	Record(value uint64)
}

// TODO
type HistogramMetric interface {
}

type HttpTcpBridgeCallbackHandler interface {
	// GetRouteName returns the name of the route which got matched
	GetRouteName() string
	// GetVirtualClusterName returns the name of the virtual cluster which got matched
	GetVirtualClusterName() string
	// SetSelfHalfCloseForUpstreamConn default is false
	SetSelfHalfCloseForUpstreamConn(enabled bool)
}

type HttpTcpBridge interface {

	// Invoked when header is delivered from the downstream.
	// Notice-1: when return HttpTcpBridgeContinue or HttpTcpBridgeStopAndBuffer, dataForSet is used to be sent to upstream; when return HttpTcpBridgeEndStream, dataForSet is useed to sent to downstream as response body.
	// Notice-2: headerMap and dataToUpstream cannot be invoked after the func return.
	EncodeHeaders(headerMap RequestHeaderMap, dataForSet BufferInstance, endOfStream bool) HttpTcpBridgeStatus

	// Streaming, Invoked when data is delivered from the downstream.
	// Notice: buffer cannot be invoked after the func return.
	EncodeData(buffer BufferInstance, endOfStream bool) HttpTcpBridgeStatus

	// Streaming, Called when data is read on from tcp upstream.
	// Notice-1: when return HttpTcpBridgeContinue, resp headers will be send to http all at once; from then on, you MUST NOT invoke responseHeaderForSet at any time(or you will get panic).
	// Notice-2: responseHeaderForSet and buffer cannot be invoked after the func return.
	OnUpstreamData(responseHeaderForSet ResponseHeaderMap, buffer BufferInstance, endOfStream bool) HttpTcpBridgeStatus

	// destroy filter
	OnDestroy()
}

func (*PassThroughHttpTcpBridge) EncodeHeaders(headerMap RequestHeaderMap, dataForSet BufferInstance, endOfStream bool) HttpTcpBridgeStatus {
	return HttpTcpBridgeContinue
}

func (*PassThroughHttpTcpBridge) EncodeData(buffer BufferInstance, endOfStream bool) HttpTcpBridgeStatus {
	return HttpTcpBridgeContinue
}

func (*PassThroughHttpTcpBridge) OnUpstreamData(responseHeaderForSet ResponseHeaderMap, buffer BufferInstance, endOfStream bool) HttpTcpBridgeStatus {
	return HttpTcpBridgeContinue
}

func (*PassThroughHttpTcpBridge) OnDestroy() {
}

type HttpTcpBridgeFactory func(config interface{}, callbacks HttpTcpBridgeCallbackHandler) HttpTcpBridge

type HttpTcpBridgeConfigParser interface {
	Parse(any *anypb.Any) (interface{}, error)
}




package api

import "errors"

// ****************** filter status start ******************//
type StatusType int

const (
	Running                StatusType = 0
	LocalReply             StatusType = 1
	Continue               StatusType = 2
	StopAndBuffer          StatusType = 3
	StopAndBufferWatermark StatusType = 4
	StopNoBuffer           StatusType = 5
)

// header status
// refer https://github.com/envoyproxy/envoy/blob/main/envoy/http/filter.h
const (
	HeaderContinue                     StatusType = 100
	HeaderStopIteration                StatusType = 101
	HeaderContinueAndDontEndStream     StatusType = 102
	HeaderStopAllIterationAndBuffer    StatusType = 103
	HeaderStopAllIterationAndWatermark StatusType = 104
)

// data status
// refer https://github.com/envoyproxy/envoy/blob/main/envoy/http/filter.h
const (
	DataContinue                  StatusType = 200
	DataStopIterationAndBuffer    StatusType = 201
	DataStopIterationAndWatermark StatusType = 202
	DataStopIterationNoBuffer     StatusType = 203
)

// Trailer status
// refer https://github.com/envoyproxy/envoy/blob/main/envoy/http/filter.h
const (
	TrailerContinue      StatusType = 300
	TrailerStopIteration StatusType = 301
)

//****************** filter status end ******************//

// ****************** log level start ******************//
type LogType int

// refer https://github.com/envoyproxy/envoy/blob/main/source/common/common/base_logger.h
const (
	Trace    LogType = 0
	Debug    LogType = 1
	Info     LogType = 2
	Warn     LogType = 3
	Error    LogType = 4
	Critical LogType = 5
)

func (self LogType) String() string {
	switch self {
	case Trace:
		return "trace"
	case Debug:
		return "debug"
	case Info:
		return "info"
	case Warn:
		return "warn"
	case Error:
		return "error"
	case Critical:
		return "critical"
	}
	return "unknown"
}

//******************* log level end *******************//

// ****************** HeaderMap start ******************//

// refer https://github.com/envoyproxy/envoy/blob/main/envoy/http/header_map.h
type HeaderMap interface {
	// GetRaw is unsafe, reuse the memory from Envoy
	GetRaw(name string) string

	// Get value of key
	// If multiple values associated with this key, first one will be returned.
	Get(key string) (string, bool)

	// Values returns all values associated with the given key.
	// The returned slice is not a copy.
	Values(key string) []string

	// Set key-value pair in header map, the previous pair will be replaced if exists.
	// It may not take affects immediately in the Envoy thread side when it's invoked in a Go thread.
	// This won't refresh route cache, please invoke ClearRouteCache if needed.
	Set(key, value string)

	// Add value for given key.
	// Multiple headers with the same key may be added with this function.
	// Use Set for setting a single header for the given key.
	// It may not take affects immediately in the Envoy thread side when it's invoked in a Go thread.
	// This won't refresh route cache, please invoke ClearRouteCache if needed.
	Add(key, value string)

	// Del delete pair of specified key
	// It may not take affects immediately in the Envoy thread side when it's invoked in a Go thread.
	// This won't refresh route cache, please invoke ClearRouteCache if needed.
	Del(key string)

	// Range calls f sequentially for each key and value present in the map.
	// If f returns false, range stops the iteration.
	// When there are multiple values of a key, f will be invoked multiple times with the same key and each value.
	Range(f func(key, value string) bool)

	// RangeWithCopy calls f sequentially for each key and value copied from the map.
	RangeWithCopy(f func(key, value string) bool)

	// GetAllHeaders returns all the headers.
	GetAllHeaders() map[string][]string
}

type RequestHeaderMap interface {
	HeaderMap
	Scheme() string
	Method() string
	Host() string
	Path() string
	// SetMethod set method in header map
	// This won't refresh route cache, please invoke ClearRouteCache if needed.
	SetMethod(method string)
	// SetHost set host in header map
	// This won't refresh route cache, please invoke ClearRouteCache if needed.
	SetHost(host string)
	// SetPath set path in header map
	// This won't refresh route cache, please invoke ClearRouteCache if needed.
	SetPath(path string)
	// Note: Scheme is the downstream protocol, we'd better not override it.
}

type RequestTrailerMap interface {
	HeaderMap
	// others
}

type ResponseHeaderMap interface {
	HeaderMap
	Status() (int, bool)
}

type ResponseTrailerMap interface {
	HeaderMap
	// others
}

type MetadataMap interface {
}

//****************** HeaderMap end ******************//

// *************** BufferInstance start **************//
type BufferAction int

const (
	SetBuffer     BufferAction = 0
	AppendBuffer  BufferAction = 1
	PrependBuffer BufferAction = 2
)

type DataBufferBase interface {
	// Write appends the contents of p to the buffer, growing the buffer as
	// needed. The return value n is the length of p; err is always nil. If the
	// buffer becomes too large, Write will panic with ErrTooLarge.
	Write(p []byte) (n int, err error)

	// WriteString appends the string to the buffer, growing the buffer as
	// needed. The return value n is the length of s; err is always nil. If the
	// buffer becomes too large, Write will panic with ErrTooLarge.
	WriteString(s string) (n int, err error)

	// WriteByte appends the byte to the buffer, growing the buffer as
	// needed. The return value n is the length of s; err is always nil. If the
	// buffer becomes too large, Write will panic with ErrTooLarge.
	WriteByte(p byte) error

	// WriteUint16 appends the uint16 to the buffer, growing the buffer as
	// needed. The return value n is the length of s; err is always nil. If the
	// buffer becomes too large, Write will panic with ErrTooLarge.
	WriteUint16(p uint16) error

	// WriteUint32 appends the uint32 to the buffer, growing the buffer as
	// needed. The return value n is the length of s; err is always nil. If the
	// buffer becomes too large, Write will panic with ErrTooLarge.
	WriteUint32(p uint32) error

	// WriteUint64 appends the uint64 to the buffer, growing the buffer as
	// needed. The return value n is the length of s; err is always nil. If the
	// buffer becomes too large, Write will panic with ErrTooLarge.
	WriteUint64(p uint64) error

	// Bytes returns all bytes from buffer, without draining any buffered data.
	// It can be used to get fixed-length content, such as headers, body.
	// Note: do not change content in return bytes, use write instead
	Bytes() []byte

	// Drain drains a offset length of bytes in buffer.
	// It can be used with Bytes(), after consuming a fixed-length of data
	Drain(offset int)

	// Len returns the number of bytes of the unread portion of the buffer;
	// b.Len() == len(b.Bytes()).
	Len() int

	// Reset resets the buffer to be empty.
	Reset()

	// String returns the contents of the buffer as a string.
	String() string

	// Append append the contents of the slice data to the buffer.
	Append(data []byte) error
}

type BufferInstance interface {
	DataBufferBase

	// Set overwrite the whole buffer content with byte slice.
	Set([]byte) error

	// SetString overwrite the whole buffer content with string.
	SetString(string) error

	// Prepend prepend the contents of the slice data to the buffer.
	Prepend(data []byte) error

	// Prepend prepend the contents of the string data to the buffer.
	PrependString(s string) error

	// Append append the contents of the string data to the buffer.
	AppendString(s string) error
}

//*************** BufferInstance end **************//

type DestroyReason int

const (
	Normal    DestroyReason = 0
	Terminate DestroyReason = 1
)

// For each AccessLogType's meaning, see
// https://www.envoyproxy.io/docs/envoy/latest/configuration/observability/access_log/usage
// Currently, only some downstream access log types are supported
type AccessLogType int

const (
	AccessLogNotSet                                  AccessLogType = 0
	AccessLogTcpUpstreamConnected                    AccessLogType = 1
	AccessLogTcpPeriodic                             AccessLogType = 2
	AccessLogTcpConnectionEnd                        AccessLogType = 3
	AccessLogDownstreamStart                         AccessLogType = 4
	AccessLogDownstreamPeriodic                      AccessLogType = 5
	AccessLogDownstreamEnd                           AccessLogType = 6
	AccessLogUpstreamPoolReady                       AccessLogType = 7
	AccessLogUpstreamPeriodic                        AccessLogType = 8
	AccessLogUpstreamEnd                             AccessLogType = 9
	AccessLogDownstreamTunnelSuccessfullyEstablished AccessLogType = 10
)

const (
	NormalFinalize int = 0 // normal, finalize on destroy
	GCFinalize     int = 1 // finalize in GC sweep
)

type EnvoyRequestPhase int

const (
	DecodeHeaderPhase EnvoyRequestPhase = iota + 1
	DecodeDataPhase
	DecodeTrailerPhase
	EncodeHeaderPhase
	EncodeDataPhase
	EncodeTrailerPhase
)

func (e EnvoyRequestPhase) String() string {
	switch e {
	case DecodeHeaderPhase:
		return "DecodeHeader"
	case DecodeDataPhase:
		return "DecodeData"
	case DecodeTrailerPhase:
		return "DecodeTrailer"
	case EncodeHeaderPhase:
		return "EncodeHeader"
	case EncodeDataPhase:
		return "EncodeData"
	case EncodeTrailerPhase:
		return "EncodeTrailer"
	}
	return "unknown phase"
}

// Status codes returned by filters that can cause future filters to not get iterated to.
type FilterStatus int

const (
	// Continue to further filters.
	NetworkFilterContinue FilterStatus = 0
	// Stop executing further filters.
	NetworkFilterStopIteration FilterStatus = 1
)

func (s FilterStatus) String() string {
	switch s {
	case NetworkFilterContinue:
		return "Continue"
	case NetworkFilterStopIteration:
		return "StopIteration"
	}
	return "unknown"
}

// Events that occur on a connection.
type ConnectionEvent int

const (
	RemoteClose      ConnectionEvent = 0
	LocalClose       ConnectionEvent = 1
	Connected        ConnectionEvent = 2
	ConnectedZeroRtt ConnectionEvent = 3
)

func (e ConnectionEvent) String() string {
	switch e {
	case RemoteClose:
		return "RemoteClose"
	case LocalClose:
		return "LocalClose"
	case Connected:
		return "Connected"
	case ConnectedZeroRtt:
		return "ConnectedZeroRtt"
	}
	return "unknown"
}

// Type of connection close to perform.
type ConnectionCloseType int

const (
	// Flush pending write data before raising ConnectionEvent::LocalClose
	FlushWrite ConnectionCloseType = 0
	// Do not flush any pending data. Write the pending data to buffer and then immediately
	// raise ConnectionEvent::LocalClose
	NoFlush ConnectionCloseType = 1
	// Flush pending write data and delay raising a ConnectionEvent::LocalClose
	// until the delayed_close_timeout expires
	FlushWriteAndDelay ConnectionCloseType = 2
	// Do not write/flush any pending data and immediately raise ConnectionEvent::LocalClose
	Abort ConnectionCloseType = 3
	// Do not write/flush any pending data and immediately raise
	// ConnectionEvent::LocalClose. Envoy will try to close the connection with RST flag.
	AbortReset ConnectionCloseType = 4
)

func (t ConnectionCloseType) String() string {
	switch t {
	case FlushWrite:
		return "FlushWrite"
	case NoFlush:
		return "NoFlush"
	case FlushWriteAndDelay:
		return "FlushWriteAndDelay"
	case Abort:
		return "Abort"
	case AbortReset:
		return "AbortReset"
	}
	return "unknown"
}

type PoolFailureReason int

const (
	// A resource overflowed and policy prevented a new connection from being created.
	Overflow PoolFailureReason = 0
	// A local connection failure took place while creating a new connection.
	LocalConnectionFailure PoolFailureReason = 1
	// A remote connection failure took place while creating a new connection.
	RemoteConnectionFailure PoolFailureReason = 2
	// A timeout occurred while creating a new connection.
	Timeout PoolFailureReason = 3
)

func (r PoolFailureReason) String() string {
	switch r {
	case Overflow:
		return "Overflow"
	case LocalConnectionFailure:
		return "LocalConnectionFailure"
	case RemoteConnectionFailure:
		return "RemoteConnectionFailure"
	case Timeout:
		return "Timeout"
	}
	return "unknown"
}

type ConnectionInfoType int

const (
	ConnectionInfoLocalAddr  ConnectionInfoType = 0
	ConnectionInfoRemoteAddr ConnectionInfoType = 1
)

func (t ConnectionInfoType) String() string {
	switch t {
	case ConnectionInfoLocalAddr:
		return "ConnectionInfoLocalAddr"
	case ConnectionInfoRemoteAddr:
		return "ConnectionInfoRemoteAddr"
	}
	return "unknown"
}

// *************** errors start **************//
var (
	ErrInternalFailure = errors.New("internal failure")
	ErrValueNotFound   = errors.New("value not found")
	// Failed to serialize the value when we fetch the value as string
	ErrSerializationFailure = errors.New("serialization failure")
)

// *************** errors end **************//

// Info types called by http-tcp bridge that can get the corresponding info from c++ side.
type HttpTcpBridgeInfoType int

const (
	HttpTcpBridgeInfoRouterName  HttpTcpBridgeInfoType = 0
	HttpTcpBridgeInfoClusterName HttpTcpBridgeInfoType = 1
)

func (t HttpTcpBridgeInfoType) String() string {
	switch t {
	case HttpTcpBridgeInfoRouterName:
		return "HttpTcpBridgeInfoRouterName"
	case HttpTcpBridgeInfoClusterName:
		return "HttpTcpBridgeInfoClusterName"
	}
	return "unknown"
}

type EndStreamType int

const (
	NotEndStream EndStreamType = 0
	EndStream    EndStreamType = 1
)

func (t EndStreamType) String() string {
	switch t {
	case NotEndStream:
		return "NotEndStream"
	case EndStream:
		return "EndStream"
	}
	return "unknown"
}

// Status codes returned by tcp upstream extension.
type HttpTcpBridgeStatus int

const (
	/**
	 *
	 * Used when you want to leave the current func area and continue further func. (when streaming,
	 * go side get each_data_piece, may be called multipled times)
	 *
	 * Here is the specific explanation in different funcs:
	 *
	 * encodeHeaders: will go to encodeData, go side in encodeData will streaming get each_data_piece.
	 *
	 * encodeData: streaming send data to upstream, go side get each_data_piece, may be called
	 * multipled times.
	 *
	 * onUpstreamData: go side in onUpstreamData will get each_data_piece, pass data
	 * and headers to downstream streaming.
	 */
	HttpTcpBridgeContinue HttpTcpBridgeStatus = 0

	/**
	*
	* Used when you want to buffer data.
	*
	* Here is the specific explanation in different funcs:
	*
	* encodeHeaders: will go to encodeData, encodeData will buffer whole data, go side in encodeData
	* get whole data one-off.
	*
	* encodeData: buffer further whole data, go side in encodeData get whole
	* data one-off. (Be careful: cannot be used when end_stream=true)
	*
	* onUpstreamData: every data
	* trigger will call go side, and go side get whloe buffered data ever since at every time.
	 */
	HttpTcpBridgeStopAndBuffer HttpTcpBridgeStatus = 1

	/**
	*
	* Used when you want to endStream for sending resp to downstream.
	*
	* Here is the specific explanation in different funcs:
	*
	* encodeHeaders, encodeData: endStream to upstream&downstream and send data to
	* downstream(if not blank), which means the whole resp to http has finished.
	*
	* onUpstreamData: endStream to downstream which means the whole resp to http has finished.
	 */
	HttpTcpBridgeEndStream HttpTcpBridgeStatus = 2
)

func (s HttpTcpBridgeStatus) String() string {
	switch s {
	case HttpTcpBridgeContinue:
		return "HttpTcpBridgeContinue"
	case HttpTcpBridgeStopAndBuffer:
		return "HttpTcpBridgeStopAndBuffer"
	case HttpTcpBridgeEndStream:
		return "HttpTcpBridgeEndStream"
	}
	return "unknown"
}



#Example

package main

import (
	"fmt"
	"strconv"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
)

var UpdateUpstreamBody = "upstream response body updated by the simple plugin"

// The callbacks in the filter, like `DecodeHeaders`, can be implemented on demand.
// Because api.PassThroughStreamFilter provides a default implementation.
type filter struct {
	api.PassThroughStreamFilter

	callbacks api.FilterCallbackHandler
	path      string
	config    *config
}

func (f *filter) sendLocalReplyInternal() api.StatusType {
	body := fmt.Sprintf("%s, path: %s\r\n", f.config.echoBody, f.path)
	f.callbacks.DecoderFilterCallbacks().SendLocalReply(200, body, nil, 0, "")
	// Remember to return LocalReply when the request is replied locally
	return api.LocalReply
}

// Callbacks which are called in request path
// The endStream is true if the request doesn't have body
func (f *filter) DecodeHeaders(header api.RequestHeaderMap, endStream bool) api.StatusType {
	f.path, _ = header.Get(":path")
	api.LogDebugf("get path %s", f.path)

	if f.path == "/localreply_by_config" {
		return f.sendLocalReplyInternal()
	}
	return api.Continue
	/*
		// If the code is time-consuming, to avoid blocking the Envoy,
		// we need to run the code in a background goroutine
		// and suspend & resume the filter
		go func() {
			defer f.callbacks.DecoderFilterCallbacks().RecoverPanic()
			// do time-consuming jobs

			// resume the filter
			f.callbacks.DecoderFilterCallbacks().Continue(status)
		}()

		// suspend the filter
		return api.Running
	*/
}

// DecodeData might be called multiple times during handling the request body.
// The endStream is true when handling the last piece of the body.
func (f *filter) DecodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	// support suspending & resuming the filter in a background goroutine
	return api.Continue
}

func (f *filter) DecodeTrailers(trailers api.RequestTrailerMap) api.StatusType {
	// support suspending & resuming the filter in a background goroutine
	return api.Continue
}

// Callbacks which are called in response path
// The endStream is true if the response doesn't have body
func (f *filter) EncodeHeaders(header api.ResponseHeaderMap, endStream bool) api.StatusType {
	if f.path == "/update_upstream_response" {
		header.Set("Content-Length", strconv.Itoa(len(UpdateUpstreamBody)))
	}
	header.Set("Rsp-Header-From-Go", "bar-test")
	// support suspending & resuming the filter in a background goroutine
	return api.Continue
}

// EncodeData might be called multiple times during handling the response body.
// The endStream is true when handling the last piece of the body.
func (f *filter) EncodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	if f.path == "/update_upstream_response" {
		if endStream {
			buffer.SetString(UpdateUpstreamBody)
		} else {
			buffer.Reset()
		}
	}
	// support suspending & resuming the filter in a background goroutine
	return api.Continue
}

func (f *filter) EncodeTrailers(trailers api.ResponseTrailerMap) api.StatusType {
	return api.Continue
}

// OnLog is called when the HTTP stream is ended on HTTP Connection Manager filter.
func (f *filter) OnLog(reqHeader api.RequestHeaderMap, reqTrailer api.RequestTrailerMap, respHeader api.ResponseHeaderMap, respTrailer api.ResponseTrailerMap) {
	code, _ := f.callbacks.StreamInfo().ResponseCode()
	respCode := strconv.Itoa(int(code))
	api.LogDebug(respCode)

	/*
		// It's possible to kick off a goroutine here.
		// But it's unsafe to access the f.callbacks because the FilterCallbackHandler
		// may be already released when the goroutine is scheduled.
		go func() {
			defer func() {
				if p := recover(); p != nil {
					const size = 64 << 10
					buf := make([]byte, size)
					buf = buf[:runtime.Stack(buf, false)]
					fmt.Printf("http: panic serving: %v\n%s", p, buf)
				}
			}()

			// do time-consuming jobs
		}()
	*/
}

// OnLogDownstreamStart is called when HTTP Connection Manager filter receives a new HTTP request
// (required the corresponding access log type is enabled)
func (f *filter) OnLogDownstreamStart(reqHeader api.RequestHeaderMap) {
	// also support kicking off a goroutine here, like OnLog.
}

// OnLogDownstreamPeriodic is called on any HTTP Connection Manager periodic log record
// (required the corresponding access log type is enabled)
func (f *filter) OnLogDownstreamPeriodic(reqHeader api.RequestHeaderMap, reqTrailer api.RequestTrailerMap, respHeader api.ResponseHeaderMap, respTrailer api.ResponseTrailerMap) {
	// also support kicking off a goroutine here, like OnLog.
}

func (f *filter) OnDestroy(reason api.DestroyReason) {
	// One should not access f.callbacks here because the FilterCallbackHandler
	// is released. But we can still access other Go fields in the filter f.

	// goroutine can be used everywhere.
}
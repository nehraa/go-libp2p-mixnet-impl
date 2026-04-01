package hub

import "errors"

var (
	// ErrInvalidConfig indicates the hub configuration is invalid.
	ErrInvalidConfig = errors.New("hub: invalid config")
	// ErrHubClosed indicates the hub is shutting down or already stopped.
	ErrHubClosed = errors.New("hub: closed")
	// ErrSelfBinding indicates a receptor attempted to bind the local host.
	ErrSelfBinding = errors.New("hub: self binding is not allowed")
	// ErrDuplicatePeerBinding indicates a receptor for the peer already exists.
	ErrDuplicatePeerBinding = errors.New("hub: duplicate peer binding")
	// ErrProtocolHandlerConflict indicates the configured protocol already has a handler.
	ErrProtocolHandlerConflict = errors.New("hub: protocol handler conflict")
	// ErrReceptorNotFound indicates the requested receptor does not exist.
	ErrReceptorNotFound = errors.New("hub: receptor not found")
	// ErrNoActiveStream indicates the receptor has no active stream.
	ErrNoActiveStream = errors.New("hub: no active stream")
	// ErrActiveStreamExists indicates a receptor already has the preferred stream.
	ErrActiveStreamExists = errors.New("hub: active stream already exists")
	// ErrEventBufferFull indicates the event consumer is not draining fast enough.
	ErrEventBufferFull = errors.New("hub: event buffer full")
	// ErrMetricsBufferFull indicates the metrics consumer is not draining fast enough.
	ErrMetricsBufferFull = errors.New("hub: metrics buffer full")
)

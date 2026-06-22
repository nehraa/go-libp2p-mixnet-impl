package upload

import "errors"

var (
	// ErrInvalidConfig indicates configuration validation failed.
	ErrInvalidConfig = errors.New("upload: invalid config")
	// ErrInvalidRequest indicates upload request validation failed.
	ErrInvalidRequest = errors.New("upload: invalid request")
	// ErrResolverUnavailable indicates peer discovery cannot run because no resolver is configured.
	ErrResolverUnavailable = errors.New("upload: peer resolver is unavailable")
	// ErrInsufficientPeers indicates the resolver returned fewer peers than required.
	ErrInsufficientPeers = errors.New("upload: insufficient peers")
	// ErrAckTimeout indicates the sender waited for a shard ACK and timed out.
	ErrAckTimeout = errors.New("upload: ack timeout")
	// ErrFrameTooLarge indicates a received frame exceeded limits.
	ErrFrameTooLarge = errors.New("upload: frame too large")
	// ErrProtocolViolation indicates malformed frame or unsupported wire payload.
	ErrProtocolViolation = errors.New("upload: protocol violation")
	// ErrUploadInProgress indicates another upload with the same upload ID is active.
	ErrUploadInProgress = errors.New("upload: upload already in progress")
)

package shardxfer

import "errors"

var (
	// ErrFrameTooLarge indicates a frame exceeded the configured maximum size.
	ErrFrameTooLarge = errors.New("shardxfer: frame too large")
	// ErrMalformedFrame indicates an invalid frame payload or header.
	ErrMalformedFrame = errors.New("shardxfer: malformed frame")
)

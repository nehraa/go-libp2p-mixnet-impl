package shardxfer

import (
	"encoding/binary"
	"fmt"
	"io"
)

const headerSize = 4

// Frame is one decoded transport frame.
type Frame struct {
	Kind    byte
	Payload []byte
}

// EncodeFrame encodes one frame as [length(4)][kind(1)][payload].
func EncodeFrame(kind byte, payload []byte, maxFrameSize int) ([]byte, error) {
	if kind == 0 {
		return nil, fmt.Errorf("%w: frame kind is required", ErrMalformedFrame)
	}
	framePayloadLen := 1 + len(payload)
	if maxFrameSize > 0 && framePayloadLen > maxFrameSize {
		return nil, fmt.Errorf("%w: frame size %d exceeds limit %d", ErrFrameTooLarge, framePayloadLen, maxFrameSize)
	}
	out := make([]byte, headerSize+framePayloadLen)
	binary.BigEndian.PutUint32(out[:headerSize], uint32(framePayloadLen))
	out[headerSize] = kind
	copy(out[headerSize+1:], payload)
	return out, nil
}

// DecodeBuffer extracts all complete frames from buffer and returns the
// remaining incomplete suffix.
func DecodeBuffer(buffer []byte, maxFrameSize int) ([]Frame, []byte, error) {
	if len(buffer) == 0 {
		return nil, buffer, nil
	}

	frames := make([]Frame, 0, 1)
	offset := 0
	for len(buffer)-offset >= headerSize {
		size := int(binary.BigEndian.Uint32(buffer[offset : offset+headerSize]))
		if size <= 0 || (maxFrameSize > 0 && size > maxFrameSize) {
			return nil, nil, fmt.Errorf("%w: frame size %d exceeds limit %d", ErrFrameTooLarge, size, maxFrameSize)
		}
		total := headerSize + size
		if len(buffer)-offset < total {
			break
		}

		payload := make([]byte, size)
		copy(payload, buffer[offset+headerSize:offset+total])
		frame, err := decodeFramePayload(payload)
		if err != nil {
			return nil, nil, err
		}
		frames = append(frames, frame)
		offset += total
	}

	remaining := make([]byte, len(buffer)-offset)
	copy(remaining, buffer[offset:])
	return frames, remaining, nil
}

// ReadFrame reads one full frame from r.
func ReadFrame(r io.Reader, maxFrameSize int) (Frame, error) {
	var header [headerSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Frame{}, err
	}

	size := int(binary.BigEndian.Uint32(header[:]))
	if size <= 0 || (maxFrameSize > 0 && size > maxFrameSize) {
		return Frame{}, fmt.Errorf("%w: frame size %d exceeds limit %d", ErrFrameTooLarge, size, maxFrameSize)
	}

	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Frame{}, err
	}
	return decodeFramePayload(payload)
}

func decodeFramePayload(payload []byte) (Frame, error) {
	if len(payload) < 1 {
		return Frame{}, fmt.Errorf("%w: empty frame payload", ErrMalformedFrame)
	}
	return Frame{
		Kind:    payload[0],
		Payload: payload[1:],
	}, nil
}

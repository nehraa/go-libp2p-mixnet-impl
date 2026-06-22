package upload

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	frameTypeData byte = 0x01
	frameTypeAck  byte = 0x02

	ackStatusFailed byte = 0x00
	ackStatusOK     byte = 0x01

	maxUploadIDLen = 512
	maxAckTextLen  = 4096
)

type dataFrame struct {
	UploadID   string
	ShardIndex int
	ShardCount int
	Payload    []byte
}

type ackFrame struct {
	UploadID   string
	ShardIndex int
	Accepted   bool
	Message    string
}

func encodeDataFrame(frame dataFrame) ([]byte, error) {
	prefix, err := encodeDataFramePrefix(frame.UploadID, frame.ShardIndex, frame.ShardCount, len(frame.Payload), 0)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(prefix)+len(frame.Payload))
	copy(out, prefix)
	copy(out[len(prefix):], frame.Payload)
	return out, nil
}

func encodeDataFramePrefix(uploadID string, shardIndex int, shardCount int, payloadLen int, maxFrameSize int) ([]byte, error) {
	if len(uploadID) == 0 || len(uploadID) > maxUploadIDLen {
		return nil, fmt.Errorf("%w: upload id length out of range", ErrProtocolViolation)
	}
	if shardIndex < 0 || shardCount <= 0 {
		return nil, fmt.Errorf("%w: invalid shard metadata", ErrProtocolViolation)
	}
	uploadIDLen := len(uploadID)
	framePayloadLen := 1 + 2 + uploadIDLen + 4 + 4 + 4 + payloadLen
	if maxFrameSize > 0 && framePayloadLen > maxFrameSize {
		return nil, fmt.Errorf("%w: frame size %d exceeds limit %d", ErrFrameTooLarge, framePayloadLen, maxFrameSize)
	}
	prefixLen := 4 + 1 + 2 + uploadIDLen + 4 + 4 + 4
	out := make([]byte, prefixLen)
	binary.BigEndian.PutUint32(out[:4], uint32(framePayloadLen))
	pos := 4
	out[pos] = frameTypeData
	pos++
	binary.BigEndian.PutUint16(out[pos:pos+2], uint16(uploadIDLen))
	pos += 2
	copy(out[pos:pos+uploadIDLen], uploadID)
	pos += uploadIDLen
	binary.BigEndian.PutUint32(out[pos:pos+4], uint32(shardIndex))
	pos += 4
	binary.BigEndian.PutUint32(out[pos:pos+4], uint32(shardCount))
	pos += 4
	binary.BigEndian.PutUint32(out[pos:pos+4], uint32(payloadLen))
	return out, nil
}

func decodeDataFrame(payload []byte) (dataFrame, error) {
	if len(payload) < 1+2+4+4+4 {
		return dataFrame{}, fmt.Errorf("%w: short data frame", ErrProtocolViolation)
	}
	if payload[0] != frameTypeData {
		return dataFrame{}, fmt.Errorf("%w: unexpected data frame type", ErrProtocolViolation)
	}
	pos := 1
	uploadIDLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2
	if uploadIDLen <= 0 || uploadIDLen > maxUploadIDLen {
		return dataFrame{}, fmt.Errorf("%w: upload id length out of range", ErrProtocolViolation)
	}
	if len(payload) < pos+uploadIDLen+4+4+4 {
		return dataFrame{}, fmt.Errorf("%w: truncated data frame metadata", ErrProtocolViolation)
	}
	uploadID := string(payload[pos : pos+uploadIDLen])
	pos += uploadIDLen
	shardIndex := int(binary.BigEndian.Uint32(payload[pos : pos+4]))
	pos += 4
	shardCount := int(binary.BigEndian.Uint32(payload[pos : pos+4]))
	pos += 4
	dataLen := int(binary.BigEndian.Uint32(payload[pos : pos+4]))
	pos += 4
	if dataLen < 0 || len(payload) != pos+dataLen {
		return dataFrame{}, fmt.Errorf("%w: malformed data payload length", ErrProtocolViolation)
	}
	return dataFrame{
		UploadID:   uploadID,
		ShardIndex: shardIndex,
		ShardCount: shardCount,
		Payload:    payload[pos : pos+dataLen],
	}, nil
}

func encodeAckFrame(frame ackFrame) ([]byte, error) {
	if len(frame.UploadID) == 0 || len(frame.UploadID) > maxUploadIDLen {
		return nil, fmt.Errorf("%w: upload id length out of range", ErrProtocolViolation)
	}
	if frame.ShardIndex < 0 {
		return nil, fmt.Errorf("%w: invalid shard index", ErrProtocolViolation)
	}
	if len(frame.Message) > maxAckTextLen {
		return nil, fmt.Errorf("%w: ack message too long", ErrProtocolViolation)
	}
	uploadIDLen := len(frame.UploadID)
	msgLen := len(frame.Message)
	framePayloadLen := 1 + 2 + uploadIDLen + 4 + 1 + 2 + msgLen
	out := make([]byte, 4+framePayloadLen)
	binary.BigEndian.PutUint32(out[:4], uint32(framePayloadLen))
	pos := 4
	out[pos] = frameTypeAck
	pos++
	binary.BigEndian.PutUint16(out[pos:pos+2], uint16(uploadIDLen))
	pos += 2
	copy(out[pos:pos+uploadIDLen], frame.UploadID)
	pos += uploadIDLen
	binary.BigEndian.PutUint32(out[pos:pos+4], uint32(frame.ShardIndex))
	pos += 4
	if frame.Accepted {
		out[pos] = ackStatusOK
	} else {
		out[pos] = ackStatusFailed
	}
	pos++
	binary.BigEndian.PutUint16(out[pos:pos+2], uint16(msgLen))
	pos += 2
	copy(out[pos:pos+msgLen], frame.Message)
	return out, nil
}

func decodeAckFrame(payload []byte) (ackFrame, error) {
	if len(payload) < 1+2+4+1+2 {
		return ackFrame{}, fmt.Errorf("%w: short ack frame", ErrProtocolViolation)
	}
	if payload[0] != frameTypeAck {
		return ackFrame{}, fmt.Errorf("%w: unexpected ack frame type", ErrProtocolViolation)
	}
	pos := 1
	uploadIDLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2
	if uploadIDLen <= 0 || uploadIDLen > maxUploadIDLen {
		return ackFrame{}, fmt.Errorf("%w: upload id length out of range", ErrProtocolViolation)
	}
	if len(payload) < pos+uploadIDLen+4+1+2 {
		return ackFrame{}, fmt.Errorf("%w: truncated ack frame metadata", ErrProtocolViolation)
	}
	uploadID := string(payload[pos : pos+uploadIDLen])
	pos += uploadIDLen
	shardIndex := int(binary.BigEndian.Uint32(payload[pos : pos+4]))
	pos += 4
	status := payload[pos]
	pos++
	msgLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2
	if len(payload) != pos+msgLen {
		return ackFrame{}, fmt.Errorf("%w: malformed ack payload length", ErrProtocolViolation)
	}
	ack := ackFrame{
		UploadID:   uploadID,
		ShardIndex: shardIndex,
		Accepted:   status == ackStatusOK,
	}
	if msgLen > 0 {
		ack.Message = string(payload[pos : pos+msgLen])
	}
	return ack, nil
}

func readWireFrame(r io.Reader, maxFrameSize int) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint32(header[:]))
	if size <= 0 || size > maxFrameSize {
		return nil, fmt.Errorf("%w: frame size %d exceeds limit %d", ErrFrameTooLarge, size, maxFrameSize)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func decodePayloadFrames(buffer []byte, maxFrameSize int) ([][]byte, []byte, error) {
	if len(buffer) == 0 {
		return nil, buffer, nil
	}
	frames := make([][]byte, 0, 1)
	offset := 0
	for len(buffer)-offset >= 4 {
		frameSize := int(binary.BigEndian.Uint32(buffer[offset : offset+4]))
		if frameSize <= 0 || frameSize > maxFrameSize {
			return nil, nil, fmt.Errorf("%w: frame size %d exceeds limit %d", ErrFrameTooLarge, frameSize, maxFrameSize)
		}
		total := 4 + frameSize
		if len(buffer)-offset < total {
			break
		}
		frame := make([]byte, frameSize)
		copy(frame, buffer[offset+4:offset+total])
		frames = append(frames, frame)
		offset += total
	}
	remaining := make([]byte, len(buffer)-offset)
	copy(remaining, buffer[offset:])
	return frames, remaining, nil
}

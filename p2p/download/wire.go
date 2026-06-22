package download

import (
	"encoding/binary"
	"fmt"
)

const (
	frameKindPullRequest byte = 0x11
	frameKindShardChunk  byte = 0x12
	frameKindShardEnd    byte = 0x13
	frameKindError       byte = 0x14

	maxRequestIDLen = 128
	maxErrorTextLen = 2048
)

type pullRequestFrame struct {
	UploadID   string
	RequestID  string
	ShardIndex int
}

type shardChunkFrame struct {
	UploadID   string
	RequestID  string
	ShardIndex int
	Offset     uint64
	Data       []byte
}

type shardEndFrame struct {
	UploadID   string
	RequestID  string
	ShardIndex int
	TotalBytes uint64
}

type errorFrame struct {
	UploadID   string
	RequestID  string
	ShardIndex int
	Message    string
}

func encodePullRequestFrame(frame pullRequestFrame) ([]byte, error) {
	uploadID, requestID, err := normalizeWireIDs(frame.UploadID, frame.RequestID)
	if err != nil {
		return nil, err
	}
	if frame.ShardIndex < 0 {
		return nil, fmt.Errorf("%w: invalid shard index", ErrInvalidRequest)
	}

	uploadLen := len(uploadID)
	reqLen := len(requestID)
	out := make([]byte, 2+uploadLen+2+reqLen+4)
	pos := 0
	binary.BigEndian.PutUint16(out[pos:pos+2], uint16(uploadLen))
	pos += 2
	copy(out[pos:pos+uploadLen], uploadID)
	pos += uploadLen
	binary.BigEndian.PutUint16(out[pos:pos+2], uint16(reqLen))
	pos += 2
	copy(out[pos:pos+reqLen], requestID)
	pos += reqLen
	binary.BigEndian.PutUint32(out[pos:pos+4], uint32(frame.ShardIndex))
	return out, nil
}

func decodePullRequestFrame(payload []byte) (pullRequestFrame, error) {
	pos := 0
	uploadID, next, err := decodeBoundedString(payload, pos, maxUploadIDLen, "upload id")
	if err != nil {
		return pullRequestFrame{}, err
	}
	pos = next
	requestID, next, err := decodeBoundedString(payload, pos, maxRequestIDLen, "request id")
	if err != nil {
		return pullRequestFrame{}, err
	}
	pos = next
	if len(payload) < pos+4 {
		return pullRequestFrame{}, fmt.Errorf("%w: pull request frame missing shard index", ErrInvalidRequest)
	}
	shardIndex := int(binary.BigEndian.Uint32(payload[pos : pos+4]))
	return pullRequestFrame{
		UploadID:   uploadID,
		RequestID:  requestID,
		ShardIndex: shardIndex,
	}, nil
}

func encodeShardChunkFrame(frame shardChunkFrame) ([]byte, error) {
	uploadID, requestID, err := normalizeWireIDs(frame.UploadID, frame.RequestID)
	if err != nil {
		return nil, err
	}
	if frame.ShardIndex < 0 {
		return nil, fmt.Errorf("%w: invalid shard index", ErrInvalidRequest)
	}
	uploadLen := len(uploadID)
	reqLen := len(requestID)
	dataLen := len(frame.Data)
	out := make([]byte, 2+uploadLen+2+reqLen+4+8+4+dataLen)
	pos := 0
	binary.BigEndian.PutUint16(out[pos:pos+2], uint16(uploadLen))
	pos += 2
	copy(out[pos:pos+uploadLen], uploadID)
	pos += uploadLen
	binary.BigEndian.PutUint16(out[pos:pos+2], uint16(reqLen))
	pos += 2
	copy(out[pos:pos+reqLen], requestID)
	pos += reqLen
	binary.BigEndian.PutUint32(out[pos:pos+4], uint32(frame.ShardIndex))
	pos += 4
	binary.BigEndian.PutUint64(out[pos:pos+8], frame.Offset)
	pos += 8
	binary.BigEndian.PutUint32(out[pos:pos+4], uint32(dataLen))
	pos += 4
	copy(out[pos:pos+dataLen], frame.Data)
	return out, nil
}

func decodeShardChunkFrame(payload []byte) (shardChunkFrame, error) {
	pos := 0
	uploadID, next, err := decodeBoundedString(payload, pos, maxUploadIDLen, "upload id")
	if err != nil {
		return shardChunkFrame{}, err
	}
	pos = next
	requestID, next, err := decodeBoundedString(payload, pos, maxRequestIDLen, "request id")
	if err != nil {
		return shardChunkFrame{}, err
	}
	pos = next
	if len(payload) < pos+4+8+4 {
		return shardChunkFrame{}, fmt.Errorf("%w: chunk frame metadata truncated", ErrInvalidRequest)
	}
	shardIndex := int(binary.BigEndian.Uint32(payload[pos : pos+4]))
	pos += 4
	offset := binary.BigEndian.Uint64(payload[pos : pos+8])
	pos += 8
	dataLen := int(binary.BigEndian.Uint32(payload[pos : pos+4]))
	pos += 4
	if dataLen < 0 || len(payload) != pos+dataLen {
		return shardChunkFrame{}, fmt.Errorf("%w: invalid chunk payload length", ErrInvalidRequest)
	}
	return shardChunkFrame{
		UploadID:   uploadID,
		RequestID:  requestID,
		ShardIndex: shardIndex,
		Offset:     offset,
		Data:       payload[pos : pos+dataLen],
	}, nil
}

func encodeShardEndFrame(frame shardEndFrame) ([]byte, error) {
	uploadID, requestID, err := normalizeWireIDs(frame.UploadID, frame.RequestID)
	if err != nil {
		return nil, err
	}
	if frame.ShardIndex < 0 {
		return nil, fmt.Errorf("%w: invalid shard index", ErrInvalidRequest)
	}
	uploadLen := len(uploadID)
	reqLen := len(requestID)
	out := make([]byte, 2+uploadLen+2+reqLen+4+8)
	pos := 0
	binary.BigEndian.PutUint16(out[pos:pos+2], uint16(uploadLen))
	pos += 2
	copy(out[pos:pos+uploadLen], uploadID)
	pos += uploadLen
	binary.BigEndian.PutUint16(out[pos:pos+2], uint16(reqLen))
	pos += 2
	copy(out[pos:pos+reqLen], requestID)
	pos += reqLen
	binary.BigEndian.PutUint32(out[pos:pos+4], uint32(frame.ShardIndex))
	pos += 4
	binary.BigEndian.PutUint64(out[pos:pos+8], frame.TotalBytes)
	return out, nil
}

func decodeShardEndFrame(payload []byte) (shardEndFrame, error) {
	pos := 0
	uploadID, next, err := decodeBoundedString(payload, pos, maxUploadIDLen, "upload id")
	if err != nil {
		return shardEndFrame{}, err
	}
	pos = next
	requestID, next, err := decodeBoundedString(payload, pos, maxRequestIDLen, "request id")
	if err != nil {
		return shardEndFrame{}, err
	}
	pos = next
	if len(payload) < pos+4+8 {
		return shardEndFrame{}, fmt.Errorf("%w: end frame metadata truncated", ErrInvalidRequest)
	}
	shardIndex := int(binary.BigEndian.Uint32(payload[pos : pos+4]))
	pos += 4
	totalBytes := binary.BigEndian.Uint64(payload[pos : pos+8])
	return shardEndFrame{
		UploadID:   uploadID,
		RequestID:  requestID,
		ShardIndex: shardIndex,
		TotalBytes: totalBytes,
	}, nil
}

func encodeErrorFrame(frame errorFrame) ([]byte, error) {
	uploadID, requestID, err := normalizeWireIDs(frame.UploadID, frame.RequestID)
	if err != nil {
		return nil, err
	}
	if frame.ShardIndex < 0 {
		return nil, fmt.Errorf("%w: invalid shard index", ErrInvalidRequest)
	}
	if len(frame.Message) == 0 {
		return nil, fmt.Errorf("%w: error frame message required", ErrInvalidRequest)
	}
	if len(frame.Message) > maxErrorTextLen {
		return nil, fmt.Errorf("%w: error frame message too long", ErrInvalidRequest)
	}
	uploadLen := len(uploadID)
	reqLen := len(requestID)
	msgLen := len(frame.Message)
	out := make([]byte, 2+uploadLen+2+reqLen+4+2+msgLen)
	pos := 0
	binary.BigEndian.PutUint16(out[pos:pos+2], uint16(uploadLen))
	pos += 2
	copy(out[pos:pos+uploadLen], uploadID)
	pos += uploadLen
	binary.BigEndian.PutUint16(out[pos:pos+2], uint16(reqLen))
	pos += 2
	copy(out[pos:pos+reqLen], requestID)
	pos += reqLen
	binary.BigEndian.PutUint32(out[pos:pos+4], uint32(frame.ShardIndex))
	pos += 4
	binary.BigEndian.PutUint16(out[pos:pos+2], uint16(msgLen))
	pos += 2
	copy(out[pos:pos+msgLen], frame.Message)
	return out, nil
}

func decodeErrorFrame(payload []byte) (errorFrame, error) {
	pos := 0
	uploadID, next, err := decodeBoundedString(payload, pos, maxUploadIDLen, "upload id")
	if err != nil {
		return errorFrame{}, err
	}
	pos = next
	requestID, next, err := decodeBoundedString(payload, pos, maxRequestIDLen, "request id")
	if err != nil {
		return errorFrame{}, err
	}
	pos = next
	if len(payload) < pos+4+2 {
		return errorFrame{}, fmt.Errorf("%w: error frame metadata truncated", ErrInvalidRequest)
	}
	shardIndex := int(binary.BigEndian.Uint32(payload[pos : pos+4]))
	pos += 4
	msgLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2
	if msgLen <= 0 || msgLen > maxErrorTextLen || len(payload) != pos+msgLen {
		return errorFrame{}, fmt.Errorf("%w: invalid error message length", ErrInvalidRequest)
	}
	return errorFrame{
		UploadID:   uploadID,
		RequestID:  requestID,
		ShardIndex: shardIndex,
		Message:    string(payload[pos : pos+msgLen]),
	}, nil
}

func normalizeWireIDs(uploadID string, requestID string) (string, string, error) {
	normalizedUploadID, err := normalizeUploadID(uploadID)
	if err != nil {
		return "", "", err
	}
	if len(requestID) == 0 || len(requestID) > maxRequestIDLen {
		return "", "", fmt.Errorf("%w: request id length out of range", ErrInvalidRequest)
	}
	return normalizedUploadID, requestID, nil
}

func decodeBoundedString(payload []byte, pos int, maxLen int, field string) (string, int, error) {
	if len(payload) < pos+2 {
		return "", 0, fmt.Errorf("%w: %s length missing", ErrInvalidRequest, field)
	}
	n := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2
	if n <= 0 || n > maxLen {
		return "", 0, fmt.Errorf("%w: %s length out of range", ErrInvalidRequest, field)
	}
	if len(payload) < pos+n {
		return "", 0, fmt.Errorf("%w: %s truncated", ErrInvalidRequest, field)
	}
	return string(payload[pos : pos+n]), pos + n, nil
}

package mixnet

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/mixnet/ces"
)

const (
	frameVersionSessionSetupHeaderOnly byte = 0x03
	frameVersionSessionDataHeaderOnly  byte = 0x04
	frameVersionSessionSetupFullOnion  byte = 0x05
	frameVersionSessionDataFullOnion   byte = 0x06
	frameVersionSessionClose           byte = 0x07

	msgTypeSessionSetup byte = 0x03
	msgTypeSessionData  byte = 0x04
	msgTypeSessionClose byte = 0x05

	sessionDataFlagSequenced byte = 0x01
)

type sessionRouteMode byte

const (
	sessionRouteModeHeaderOnly sessionRouteMode = 0x01
	sessionRouteModeFullOnion  sessionRouteMode = 0x02
)

type senderSessionRouteState struct {
	timer          *time.Timer
	lastUsed       time.Time
	setupByCircuit map[string]struct{}
	nextSeq        uint64
}

func sessionRoutingEnabled(cfg *MixnetConfig) bool {
	return cfg != nil && cfg.EnableSessionRouting && cfg.EncryptionMode == EncryptionModeHeaderOnly
}

func sessionRouteModeForConfig(cfg *MixnetConfig) sessionRouteMode {
	if cfg != nil && cfg.EncryptionMode == EncryptionModeHeaderOnly {
		return sessionRouteModeHeaderOnly
	}
	return sessionRouteModeFullOnion
}

func sessionSetupFrameVersion(mode sessionRouteMode) byte {
	if mode == sessionRouteModeHeaderOnly {
		return frameVersionSessionSetupHeaderOnly
	}
	return frameVersionSessionSetupFullOnion
}

func sessionDataFrameVersion(mode sessionRouteMode) byte {
	if mode == sessionRouteModeHeaderOnly {
		return frameVersionSessionDataHeaderOnly
	}
	return frameVersionSessionDataFullOnion
}

func encodeSessionSetupFramePayload(baseSessionID string, mode sessionRouteMode, encryptedHeader []byte, keyData []byte) ([]byte, error) {
	if len(baseSessionID) > 0xff {
		return nil, fmt.Errorf("base session id too long: %d", len(baseSessionID))
	}
	buf := make([]byte, 1+len(baseSessionID)+1+4+len(encryptedHeader)+4+len(keyData))
	pos := 0
	buf[pos] = byte(len(baseSessionID))
	pos++
	pos += copy(buf[pos:], baseSessionID)
	buf[pos] = byte(mode)
	pos++
	binary.LittleEndian.PutUint32(buf[pos:], uint32(len(encryptedHeader)))
	pos += 4
	pos += copy(buf[pos:], encryptedHeader)
	binary.LittleEndian.PutUint32(buf[pos:], uint32(len(keyData)))
	pos += 4
	copy(buf[pos:], keyData)
	return buf, nil
}

func decodeSessionSetupFramePayload(data []byte) (string, sessionRouteMode, []byte, []byte, error) {
	if len(data) < 1 {
		return "", 0, nil, nil, fmt.Errorf("session setup payload too short")
	}
	baseLen := int(data[0])
	offset := 1
	if len(data) < offset+baseLen+1+4 {
		return "", 0, nil, nil, fmt.Errorf("session setup payload truncated")
	}
	baseID := string(data[offset : offset+baseLen])
	offset += baseLen
	mode := sessionRouteMode(data[offset])
	offset++
	headerLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if headerLen < 0 || len(data) < offset+headerLen+4 {
		return "", 0, nil, nil, fmt.Errorf("invalid session setup header length")
	}
	encryptedHeader := append([]byte(nil), data[offset:offset+headerLen]...)
	offset += headerLen
	keyLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if keyLen < 0 || len(data) < offset+keyLen {
		return "", 0, nil, nil, fmt.Errorf("invalid session setup key length")
	}
	keyData := append([]byte(nil), data[offset:offset+keyLen]...)
	return baseID, mode, encryptedHeader, keyData, nil
}

func encodeSessionSetupDeliveryPayload(baseSessionID string, keyData []byte) ([]byte, error) {
	return encodeSessionCloseFramePayloadWithKey(baseSessionID, keyData)
}

func decodeSessionSetupDeliveryPayload(data []byte) (string, []byte, error) {
	return decodeSessionCloseFramePayloadWithKey(data)
}

func encodeSessionDataFramePayload(baseSessionID string, hasSeq bool, seq uint64, shard *ces.Shard, totalShards int, authTag []byte) ([]byte, error) {
	if len(baseSessionID) > 0xff {
		return nil, fmt.Errorf("base session id too long: %d", len(baseSessionID))
	}
	if shard == nil {
		return nil, fmt.Errorf("missing shard")
	}
	if totalShards < 0 {
		return nil, fmt.Errorf("invalid total shards: %d", totalShards)
	}
	if len(authTag) > 0xffff {
		return nil, fmt.Errorf("auth tag too large: %d", len(authTag))
	}
	flags := byte(0)
	seqLen := 0
	if hasSeq {
		flags |= sessionDataFlagSequenced
		seqLen = 8
	}
	buf := make([]byte, 1+len(baseSessionID)+1+seqLen+4+4+2+len(authTag)+len(shard.Data))
	pos := 0
	buf[pos] = byte(len(baseSessionID))
	pos++
	pos += copy(buf[pos:], baseSessionID)
	buf[pos] = flags
	pos++
	if hasSeq {
		binary.LittleEndian.PutUint64(buf[pos:], seq)
		pos += 8
	}
	binary.LittleEndian.PutUint32(buf[pos:], uint32(shard.Index))
	pos += 4
	binary.LittleEndian.PutUint32(buf[pos:], uint32(totalShards))
	pos += 4
	binary.LittleEndian.PutUint16(buf[pos:], uint16(len(authTag)))
	pos += 2
	pos += copy(buf[pos:], authTag)
	copy(buf[pos:], shard.Data)
	return buf, nil
}

func decodeSessionDataFramePayload(data []byte) (string, bool, uint64, *ces.Shard, int, []byte, error) {
	if len(data) < 1 {
		return "", false, 0, nil, 0, nil, fmt.Errorf("session data payload too short")
	}
	baseLen := int(data[0])
	offset := 1
	if len(data) < offset+baseLen+1+4+4+2 {
		return "", false, 0, nil, 0, nil, fmt.Errorf("session data payload truncated")
	}
	baseID := string(data[offset : offset+baseLen])
	offset += baseLen
	flags := data[offset]
	offset++
	hasSeq := flags&sessionDataFlagSequenced != 0
	var seq uint64
	if hasSeq {
		if len(data) < offset+8+4+4+2 {
			return "", false, 0, nil, 0, nil, fmt.Errorf("session data sequence truncated")
		}
		seq = binary.LittleEndian.Uint64(data[offset:])
		offset += 8
	}
	shardIndex := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	totalShards := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	authLen := int(binary.LittleEndian.Uint16(data[offset:]))
	offset += 2
	if authLen < 0 || len(data) < offset+authLen {
		return "", false, 0, nil, 0, nil, fmt.Errorf("invalid session data auth length")
	}
	authTag := append([]byte(nil), data[offset:offset+authLen]...)
	offset += authLen
	shardData := append([]byte(nil), data[offset:]...)
	return baseID, hasSeq, seq, &ces.Shard{Index: shardIndex, Data: shardData}, totalShards, authTag, nil
}

func encodeSessionCloseFramePayload(baseSessionID string) ([]byte, error) {
	return encodeSessionCloseFramePayloadWithKey(baseSessionID, nil)
}

func decodeSessionCloseFramePayload(data []byte) (string, error) {
	baseID, _, err := decodeSessionCloseFramePayloadWithKey(data)
	return baseID, err
}

func encodeSessionCloseFramePayloadWithKey(baseSessionID string, keyData []byte) ([]byte, error) {
	if len(baseSessionID) > 0xff {
		return nil, fmt.Errorf("base session id too long: %d", len(baseSessionID))
	}
	buf := make([]byte, 1+len(baseSessionID)+4+len(keyData))
	pos := 0
	buf[pos] = byte(len(baseSessionID))
	pos++
	pos += copy(buf[pos:], baseSessionID)
	binary.LittleEndian.PutUint32(buf[pos:], uint32(len(keyData)))
	pos += 4
	copy(buf[pos:], keyData)
	return buf, nil
}

func decodeSessionCloseFramePayloadWithKey(data []byte) (string, []byte, error) {
	if len(data) < 1 {
		return "", nil, fmt.Errorf("session payload too short")
	}
	baseLen := int(data[0])
	offset := 1
	if len(data) < offset+baseLen+4 {
		return "", nil, fmt.Errorf("session payload truncated")
	}
	baseID := string(data[offset : offset+baseLen])
	offset += baseLen
	keyLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if keyLen < 0 || len(data) < offset+keyLen {
		return "", nil, fmt.Errorf("invalid session key length")
	}
	return baseID, append([]byte(nil), data[offset:offset+keyLen]...), nil
}

func routedSessionID(baseID string, hasSeq bool, seq uint64) string {
	if !hasSeq {
		return baseID
	}
	return streamWriteSessionID(baseID, seq)
}

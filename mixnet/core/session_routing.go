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
	prefix, keyPrefix, err := buildSessionSetupFrameControlParts(baseSessionID, mode, len(encryptedHeader), len(keyData))
	if err != nil {
		return nil, err
	}
	buf := make([]byte, len(prefix)+len(encryptedHeader)+len(keyPrefix)+len(keyData))
	copy(buf, prefix)
	pos := len(prefix)
	pos += copy(buf[pos:], encryptedHeader)
	pos += copy(buf[pos:], keyPrefix)
	copy(buf[pos:], keyData)
	return buf, nil
}

func buildSessionSetupFrameControlParts(baseSessionID string, mode sessionRouteMode, encryptedHeaderLen int, keyDataLen int) ([]byte, []byte, error) {
	if len(baseSessionID) > 0xff {
		return nil, nil, fmt.Errorf("base session id too long: %d", len(baseSessionID))
	}
	if encryptedHeaderLen < 0 {
		return nil, nil, fmt.Errorf("invalid encrypted header length: %d", encryptedHeaderLen)
	}
	if keyDataLen < 0 {
		return nil, nil, fmt.Errorf("invalid key length: %d", keyDataLen)
	}
	buf := make([]byte, 1+len(baseSessionID)+1+4)
	pos := 0
	buf[pos] = byte(len(baseSessionID))
	pos++
	pos += copy(buf[pos:], baseSessionID)
	buf[pos] = byte(mode)
	pos++
	binary.LittleEndian.PutUint32(buf[pos:], uint32(encryptedHeaderLen))
	keyPrefix := make([]byte, 4)
	binary.LittleEndian.PutUint32(keyPrefix, uint32(keyDataLen))
	return buf, keyPrefix, nil
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

func decodeSessionSetupDeliveryPayloadView(data []byte) (string, []byte, error) {
	return decodeSessionCloseFramePayloadWithKeyView(data)
}

func encodeSessionDataFramePayload(baseSessionID string, hasSeq bool, seq uint64, shard *ces.Shard, totalShards int, authTag []byte) ([]byte, error) {
	if shard == nil {
		return nil, fmt.Errorf("missing shard")
	}
	prefixLen, err := sessionDataControlPrefixLen(baseSessionID, hasSeq, shard.Index, totalShards, len(authTag))
	if err != nil {
		return nil, err
	}
	buf := make([]byte, prefixLen+len(authTag)+len(shard.Data))
	pos, err := writeSessionDataFrameControlPrefix(buf, baseSessionID, hasSeq, seq, shard.Index, totalShards, len(authTag))
	if err != nil {
		return nil, err
	}
	pos += copy(buf[pos:], authTag)
	copy(buf[pos:], shard.Data)
	return buf, nil
}

func buildSessionDataFrameControlPrefix(baseSessionID string, hasSeq bool, seq uint64, shardIndex int, totalShards int, authTagLen int) ([]byte, error) {
	prefixLen, err := sessionDataControlPrefixLen(baseSessionID, hasSeq, shardIndex, totalShards, authTagLen)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, prefixLen)
	_, err = writeSessionDataFrameControlPrefix(buf, baseSessionID, hasSeq, seq, shardIndex, totalShards, authTagLen)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func sessionDataControlPrefixLen(baseSessionID string, hasSeq bool, shardIndex int, totalShards int, authTagLen int) (int, error) {
	if len(baseSessionID) > 0xff {
		return 0, fmt.Errorf("base session id too long: %d", len(baseSessionID))
	}
	if shardIndex < 0 {
		return 0, fmt.Errorf("invalid shard index: %d", shardIndex)
	}
	if totalShards < 0 {
		return 0, fmt.Errorf("invalid total shards: %d", totalShards)
	}
	if authTagLen < 0 || authTagLen > 0xffff {
		return 0, fmt.Errorf("auth tag too large: %d", authTagLen)
	}
	seqLen := 0
	if hasSeq {
		seqLen = 8
	}
	return 1 + len(baseSessionID) + 1 + seqLen + 4 + 4 + 2, nil
}

func writeSessionDataFrameControlPrefix(dst []byte, baseSessionID string, hasSeq bool, seq uint64, shardIndex int, totalShards int, authTagLen int) (int, error) {
	prefixLen, err := sessionDataControlPrefixLen(baseSessionID, hasSeq, shardIndex, totalShards, authTagLen)
	if err != nil {
		return 0, err
	}
	if len(dst) < prefixLen {
		return 0, fmt.Errorf("session data control destination too small: have %d, need %d", len(dst), prefixLen)
	}
	flags := byte(0)
	if hasSeq {
		flags |= sessionDataFlagSequenced
	}
	pos := 0
	dst[pos] = byte(len(baseSessionID))
	pos++
	pos += copy(dst[pos:], baseSessionID)
	dst[pos] = flags
	pos++
	if hasSeq {
		binary.LittleEndian.PutUint64(dst[pos:], seq)
		pos += 8
	}
	binary.LittleEndian.PutUint32(dst[pos:], uint32(shardIndex))
	pos += 4
	binary.LittleEndian.PutUint32(dst[pos:], uint32(totalShards))
	pos += 4
	binary.LittleEndian.PutUint16(dst[pos:], uint16(authTagLen))
	return prefixLen, nil
}

func decodeSessionDataFramePayload(data []byte) (string, bool, uint64, *ces.Shard, int, []byte, error) {
	baseID, hasSeq, seq, shard, totalShards, authTag, err := decodeSessionDataFramePayloadView(data)
	if err != nil {
		return "", false, 0, nil, 0, nil, err
	}
	clonedShard := &ces.Shard{Index: shard.Index}
	if len(shard.Data) > 0 {
		clonedShard.Data = append([]byte(nil), shard.Data...)
	}
	var clonedAuthTag []byte
	if len(authTag) > 0 {
		clonedAuthTag = append([]byte(nil), authTag...)
	}
	return baseID, hasSeq, seq, clonedShard, totalShards, clonedAuthTag, nil
}

func decodeSessionDataFramePayloadView(data []byte) (string, bool, uint64, *ces.Shard, int, []byte, error) {
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
	authTag := data[offset : offset+authLen]
	offset += authLen
	shardData := data[offset:]
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
	baseID, keyData, err := decodeSessionCloseFramePayloadWithKeyView(data)
	if err != nil {
		return "", nil, err
	}
	return baseID, append([]byte(nil), keyData...), nil
}

func decodeSessionCloseFramePayloadWithKeyView(data []byte) (string, []byte, error) {
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
	return baseID, data[offset : offset+keyLen], nil
}

func routedSessionID(baseID string, hasSeq bool, seq uint64) string {
	if !hasSeq {
		return baseID
	}
	return streamWriteSessionID(baseID, seq)
}

package mixnet

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

const lengthPrefixSize = 8

func addLengthPrefix(payload []byte) []byte {
	buf := make([]byte, lengthPrefixSize+len(payload))
	binary.LittleEndian.PutUint64(buf[:lengthPrefixSize], uint64(len(payload)))
	copy(buf[lengthPrefixSize:], payload)
	return buf
}

func addLengthPrefixWithLen(payload []byte, origLen int) []byte {
	buf := make([]byte, lengthPrefixSize+len(payload))
	binary.LittleEndian.PutUint64(buf[:lengthPrefixSize], uint64(origLen))
	copy(buf[lengthPrefixSize:], payload)
	return buf
}

func stripLengthPrefix(payload []byte) ([]byte, error) {
	if len(payload) < lengthPrefixSize {
		return nil, fmt.Errorf("payload too short for length prefix")
	}
	origLen := binary.LittleEndian.Uint64(payload[:lengthPrefixSize])
	data := payload[lengthPrefixSize:]
	if uint64(len(data)) < origLen {
		return nil, fmt.Errorf("payload shorter than expected: got %d want %d", len(data), origLen)
	}
	return data[:origLen], nil
}

func applyPayloadPadding(payload []byte, cfg *MixnetConfig) ([]byte, bool, error) {
	if cfg == nil || cfg.PayloadPaddingStrategy == PaddingStrategyNone {
		return payload, false, nil
	}

	switch cfg.PayloadPaddingStrategy {
	case PaddingStrategyRandom:
		padLen := 0
		if cfg.PayloadPaddingMax > 0 {
			span := cfg.PayloadPaddingMax - cfg.PayloadPaddingMin + 1
			if span <= 0 {
				return nil, false, fmt.Errorf("invalid padding range")
			}
			var buf [4]byte
			if _, err := rand.Read(buf[:]); err != nil {
				return nil, false, err
			}
			v := int(binary.LittleEndian.Uint32(buf[:]))
			padLen = cfg.PayloadPaddingMin + v%span
		}
		if padLen == 0 {
			return payload, false, nil
		}
		padded := make([]byte, len(payload)+padLen)
		copy(padded, payload)
		if _, err := rand.Read(padded[len(payload):]); err != nil {
			return nil, false, err
		}
		return padded, true, nil
	case PaddingStrategyBuckets:
		if len(cfg.PayloadPaddingBuckets) == 0 {
			return payload, false, fmt.Errorf("padding buckets not configured")
		}
		target := 0
		for _, b := range cfg.PayloadPaddingBuckets {
			if b >= len(payload) {
				target = b
				break
			}
		}
		if target == 0 {
			maxBucket := cfg.PayloadPaddingBuckets[len(cfg.PayloadPaddingBuckets)-1]
			if maxBucket <= 0 {
				return payload, false, fmt.Errorf("invalid padding bucket size")
			}
			target = ((len(payload) + maxBucket - 1) / maxBucket) * maxBucket
		}
		if target == len(payload) {
			return payload, false, nil
		}
		padded := make([]byte, target)
		copy(padded, payload)
		if _, err := rand.Read(padded[len(payload):]); err != nil {
			return nil, false, err
		}
		return padded, true, nil
	default:
		return payload, false, fmt.Errorf("unknown padding strategy: %s", cfg.PayloadPaddingStrategy)
	}
}

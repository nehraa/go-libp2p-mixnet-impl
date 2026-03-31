package mixnet

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/mixnet/circuit"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	frameVersionFullOnion  byte = 0x01
	frameVersionHeaderOnly byte = 0x02
)

func encryptOnion(payload []byte, c *circuit.Circuit, dest peer.ID, hopKeys [][]byte) ([]byte, error) {
	if c == nil || len(c.Peers) == 0 {
		return nil, fmt.Errorf("empty circuit")
	}
	if len(hopKeys) != len(c.Peers) {
		return nil, fmt.Errorf("hop key count mismatch")
	}

	current := payload
	for i := len(c.Peers) - 1; i >= 0; i-- {
		isFinal := byte(0)
		nextHop := ""
		if i == len(c.Peers)-1 {
			isFinal = 1
			nextHop = dest.String()
		} else {
			nextHop = c.Peers[i+1].String()
		}
		enc, err := encryptWrappedHopPayload(hopKeys[i], isFinal, nextHop, current)
		if err != nil {
			return nil, err
		}
		current = enc
	}
	return current, nil
}

func encryptOnionWithAEADs(payload []byte, c *circuit.Circuit, dest peer.ID, hopAEADs []cipher.AEAD) ([]byte, error) {
	if c == nil || len(c.Peers) == 0 {
		return nil, fmt.Errorf("empty circuit")
	}
	if len(hopAEADs) != len(c.Peers) {
		return nil, fmt.Errorf("hop aead count mismatch")
	}

	current := payload
	for i := len(c.Peers) - 1; i >= 0; i-- {
		isFinal := byte(0)
		nextHop := ""
		if i == len(c.Peers)-1 {
			isFinal = 1
			nextHop = dest.String()
		} else {
			nextHop = c.Peers[i+1].String()
		}
		enc, err := encryptWrappedHopPayloadWithAEAD(hopAEADs[i], isFinal, nextHop, current)
		if err != nil {
			return nil, err
		}
		current = enc
	}
	return current, nil
}

func encryptOnionPrepared(payload []byte, c *circuit.Circuit, dest peer.ID, hopKeys [][]byte, hopAEADs []cipher.AEAD) ([]byte, error) {
	if c != nil && len(hopAEADs) == len(c.Peers) {
		return encryptOnionWithAEADs(payload, c, dest, hopAEADs)
	}
	return encryptOnion(payload, c, dest, hopKeys)
}

func buildHopPayload(isFinal byte, nextHop string, payload []byte) ([]byte, error) {
	if len(nextHop) > 65535 {
		return nil, fmt.Errorf("next hop too long")
	}
	buf := make([]byte, 1+2+len(nextHop)+len(payload))
	buf[0] = isFinal
	binary.LittleEndian.PutUint16(buf[1:3], uint16(len(nextHop)))
	copy(buf[3:], nextHop)
	copy(buf[3+len(nextHop):], payload)
	return buf, nil
}

func encryptHopPayload(key []byte, payload []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid hop key length")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonceSize := aead.NonceSize()
	out := make([]byte, nonceSize, nonceSize+len(payload)+aead.Overhead())
	nonce := out[:nonceSize]
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(out, nonce, payload, nil), nil
}

func encryptWrappedHopPayload(key []byte, isFinal byte, nextHop string, payload []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid hop key length")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return encryptWrappedHopPayloadWithAEAD(aead, isFinal, nextHop, payload)
}

func encryptWrappedHopPayloadWithAEAD(aead cipher.AEAD, isFinal byte, nextHop string, payload []byte) ([]byte, error) {
	if aead == nil {
		return nil, fmt.Errorf("missing hop aead")
	}
	if len(nextHop) > 65535 {
		return nil, fmt.Errorf("next hop too long")
	}
	plainLen := 1 + 2 + len(nextHop) + len(payload)
	nonceSize := aead.NonceSize()
	out := make([]byte, nonceSize+plainLen+aead.Overhead())
	nonce := out[:nonceSize]
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	plain := out[nonceSize : nonceSize+plainLen]
	plain[0] = isFinal
	binary.LittleEndian.PutUint16(plain[1:3], uint16(len(nextHop)))
	copy(plain[3:], nextHop)
	copy(plain[3+len(nextHop):], payload)
	return aead.Seal(out[:nonceSize], nonce, plain, nil), nil
}

func prepareHopAEADs(hopKeys [][]byte) ([]cipher.AEAD, error) {
	hopAEADs := make([]cipher.AEAD, len(hopKeys))
	for i, key := range hopKeys {
		aead, err := chacha20poly1305.NewX(key)
		if err != nil {
			return nil, err
		}
		hopAEADs[i] = aead
	}
	return hopAEADs, nil
}

func encodeEncryptedFrame(circuitID string, payload []byte) ([]byte, error) {
	return encodeEncryptedFrameWithVersion(circuitID, frameVersionFullOnion, payload)
}

func buildEncryptedFrameHeader(circuitID string, version byte, payloadLen int) ([]byte, error) {
	if len(circuitID) == 0 || len(circuitID) > 255 {
		return nil, fmt.Errorf("invalid circuit id")
	}
	header := make([]byte, 1+len(circuitID)+1+4)
	header[0] = byte(len(circuitID))
	copy(header[1:], []byte(circuitID))
	header[1+len(circuitID)] = version
	binary.LittleEndian.PutUint32(header[1+len(circuitID)+1:], uint32(payloadLen))
	return header, nil
}

func encodeEncryptedFrameWithVersion(circuitID string, version byte, payload []byte) ([]byte, error) {
	header, err := buildEncryptedFrameHeader(circuitID, version, len(payload))
	if err != nil {
		return nil, err
	}
	frame := make([]byte, len(header)+len(payload))
	copy(frame, header)
	copy(frame[len(header):], payload)
	return frame, nil
}

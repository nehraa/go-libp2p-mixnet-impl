package mixnet

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/libp2p/go-libp2p/mixnet/noiseframe"
)

// KeyExchangeProtocolID is the protocol used to negotiate per-circuit hop keys.
const KeyExchangeProtocolID = "/lib-mix/key/1.0.0"

// SessionKeyProtocolID is the protocol used to exchange per-session encryption keys
// directly with the destination (out-of-band from the relay chain).
const SessionKeyProtocolID = "/lib-mix/session-key/1.0.0"

func (m *Mixnet) exchangeHopKey(ctx context.Context, relay peer.ID, circuitID string) ([]byte, error) {
	stream, err := m.host.NewStream(ctx, relay, KeyExchangeProtocolID)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	payload, err := encodeKeyExchangePayload(circuitID, key)
	if err != nil {
		return nil, err
	}

	if err := noiseframe.RunXXInitiator(ctx, stream, payload); err != nil {
		return nil, err
	}

	return key, nil
}

// sendSessionKey exchanges the per-session encryption key directly with the destination
// over a direct (non-relay) Noise XX connection. This prevents any relay node from
// observing the session key material.
func (m *Mixnet) sendSessionKey(ctx context.Context, dest peer.ID, sessionID string, keyData []byte) error {
	stream, err := m.host.NewStream(ctx, dest, SessionKeyProtocolID)
	if err != nil {
		return err
	}
	defer stream.Close()

	payload, err := encodeSessionKeyPayload(sessionID, keyData)
	if err != nil {
		return err
	}
	return noiseframe.RunXXInitiator(ctx, stream, payload)
}

// handleSessionKeyExchange receives a per-session key from the origin directly.
func (m *Mixnet) handleSessionKeyExchange(stream network.Stream) {
	defer stream.Close()
	payload, err := noiseframe.RunXXResponder(context.Background(), stream)
	if err != nil {
		return
	}
	sessionID, keyData, err := decodeSessionKeyPayload(payload)
	if err != nil {
		return
	}
	if m.destHandler == nil {
		return
	}
	m.destHandler.mu.Lock()
	if key, err := decodeSessionKeyData(keyData); err == nil {
		m.destHandler.keys[sessionID] = key
	}
	m.destHandler.mu.Unlock()
}

func encodeKeyExchangePayload(circuitID string, key []byte) ([]byte, error) {
	if len(circuitID) > 255 {
		return nil, fmt.Errorf("circuit ID too long")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid hop key length")
	}
	out := make([]byte, 0, 1+len(circuitID)+2+len(key))
	out = append(out, byte(len(circuitID)))
	out = append(out, []byte(circuitID)...)
	keyLen := make([]byte, 2)
	binary.LittleEndian.PutUint16(keyLen, uint16(len(key)))
	out = append(out, keyLen...)
	out = append(out, key...)
	return out, nil
}

func encodeSessionKeyPayload(sessionID string, keyData []byte) ([]byte, error) {
	if len(sessionID) > 65535 {
		return nil, fmt.Errorf("session ID too long")
	}
	out := make([]byte, 0, 2+len(sessionID)+2+len(keyData))
	idLen := make([]byte, 2)
	binary.LittleEndian.PutUint16(idLen, uint16(len(sessionID)))
	out = append(out, idLen...)
	out = append(out, []byte(sessionID)...)
	kLen := make([]byte, 2)
	binary.LittleEndian.PutUint16(kLen, uint16(len(keyData)))
	out = append(out, kLen...)
	out = append(out, keyData...)
	return out, nil
}

func decodeSessionKeyPayload(data []byte) (string, []byte, error) {
	if len(data) < 4 {
		return "", nil, fmt.Errorf("payload too short")
	}
	pos := 0
	idLen := int(binary.LittleEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if len(data) < pos+idLen+2 {
		return "", nil, fmt.Errorf("payload truncated (session id)")
	}
	sessionID := string(data[pos : pos+idLen])
	pos += idLen
	kLen := int(binary.LittleEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if len(data) < pos+kLen {
		return "", nil, fmt.Errorf("payload truncated (key)")
	}
	key := make([]byte, kLen)
	copy(key, data[pos:pos+kLen])
	return sessionID, key, nil
}


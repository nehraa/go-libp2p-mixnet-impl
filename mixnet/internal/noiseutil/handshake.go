// Package noiseutil provides shared Noise protocol utilities for the mixnet packages.
package noiseutil

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/flynn/noise"
)

// MixnetCipherSuite is the shared Noise cipher suite used across all mixnet components (Req 16.2).
var MixnetCipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// MixnetPrologue is the Noise prologue that binds the handshake to this protocol version.
var MixnetPrologue = []byte("lib-mix/1.0.0")

// PerformHandshake executes a Noise NN handshake over the given stream (Req 16.2).
// isInitiator=true for the circuit manager (origin side).
// Returns (sendCS, recvCS) — the cipher state for sending and for receiving.
// Messages are framed with a 2-byte big-endian length prefix.
//
// After the NN handshake:
//   - cs1 is always initiator→responder
//   - cs2 is always responder→initiator
//
// Initiator: uses cs1 to send, cs2 to receive.
// Responder: uses cs2 to send, cs1 to receive.
func PerformHandshake(stream io.ReadWriter, isInitiator bool) (*noise.CipherState, *noise.CipherState, error) {
	cfg := noise.Config{
		CipherSuite: MixnetCipherSuite,
		Pattern:     noise.HandshakeNN,
		Initiator:   isInitiator,
		Prologue:    MixnetPrologue,
	}

	hs, err := noise.NewHandshakeState(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("noise: failed to create handshake state: %w", err)
	}

	if isInitiator {
		// Message 1: initiator writes
		msg, cs1, cs2, err := hs.WriteMessage(nil, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("noise: failed to write message 1: %w", err)
		}
		_ = cs1
		_ = cs2 // nil after first message in NN pattern
		if err := sendFramed(stream, msg); err != nil {
			return nil, nil, fmt.Errorf("noise: failed to send message 1: %w", err)
		}

		// Message 2: initiator reads
		resp, err := recvFramed(stream)
		if err != nil {
			return nil, nil, fmt.Errorf("noise: failed to recv message 2: %w", err)
		}
		_, cs1, cs2, err = hs.ReadMessage(nil, resp)
		if err != nil {
			return nil, nil, fmt.Errorf("noise: failed to read message 2: %w", err)
		}
		if cs1 == nil || cs2 == nil {
			return nil, nil, fmt.Errorf("noise: handshake did not produce cipher states")
		}
		// Initiator sends with cs1, receives with cs2
		return cs1, cs2, nil
	}

	// Responder path
	// Message 1: responder reads
	msg1, err := recvFramed(stream)
	if err != nil {
		return nil, nil, fmt.Errorf("noise: failed to recv message 1: %w", err)
	}
	_, cs1, cs2, err := hs.ReadMessage(nil, msg1)
	if err != nil {
		return nil, nil, fmt.Errorf("noise: failed to read message 1: %w", err)
	}
	_ = cs1
	_ = cs2 // nil after first message in NN pattern

	// Message 2: responder writes
	msg2, cs1, cs2, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("noise: failed to write message 2: %w", err)
	}
	if cs1 == nil || cs2 == nil {
		return nil, nil, fmt.Errorf("noise: handshake did not produce cipher states")
	}
	if err := sendFramed(stream, msg2); err != nil {
		return nil, nil, fmt.Errorf("noise: failed to send message 2: %w", err)
	}
	// Responder sends with cs2, receives with cs1
	return cs2, cs1, nil
}

// sendFramed writes a message with a 2-byte big-endian length prefix.
func sendFramed(w io.Writer, msg []byte) error {
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(msg)))
	_, err := w.Write(append(lenBuf, msg...))
	return err
}

// recvFramed reads a 2-byte length-prefixed message.
func recvFramed(r io.Reader) ([]byte, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	msgLen := binary.BigEndian.Uint16(lenBuf)
	msg := make([]byte, msgLen)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

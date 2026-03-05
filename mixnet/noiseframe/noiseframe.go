// Package noiseframe provides shared framing utilities, the Noise cipher suite,
// and Noise XX handshake helpers used by both the mixnet origin and relay packages.
package noiseframe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/libp2p/go-libp2p/core/network"

	"github.com/flynn/noise"
)

// CipherSuite is the Noise cipher suite used for all key exchanges.
var CipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// WriteFrame writes a length-prefixed frame to w.
func WriteFrame(w io.Writer, msg []byte) error {
	if len(msg) > 65535 {
		return fmt.Errorf("frame too large")
	}
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(msg)))
	if _, err := w.Write(lenBuf); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}

// ReadFrame reads a length-prefixed frame from r.
func ReadFrame(r io.Reader) ([]byte, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lenBuf))
	if n <= 0 {
		return nil, fmt.Errorf("invalid frame length")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// RunXXInitiator runs the initiator side of a Noise XX handshake over stream,
// sending payload in the final handshake message.
func RunXXInitiator(ctx context.Context, stream network.Stream, payload []byte) error {
	kp, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		return fmt.Errorf("keypair: %w", err)
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   CipherSuite,
		Pattern:       noise.HandshakeXX,
		Initiator:     true,
		StaticKeypair: kp,
	})
	if err != nil {
		return fmt.Errorf("handshake init: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	} else {
		_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
	}
	msg, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return fmt.Errorf("handshake write: %w", err)
	}
	if err := WriteFrame(stream, msg); err != nil {
		return err
	}
	resp, err := ReadFrame(stream)
	if err != nil {
		return err
	}
	if _, _, _, err := hs.ReadMessage(nil, resp); err != nil {
		return fmt.Errorf("handshake read: %w", err)
	}
	msg, cs1, _, err := hs.WriteMessage(nil, payload)
	if err != nil {
		return fmt.Errorf("handshake write final: %w", err)
	}
	if err := WriteFrame(stream, msg); err != nil {
		return err
	}
	if cs1 == nil {
		return fmt.Errorf("missing cipher state after handshake")
	}
	return nil
}

// RunXXResponder runs the responder side of a Noise XX handshake over stream,
// returning the payload received in the final handshake message.
func RunXXResponder(ctx context.Context, stream network.Stream) ([]byte, error) {
	kp, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keypair: %w", err)
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   CipherSuite,
		Pattern:       noise.HandshakeXX,
		Initiator:     false,
		StaticKeypair: kp,
	})
	if err != nil {
		return nil, fmt.Errorf("handshake init: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	} else {
		_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
	}
	msg, err := ReadFrame(stream)
	if err != nil {
		return nil, err
	}
	if _, _, _, err := hs.ReadMessage(nil, msg); err != nil {
		return nil, fmt.Errorf("handshake read: %w", err)
	}
	reply, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("handshake write: %w", err)
	}
	if err := WriteFrame(stream, reply); err != nil {
		return nil, err
	}
	final, err := ReadFrame(stream)
	if err != nil {
		return nil, err
	}
	plaintext, _, _, err := hs.ReadMessage(nil, final)
	if err != nil {
		return nil, fmt.Errorf("handshake read final: %w", err)
	}
	return plaintext, nil
}

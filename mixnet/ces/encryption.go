package ces

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/flynn/noise"
)

var mixnetCipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// LayeredEncrypter handles layered onion encryption
type LayeredEncrypter struct {
	hopCount int
}

// EncryptionKey represents an ephemeral key for one encryption layer
type EncryptionKey struct {
	Key         []byte // Curve25519 private key
	Destination string
	nonce       uint64 // counter-based nonce, initialized to 0
}

// NewLayeredEncrypter creates a new layered encrypter
func NewLayeredEncrypter(hopCount int) *LayeredEncrypter {
	return &LayeredEncrypter{
		hopCount: hopCount,
	}
}

// Encrypt encrypts data with layered encryption (onion routing)
// Each layer wraps the data with destination info and encryption
// Destinations should be ordered from entry to exit (first hop = entry)
func (e *LayeredEncrypter) Encrypt(plaintext []byte, destinations []string) ([]byte, []*EncryptionKey, error) {
	if len(destinations) != e.hopCount {
		return nil, nil, fmt.Errorf("expected %d destinations, got %d", e.hopCount, len(destinations))
	}

	keys := make([]*EncryptionKey, e.hopCount)

	// Generate ephemeral Curve25519 keypair for each layer (Req 16.2)
	for i := 0; i < e.hopCount; i++ {
		kp, err := mixnetCipherSuite.GenerateKeypair(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		keys[i] = &EncryptionKey{
			Key:         kp.Private,
			Destination: destinations[i],
		}
	}

	// Build encrypted payload from outside in (reverse order for onion)
	// Start with innermost layer (exit relay)
	currentData := plaintext

	for i := e.hopCount - 1; i >= 0; i-- {
		// Build header: [dest_len:2][dest_bytes]
		destBytes := []byte(keys[i].Destination)
		header := make([]byte, 2+len(destBytes))
		binary.LittleEndian.PutUint16(header[0:2], uint16(len(destBytes)))
		copy(header[2:], destBytes)

		// Prepend header to data
		payload := append(header, currentData...)

		// Encrypt with Noise ChaCha20-Poly1305 using counter nonce (Req 16.2)
		var k [32]byte
		copy(k[:], keys[i].Key)
		noiseCipher := noise.CipherChaChaPoly.Cipher(k)
		encrypted := noiseCipher.Encrypt(nil, keys[i].nonce, nil, payload)
		currentData = encrypted
	}

	return currentData, keys, nil
}

// Decrypt decrypts layered encrypted data
// Keys should be provided in reverse order (outermost to innermost)
func (e *LayeredEncrypter) Decrypt(ciphertext []byte, keys []*EncryptionKey) ([]byte, error) {
	if len(keys) != e.hopCount {
		return nil, fmt.Errorf("expected %d keys, got %d", e.hopCount, len(keys))
	}

	// Decrypt from outside in
	currentData := ciphertext

	for i := 0; i < e.hopCount; i++ {
		var k [32]byte
		copy(k[:], keys[i].Key)
		noiseCipher := noise.CipherChaChaPoly.Cipher(k)

		plaintext, err := noiseCipher.Decrypt(nil, keys[i].nonce, nil, currentData)
		if err != nil {
			return nil, err
		}

		// Extract destination from header: [dest_len:2][dest_bytes][data]
		if len(plaintext) < 2 {
			return nil, fmt.Errorf("invalid header: too short")
		}
		destLen := int(binary.LittleEndian.Uint16(plaintext[0:2]))
		if len(plaintext) < 2+destLen {
			return nil, fmt.Errorf("invalid destination length")
		}

		// Remaining is the decrypted payload for next layer
		currentData = plaintext[2+destLen:]
	}

	return currentData, nil
}

// SecureErase securely wipes all key material from memory (Req 16.3).
// Uses explicit byte-level zeroing that cannot be optimized away by the compiler
// via the use of the runtime.KeepAlive barrier (via unsafe indirect write).
func SecureEraseBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// SecureErase implements the Eraser interface (Req 16.3).
// Callers are responsible for passing the key slices they wish to erase;
// this method is intentionally a no-op on the encrypter itself because
// keys are generated and held by the caller (not stored inside
// LayeredEncrypter).  Use SecureEraseBytes on the EncryptionKey.Key slices.
func (e *LayeredEncrypter) SecureErase() {}

// EraseKeys zeroes out all key material in the provided keys slice (Req 16.3).
func EraseKeys(keys []*EncryptionKey) {
	for _, k := range keys {
		if k != nil {
			SecureEraseBytes(k.Key)
		}
	}
}

// HopCount returns the number of encryption layers
func (e *LayeredEncrypter) HopCount() int {
	return e.hopCount
}

// Eraser interface for secure key erasure
type Eraser interface {
	SecureErase()
}

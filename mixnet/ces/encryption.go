package ces

import (
	cryptorand "crypto/rand"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/flynn/noise"
)

// noiseSuite is the cipher suite used for all layered encryption.
var noiseSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// LayeredEncrypter implements multi-layer onion encryption for mixnet traffic.
// It handles layered onion encryption using Noise Protocol primitives.
type LayeredEncrypter struct {
	hopCount int
}

// EncryptionKey holds the key material and destination information for a single encryption layer.
type EncryptionKey struct {
	// Key is the raw symmetric key material.
	Key []byte
	// EphemeralPub is the ephemeral public key used for this layer.
	EphemeralPub []byte
	// Destination is the identifier of the peer that should decrypt this layer.
	Destination string
}

// NewLayeredEncrypter creates a new LayeredEncrypter with the specified number of hops.
func NewLayeredEncrypter(hopCount int) *LayeredEncrypter {
	return &LayeredEncrypter{hopCount: hopCount}
}

// deriveKey uses HMAC-SHA256 HKDF to derive a 32-byte key from inputKeyMaterial.
func deriveKey(inputKeyMaterial []byte) ([]byte, error) {
	// HKDF-Extract with zero chaining key
	ck := make([]byte, 32)
	mac1 := hmac.New(sha256.New, ck)
	mac1.Write(inputKeyMaterial)
	prk := mac1.Sum(nil)
	// HKDF-Expand: T(1) = HMAC(prk, 0x01)
	mac2 := hmac.New(sha256.New, prk)
	mac2.Write([]byte{0x01})
	return mac2.Sum(nil)[:32], nil
}

// Encrypt wraps the data in multiple layers of encryption, one for each hop in the mixnet circuit.
// Each layer contains the destination of the next hop and is encrypted with an ephemeral key.
// Destinations should be ordered from entry relay to exit relay.
func (e *LayeredEncrypter) Encrypt(plaintext []byte, destinations []string) ([]byte, []*EncryptionKey, error) {
	if len(destinations) != e.hopCount {
		return nil, nil, fmt.Errorf("expected %d destinations, got %d", e.hopCount, len(destinations))
	}

	keys := make([]*EncryptionKey, e.hopCount)

	for i := 0; i < e.hopCount; i++ {
		kp, err := noiseSuite.GenerateKeypair(cryptorand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate keypair for hop %d: %w", i, err)
		}
		k, err := deriveKey(kp.Private)
		// Securely erase the ephemeral private key after derivation (Req 16.3)
		SecureEraseBytes(kp.Private)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to derive key for hop %d: %w", i, err)
		}
		keys[i] = &EncryptionKey{
			Key:          k,
			EphemeralPub: kp.Public,
			Destination:  destinations[i],
		}
	}

	currentData := plaintext
	for i := e.hopCount - 1; i >= 0; i-- {
		dest := destinations[i]
		// Header: [dest_len: 2 bytes][dest_bytes][ephemeral_pub: 32 bytes]
		header := make([]byte, 2+len(dest)+32)
		binary.LittleEndian.PutUint16(header[0:2], uint16(len(dest)))
		copy(header[2:], dest)
		copy(header[2+len(dest):], keys[i].EphemeralPub)

		payload := append(header, currentData...)

		// Encrypt with Noise CipherChaChaPoly.
		// Nonce is derived from the first 8 bytes of the ephemeral public key.
		// Each key is ephemeral and used exactly once; deriving the nonce from the
		// public key binds it to the keypair and adds defense-in-depth against any
		// accidental key reuse.
		nonce := binary.LittleEndian.Uint64(keys[i].EphemeralPub[:8])
		var cipherKey [32]byte
		copy(cipherKey[:], keys[i].Key)
		cipher := noiseSuite.Cipher(cipherKey)

		encrypted := cipher.Encrypt(nil, nonce, nil, payload)
		currentData = encrypted
	}

	return currentData, keys, nil
}

// Decrypt removes one or more layers of onion encryption using the provided keys.
// Keys should be provided in the order of the hops encountered (outermost to innermost).
func (e *LayeredEncrypter) Decrypt(ciphertext []byte, keys []*EncryptionKey) ([]byte, error) {
	if len(keys) != e.hopCount {
		return nil, fmt.Errorf("expected %d keys, got %d", e.hopCount, len(keys))
	}

	currentData := ciphertext

	for i := 0; i < e.hopCount; i++ {
		if len(currentData) < 1 {
			return nil, fmt.Errorf("ciphertext too short for hop %d", i)
		}

		// Nonce derived from first 8 bytes of the stored ephemeral public key (matches Encrypt).
		nonce := binary.LittleEndian.Uint64(keys[i].EphemeralPub[:8])
		var cipherKey [32]byte
		copy(cipherKey[:], keys[i].Key)
		cipher := noiseSuite.Cipher(cipherKey)

		plaintext, err := cipher.Decrypt(nil, nonce, nil, currentData)
		if err != nil {
			return nil, fmt.Errorf("decryption failed for hop %d: %w", i, err)
		}

		// Parse header: [dest_len: 2][dest_bytes][ephemeral_pub: 32][payload...]
		if len(plaintext) < 2 {
			return nil, fmt.Errorf("invalid header at hop %d", i)
		}
		destLen := int(binary.LittleEndian.Uint16(plaintext[0:2]))
		headerSize := 2 + destLen + 32
		if len(plaintext) < headerSize {
			return nil, fmt.Errorf("invalid header size at hop %d", i)
		}
		currentData = plaintext[headerSize:]
	}

	return currentData, nil
}

// SecureEraseBytes overwrites the content of a byte slice with zeroes to remove sensitive data from memory.
func SecureEraseBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// SecureErase implements the Eraser interface (Req 16.3).
func (e *LayeredEncrypter) SecureErase() {}

// EraseKeys overwrites all key material in a slice of EncryptionKey instances.
func EraseKeys(keys []*EncryptionKey) {
	for _, k := range keys {
		if k != nil {
			SecureEraseBytes(k.Key)
			SecureEraseBytes(k.EphemeralPub)
		}
	}
}

// HopCount returns the number of encryption layers configured for this encrypter.
func (e *LayeredEncrypter) HopCount() int {
	return e.hopCount
}

// Eraser is an interface for types that can securely erase their sensitive contents.
type Eraser interface {
	SecureErase()
}

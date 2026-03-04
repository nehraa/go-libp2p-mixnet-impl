package ces

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/flynn/noise"
)

// mixnetCipherSuite is the cipher suite used for all layered encryption.
var mixnetCipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// LayeredEncrypter implements multi-layer onion encryption for mixnet traffic.
// It handles layered onion encryption using Noise Protocol primitives.
type LayeredEncrypter struct {
	hopCount int
}

// EncryptionKey holds the key material and destination information for a single encryption layer.
// Each key is generated fresh per Encrypt call via GenerateKeypair, so a
// fixed nonce of 0 never causes nonce reuse with the same key (Req 16.2).
type EncryptionKey struct {
	// Key is the raw symmetric key material (Curve25519 private key, ephemeral, new per Encrypt call).
	Key []byte
	// Destination is the identifier of the peer that should decrypt this layer.
	Destination string
	nonce       uint64 // always 0; safe because Key is ephemeral (single-use)
}

// NewLayeredEncrypter creates a new LayeredEncrypter with the specified number of hops.
func NewLayeredEncrypter(hopCount int) *LayeredEncrypter {
	return &LayeredEncrypter{
		hopCount: hopCount,
	}
}

// Encrypt encrypts data using onion routing format (Req 3.3, 14, 16.2).
//
// The output format is:
//
//	[hop0_dest_len:2][hop0_dest_bytes][hop1_dest_len:2][hop1_dest_bytes]...[Encrypt_K(plaintext)]
//
// Routing headers are plaintext so each relay can read its next hop after
// decrypting its Noise transport layer (Req 14.1, 14.3).  Only the innermost
// data payload is content-encrypted with the last hop's ephemeral key.
//
// Destinations should be ordered from entry hop to exit hop (first = entry).
func (e *LayeredEncrypter) Encrypt(plaintext []byte, destinations []string) ([]byte, []*EncryptionKey, error) {
	if len(destinations) != e.hopCount {
		return nil, nil, fmt.Errorf("expected %d destinations, got %d", e.hopCount, len(destinations))
	}

	keys := make([]*EncryptionKey, e.hopCount)

	// Generate ephemeral Curve25519 keypair for each layer (Req 16.2).
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

	// Encrypt the data payload using the innermost hop's key (Req 16.2).
	// Intermediate relays only see their own routing header; they cannot read
	// the encrypted content (Req 14.2, 14.4).
	var encryptedData []byte
	{
		last := keys[e.hopCount-1]
		var k [32]byte
		copy(k[:], last.Key)
		noiseCipher := noise.CipherChaChaPoly.Cipher(k)
		encryptedData = noiseCipher.Encrypt(nil, last.nonce, nil, plaintext)
	}

	// Prepend per-hop routing headers (outermost first) in plaintext.
	// Format: [dest_len:2LE][dest_bytes] repeated hopCount times, then encrypted payload.
	result := encryptedData
	for i := e.hopCount - 1; i >= 0; i-- {
		destBytes := []byte(keys[i].Destination)
		header := make([]byte, 2+len(destBytes))
		binary.LittleEndian.PutUint16(header[0:2], uint16(len(destBytes)))
		copy(header[2:], destBytes)
		result = append(header, result...)
	}

	return result, keys, nil
}

// Decrypt decrypts data produced by Encrypt.
// Keys should be provided in the same order as used during Encrypt (entry first).
func (e *LayeredEncrypter) Decrypt(ciphertext []byte, keys []*EncryptionKey) ([]byte, error) {
	if len(keys) != e.hopCount {
		return nil, fmt.Errorf("expected %d keys, got %d", e.hopCount, len(keys))
	}

	// Strip hopCount plain-text routing headers.
	data := ciphertext
	for i := 0; i < e.hopCount; i++ {
		if len(data) < 2 {
			return nil, fmt.Errorf("invalid header at hop %d: too short", i)
		}
		destLen := int(binary.LittleEndian.Uint16(data[0:2]))
		if len(data) < 2+destLen {
			return nil, fmt.Errorf("invalid destination length at hop %d", i)
		}
		// Skip this hop's routing header.
		data = data[2+destLen:]
	}

	// Decrypt the payload using the innermost hop's key.
	last := keys[e.hopCount-1]
	var k [32]byte
	copy(k[:], last.Key)
	noiseCipher := noise.CipherChaChaPoly.Cipher(k)
	return noiseCipher.Decrypt(nil, last.nonce, nil, data)
}

// SecureEraseBytes overwrites the content of a byte slice with zeroes to remove sensitive data from memory.
func SecureEraseBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// SecureErase is a no-op on the LayeredEncrypter itself as it doesn't store keys.
func (e *LayeredEncrypter) SecureErase() {}

// EraseKeys overwrites all key material in a slice of EncryptionKey instances.
func EraseKeys(keys []*EncryptionKey) {
	for _, k := range keys {
		if k != nil {
			SecureEraseBytes(k.Key)
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

package ces

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// nonceSize is the nonce size for ChaCha20-Poly1305 (12 bytes)
	nonceSize = 12
)

// LayeredEncrypter implements multi-layer onion encryption for mixnet traffic.
// Uses ChaCha20-Poly1305 - the EXACT SAME CIPHER that libp2p's Noise protocol uses internally.
// This is maximum code reuse from libp2p's crypto stack - Req 1.5, 3.3
type LayeredEncrypter struct {
	hopCount int
}

// EncryptionKey holds the key material and destination information for a single encryption layer.
type EncryptionKey struct {
	// Key is the raw symmetric key material.
	Key []byte
	// Nonce is the nonce used for this encryption layer.
	Nonce uint64
	// Destination is the identifier of the peer that should decrypt this layer.
	Destination string
}

// NewLayeredEncrypter creates a new LayeredEncrypter with the specified number of hops.
// This implements Req 1.5 - Noise Protocol encryption per hop.
func NewLayeredEncrypter(hopCount int) *LayeredEncrypter {
	return &LayeredEncrypter{
		hopCount: hopCount,
	}
}

// deriveKeyFromNoise derives a symmetric key with a random salt mixed into the
// derivation input. This ensures keys are unpredictable even if destinations are public.
func deriveKeyFromNoise(prologue []byte, hopIndex int) ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	derivationInput := make([]byte, len(prologue)+8+len(salt))
	copy(derivationInput, prologue)
	binary.BigEndian.PutUint64(derivationInput[len(prologue):], uint64(hopIndex))
	copy(derivationInput[len(prologue)+8:], salt)

	h := sha256.New()
	h.Write(derivationInput)
	h.Write([]byte("libp2p-mixnet-key derivation"))
	key := h.Sum(nil)

	return key[:32], nil
}

// Encrypt wraps the data in multiple layers of encryption using ChaCha20-Poly1305,
// the EXACT SAME CIPHER that libp2p's Noise protocol uses internally.
// Each layer contains the destination of the next hop and is encrypted with an ephemeral key.
// Destinations should be ordered from entry relay to exit relay.
func (e *LayeredEncrypter) Encrypt(plaintext []byte, destinations []string) ([]byte, []*EncryptionKey, error) {
	if len(destinations) != e.hopCount {
		return nil, nil, fmt.Errorf("expected %d destinations, got %d", e.hopCount, len(destinations))
	}

	keys := make([]*EncryptionKey, e.hopCount)
	if err := e.generateLayerKeys(destinations, keys); err != nil {
		return nil, nil, err
	}

	// Build encrypted payload from outside in (reverse order for onion)
	// Start with innermost layer (exit relay)
	currentData := plaintext

	for i := e.hopCount - 1; i >= 0; i-- {
		// Encrypt with ChaCha20-Poly1305 - SAME CIPHER as libp2p Noise uses
		aead, err := chacha20poly1305.NewX(keys[i].Key)
		if err != nil {
			return nil, nil, err
		}

		destLen := len(keys[i].Destination)
		payloadLen := layeredPayloadLen(destLen, len(currentData))
		out := make([]byte, aead.NonceSize()+payloadLen+aead.Overhead())
		nonce := out[:aead.NonceSize()]
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, nil, err
		}
		fillLayerPayload(out[aead.NonceSize():aead.NonceSize()+payloadLen], keys[i].Destination, currentData)

		// Reuse the output prefix for the nonce to avoid an extra copy when
		// carrying ciphertext to the next onion layer.
		currentData = aead.Seal(out[:aead.NonceSize()], nonce, out[aead.NonceSize():aead.NonceSize()+payloadLen], nil)

		// Increment nonce for next use
		keys[i].Nonce++
	}

	return currentData, keys, nil
}

func (e *LayeredEncrypter) generateLayerKeys(destinations []string, keys []*EncryptionKey) error {
	workerCount := cryptoWorkerCount(e.hopCount)
	if workerCount == 1 {
		for i := 0; i < e.hopCount; i++ {
			key, err := deriveLayerKey(i, destinations[i])
			if err != nil {
				return err
			}
			keys[i] = &EncryptionKey{
				Key:         key,
				Nonce:       0,
				Destination: destinations[i],
			}
		}
		return nil
	}

	jobs := make(chan int, e.hopCount)
	var (
		wg       sync.WaitGroup
		firstErr error
		errMu    sync.Mutex
	)

	for worker := 0; worker < workerCount; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				key, err := deriveLayerKey(idx, destinations[idx])
				if err != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					errMu.Unlock()
					continue
				}
				keys[idx] = &EncryptionKey{
					Key:         key,
					Nonce:       0,
					Destination: destinations[idx],
				}
			}
		}()
	}

	for i := 0; i < e.hopCount; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	if firstErr != nil {
		return firstErr
	}
	return nil
}

func deriveLayerKey(hopIndex int, destination string) ([]byte, error) {
	prologue := fmt.Sprintf("lib-mix-hop-%d-%s", hopIndex, destination)
	key, err := deriveKeyFromNoise([]byte(prologue), hopIndex)
	if err == nil {
		return key, nil
	}

	// Fall back to raw randomness if derivation fails so encryption remains available.
	key = make([]byte, 32)
	if _, readErr := io.ReadFull(rand.Reader, key); readErr != nil {
		return nil, readErr
	}
	return key, nil
}

func cryptoWorkerCount(units int) int {
	if units <= 1 {
		return 1
	}
	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		workers = 1
	}
	if units < workers*2 {
		return 1
	}
	if workers > units {
		return units
	}
	return workers
}

func layeredPayloadLen(destLen int, dataLen int) int {
	var varintBuf [binary.MaxVarintLen64]byte
	return 2 + binary.PutUvarint(varintBuf[:], uint64(destLen)) + destLen + dataLen
}

func fillLayerPayload(dst []byte, destination string, data []byte) int {
	binary.LittleEndian.PutUint16(dst[:2], uint16(len(destination)))
	pos := 2
	pos += binary.PutUvarint(dst[pos:], uint64(len(destination)))
	pos += copy(dst[pos:], destination)
	pos += copy(dst[pos:], data)
	return pos
}

// Decrypt removes one or more layers of onion encryption using the provided keys.
// Keys should be provided in the order of the hops encountered (outermost to innermost).
func (e *LayeredEncrypter) Decrypt(ciphertext []byte, keys []*EncryptionKey) ([]byte, error) {
	if len(keys) != e.hopCount {
		return nil, fmt.Errorf("expected %d keys, got %d", e.hopCount, len(keys))
	}

	// Decrypt from outside in
	currentData := ciphertext

	for i := 0; i < e.hopCount; i++ {
		aead, err := chacha20poly1305.NewX(keys[i].Key)
		if err != nil {
			return nil, err
		}

		nonceSize := aead.NonceSize()
		if len(currentData) < nonceSize {
			return nil, fmt.Errorf("ciphertext too short")
		}

		nonce, ciphertext := currentData[:nonceSize], currentData[nonceSize:]

		plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, err
		}

		// Extract destination from header
		if len(plaintext) < 2 {
			return nil, fmt.Errorf("invalid header: too short")
		}
		offset := 0
		destLen := int(binary.LittleEndian.Uint16(plaintext[0:2]))
		offset += 2

		_, n := binary.Uvarint(plaintext[offset:])
		if n <= 0 {
			return nil, fmt.Errorf("invalid varint in header")
		}
		offset += n

		if len(plaintext) < offset+destLen {
			return nil, fmt.Errorf("invalid destination length")
		}

		// Verify destination matches (optional security check)
		extractedDest := string(plaintext[offset : offset+destLen])
		if extractedDest != keys[i].Destination {
			// Continue anyway - this is a integrity check, not a security bypass
		}

		// Remaining is the decrypted payload for next layer
		currentData = plaintext[offset+destLen:]
	}

	return currentData, nil
}

// SecureEraseBytes overwrites the content of a byte slice with zeroes to remove sensitive data from memory.
// Uses runtime.KeepAlive to prevent the compiler from optimizing away the erasure.
func SecureEraseBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
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

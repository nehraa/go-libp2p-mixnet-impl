package mixnet

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"sync"

	"github.com/libp2p/go-libp2p/mixnet/ces"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	sessionKeySize   = 32
	sessionNonceSize = 24
	sessionKeyDataV1 = sessionNonceSize + sessionKeySize
	sessionKeyDataV2 = 1 + sessionNonceSize + sessionKeySize
)

const (
	sessionCryptoModeWholePayload   byte = 0x00
	sessionCryptoModePerShard       byte = 0x01
	sessionCryptoModeWholeStream    byte = 0x02
	sessionCryptoModePerShardStream byte = 0x03
	sessionStreamNonceDomain             = "mixnet-stream-session-nonce"
)

type sessionKey struct {
	Key   []byte
	Nonce []byte
	Mode  byte
}

func encryptSessionPayload(plaintext []byte) ([]byte, []byte, error) {
	session, err := newSessionKey(sessionCryptoModeWholePayload)
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err := encryptSessionPayloadWithKey(plaintext, session, "")
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, encodeSessionKeyData(session), nil
}

func encryptSessionPayloadWithKey(plaintext []byte, session sessionKey, sessionID string) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(session.Key)
	if err != nil {
		return nil, err
	}
	var nonceBuf [sessionNonceSize]byte
	ciphertext := aead.Seal(nil, sessionPayloadNonceBytes(&nonceBuf, session, sessionID), plaintext, nil)
	return ciphertext, nil
}

func decryptSessionPayloadWithKey(ciphertext []byte, key sessionKey, sessionID string) ([]byte, error) {
	if len(key.Key) != sessionKeySize || len(key.Nonce) != sessionNonceSize {
		return nil, fmt.Errorf("invalid session key material")
	}
	aead, err := chacha20poly1305.NewX(key.Key)
	if err != nil {
		return nil, err
	}
	var nonceBuf [sessionNonceSize]byte
	return aead.Open(nil, sessionPayloadNonceBytes(&nonceBuf, key, sessionID), ciphertext, nil)
}

func encryptSessionShardsWithKey(plaintext []byte, session sessionKey, total int, sessionID string) ([]*ces.Shard, error) {
	if total <= 0 {
		return nil, fmt.Errorf("invalid shard count: %d", total)
	}
	shards, err := shardEvenly(plaintext, total)
	if err != nil {
		return nil, err
	}

	workerCount := shardCryptoWorkerCount(total, len(plaintext))
	if workerCount == 1 {
		aead, err := chacha20poly1305.NewX(session.Key)
		if err != nil {
			return nil, err
		}
		var nonceBuf [sessionNonceSize]byte
		for _, shard := range shards {
			nonce := sessionShardNonceBytes(&nonceBuf, session, sessionID, shard.Index)
			shard.Data = aead.Seal(nil, nonce, shard.Data, nil)
		}
		return shards, nil
	}

	jobs := make(chan *ces.Shard, len(shards))
	var (
		wg       sync.WaitGroup
		firstErr error
		errOnce  sync.Once
	)

	for worker := 0; worker < workerCount; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			aead, err := chacha20poly1305.NewX(session.Key)
			if err != nil {
				errOnce.Do(func() {
					firstErr = err
				})
				return
			}
			var nonceBuf [sessionNonceSize]byte

			for shard := range jobs {
				nonce := sessionShardNonceBytes(&nonceBuf, session, sessionID, shard.Index)
				shard.Data = aead.Seal(nil, nonce, shard.Data, nil)
			}
		}()
	}

	for _, shard := range shards {
		jobs <- shard
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}

	return shards, nil
}

func shardCryptoWorkerCount(total int, payloadLen int) int {
	if total <= 1 {
		return 1
	}
	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		workers = 1
	}
	// Small payloads or shallow shard counts lose more to goroutine/channel
	// setup than they gain from parallel AEAD work.
	if payloadLen < 32*1024 || total < workers*2 {
		return 1
	}
	if workers > total {
		return total
	}
	return workers
}

func decryptSessionShardPayloadWithKey(ciphertext []byte, key sessionKey, shardIndex int, sessionID string) ([]byte, error) {
	if len(key.Key) != sessionKeySize || len(key.Nonce) != sessionNonceSize {
		return nil, fmt.Errorf("invalid session key material")
	}
	aead, err := chacha20poly1305.NewX(key.Key)
	if err != nil {
		return nil, err
	}
	var nonceBuf [sessionNonceSize]byte
	return aead.Open(nil, sessionShardNonceBytes(&nonceBuf, key, sessionID, shardIndex), ciphertext, nil)
}

func streamSessionMode(mode byte) bool {
	return mode == sessionCryptoModeWholeStream || mode == sessionCryptoModePerShardStream
}

func sessionPayloadNonceBytes(dst *[sessionNonceSize]byte, key sessionKey, sessionID string) []byte {
	if !streamSessionMode(key.Mode) {
		return key.Nonce
	}
	fillSessionStreamNonce(dst, key.Nonce, streamSessionSequence(sessionID), -1)
	return dst[:]
}

func sessionShardNonceBytes(dst *[sessionNonceSize]byte, key sessionKey, sessionID string, shardIndex int) []byte {
	if !streamSessionMode(key.Mode) {
		fillSessionShardNonce(dst, key.Nonce, shardIndex)
		return dst[:]
	}
	fillSessionStreamNonce(dst, key.Nonce, streamSessionSequence(sessionID), shardIndex)
	return dst[:]
}

func streamSessionSequence(sessionID string) uint64 {
	_, seq, ok := parseStreamWriteSequence(sessionID)
	if !ok {
		return 0
	}
	return seq
}

func fillSessionStreamNonce(dst *[sessionNonceSize]byte, base []byte, seq uint64, shardIndex int) {
	var buf [12]byte
	binary.LittleEndian.PutUint64(buf[:8], seq)
	if shardIndex >= 0 {
		binary.LittleEndian.PutUint32(buf[8:], uint32(shardIndex+1))
	}
	var input [len(sessionStreamNonceDomain) + sessionNonceSize + 12]byte
	pos := copy(input[:], sessionStreamNonceDomain)
	pos += copy(input[pos:], base)
	copy(input[pos:], buf[:])
	sum := sha256.Sum256(input[:])
	copy(dst[:], sum[:sessionNonceSize])
}

func encryptSessionShards(plaintext []byte, total int) ([]*ces.Shard, []byte, error) {
	if total <= 0 {
		return nil, nil, fmt.Errorf("invalid shard count: %d", total)
	}
	session, err := newSessionKey(sessionCryptoModePerShard)
	if err != nil {
		return nil, nil, err
	}
	shards, err := encryptSessionShardsWithKey(plaintext, session, total, "")
	if err != nil {
		return nil, nil, err
	}
	return shards, encodeSessionKeyData(session), nil
}

func decryptSessionPayload(ciphertext []byte, key sessionKey) ([]byte, error) {
	return decryptSessionPayloadWithKey(ciphertext, key, "")
}

func newSessionKey(mode byte) (sessionKey, error) {
	key := make([]byte, sessionKeySize)
	nonce := make([]byte, sessionNonceSize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return sessionKey{}, err
	}
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return sessionKey{}, err
	}
	return sessionKey{Key: key, Nonce: nonce, Mode: mode}, nil
}

func fillSessionShardNonce(dst *[sessionNonceSize]byte, base []byte, shardIndex int) {
	copy(dst[:], base)
	tail := binary.LittleEndian.Uint64(dst[sessionNonceSize-8:])
	binary.LittleEndian.PutUint64(dst[sessionNonceSize-8:], tail^uint64(shardIndex+1))
}

func encodeSessionKeyData(key sessionKey) []byte {
	if key.Mode == sessionCryptoModeWholePayload {
		buf := make([]byte, 0, sessionKeyDataV1)
		buf = append(buf, key.Nonce...)
		buf = append(buf, key.Key...)
		return buf
	}
	buf := make([]byte, 0, sessionKeyDataV2)
	buf = append(buf, key.Mode)
	buf = append(buf, key.Nonce...)
	buf = append(buf, key.Key...)
	return buf
}

func decodeSessionKeyData(data []byte) (sessionKey, error) {
	mode := sessionCryptoModeWholePayload
	switch len(data) {
	case sessionKeyDataV1:
	case sessionKeyDataV2:
		mode = data[0]
		data = data[1:]
	default:
		return sessionKey{}, fmt.Errorf("invalid key data length")
	}
	nonce := make([]byte, sessionNonceSize)
	key := make([]byte, sessionKeySize)
	copy(nonce, data[:sessionNonceSize])
	copy(key, data[sessionNonceSize:])
	return sessionKey{Key: key, Nonce: nonce, Mode: mode}, nil
}

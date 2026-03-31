package mixnet

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

func deriveAuthKey(key sessionKey) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("mixnet-auth-tag"))
	_, _ = h.Write(key.Nonce)
	_, _ = h.Write(key.Key)
	return h.Sum(nil)
}

func computeAuthTag(key sessionKey, sessionID []byte, shardIndex uint32, totalShards uint32, shardData []byte, hasKeys bool, keyData []byte, tagSize int) []byte {
	authKey := deriveAuthKey(key)
	mac := hmac.New(sha256.New, authKey)
	_, _ = mac.Write(sessionID)
	var buf [8]byte
	binary.LittleEndian.PutUint32(buf[:4], shardIndex)
	binary.LittleEndian.PutUint32(buf[4:], totalShards)
	_, _ = mac.Write(buf[:])
	if hasKeys {
		_, _ = mac.Write([]byte{1})
		if keyData != nil {
			_, _ = mac.Write(keyData)
		}
	} else {
		_, _ = mac.Write([]byte{0})
	}
	_, _ = mac.Write(shardData)
	full := mac.Sum(nil)
	if tagSize <= 0 || tagSize >= len(full) {
		return full
	}
	return full[:tagSize]
}

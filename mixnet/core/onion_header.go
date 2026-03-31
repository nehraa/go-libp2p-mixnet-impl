package mixnet

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/mixnet/circuit"
)

// encryptOnionHeader builds a layered onion header that wraps only control data.
// The payload data is forwarded unchanged across hops.
func encryptOnionHeader(controlHeader []byte, c *circuit.Circuit, dest peer.ID, hopKeys [][]byte) ([]byte, error) {
	if c == nil || len(c.Peers) == 0 {
		return nil, fmt.Errorf("empty circuit")
	}
	if len(hopKeys) != len(c.Peers) {
		return nil, fmt.Errorf("hop key count mismatch")
	}

	current := controlHeader
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

func encryptOnionHeaderWithAEADs(controlHeader []byte, c *circuit.Circuit, dest peer.ID, hopAEADs []cipher.AEAD) ([]byte, error) {
	if c == nil || len(c.Peers) == 0 {
		return nil, fmt.Errorf("empty circuit")
	}
	if len(hopAEADs) != len(c.Peers) {
		return nil, fmt.Errorf("hop aead count mismatch")
	}

	current := controlHeader
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

func encryptOnionHeaderPrepared(controlHeader []byte, c *circuit.Circuit, dest peer.ID, hopKeys [][]byte, hopAEADs []cipher.AEAD) ([]byte, error) {
	if c != nil && len(hopAEADs) == len(c.Peers) {
		return encryptOnionHeaderWithAEADs(controlHeader, c, dest, hopAEADs)
	}
	return encryptOnionHeader(controlHeader, c, dest, hopKeys)
}

// buildHeaderOnlyPayload builds the header-only packet body.
// Format: [header_len(4)][encrypted_header][payload]
func buildHeaderOnlyPayload(encryptedHeader []byte, payload []byte) []byte {
	buf := make([]byte, 4+len(encryptedHeader)+len(payload))
	binary.LittleEndian.PutUint32(buf[:4], uint32(len(encryptedHeader)))
	copy(buf[4:], encryptedHeader)
	copy(buf[4+len(encryptedHeader):], payload)
	return buf
}

// buildHeaderOnlyFrameHeader builds the fixed prefix for a header-only wire
// frame.
//
// Format: [circuit_id_len][circuit_id][version][payload_len][header_len]
func buildHeaderOnlyFrameHeader(circuitID string, encryptedHeaderLen int, payloadLen int) ([]byte, error) {
	if len(circuitID) == 0 || len(circuitID) > 255 {
		return nil, fmt.Errorf("invalid circuit id")
	}
	framePayloadLen := 4 + encryptedHeaderLen + payloadLen
	buf := make([]byte, 1+len(circuitID)+1+4+4)
	pos := 0
	buf[pos] = byte(len(circuitID))
	pos++
	copy(buf[pos:], circuitID)
	pos += len(circuitID)
	buf[pos] = frameVersionHeaderOnly
	pos++
	binary.LittleEndian.PutUint32(buf[pos:], uint32(framePayloadLen))
	pos += 4
	binary.LittleEndian.PutUint32(buf[pos:], uint32(encryptedHeaderLen))
	return buf, nil
}

// encodeHeaderOnlyFrame builds the full header-only wire frame in a single
// allocation.
//
// The payload bytes are copied once at the sender into the outbound frame and
// then treated as stream-through data by intermediate relays. Header-only
// relays decrypt and replace only the onion header; they do not rebuild a new
// full [header][payload] buffer on every hop.
//
// Format: [circuit_id_len][circuit_id][version][payload_len][header_len][encrypted_header][payload]
func encodeHeaderOnlyFrame(circuitID string, encryptedHeader []byte, payload []byte) ([]byte, error) {
	prefix, err := buildHeaderOnlyFrameHeader(circuitID, len(encryptedHeader), len(payload))
	if err != nil {
		return nil, err
	}
	buf := make([]byte, len(prefix)+len(encryptedHeader)+len(payload))
	copy(buf, prefix)
	pos := len(prefix)
	copy(buf[pos:], encryptedHeader)
	pos += len(encryptedHeader)
	copy(buf[pos:], payload)
	return buf, nil
}

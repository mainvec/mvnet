package ice

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
)

// STUN message types.
const (
	stunBindingRequest  uint16 = 0x0001
	stunBindingResponse uint16 = 0x0101
)

// STUN attribute types used in ICE connectivity checks.
const (
	stunAttrUsername       uint16 = 0x0006
	stunAttrXorMappedAddr  uint16 = 0x0020
	stunAttrPriority       uint16 = 0x0024
	stunAttrUseCandidate   uint16 = 0x0025
	stunAttrIceControlled  uint16 = 0x8029
	stunAttrIceControlling uint16 = 0x802A
)

const stunMagicCookie uint32 = 0x2112A442

// stunMessage represents a STUN message with ICE attributes.
type stunMessage struct {
	msgType    uint16
	length     uint16
	cookie     uint32
	transID    [12]byte
	attributes []stunAttribute
}

// stunAttribute represents a single STUN attribute.
type stunAttribute struct {
	attrType uint16
	length   uint16
	value    []byte
}

func generateTransactionID() [12]byte {
	var id [12]byte
	rand.Read(id[:])
	return id
}

// generateCredential creates a random alphanumeric string of length n.
func generateCredential(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, n)
	randomBytes := make([]byte, n)
	if _, err := rand.Read(randomBytes); err != nil {
		for i := range result {
			result[i] = chars[i%len(chars)]
		}
		return string(result)
	}
	for i := range result {
		result[i] = chars[int(randomBytes[i])%len(chars)]
	}
	return string(result)
}

// createICEBindingRequest creates a STUN binding request with ICE attributes.
func (a *Agent) createICEBindingRequest(pair *CandidatePair, useCandidate bool) *stunMessage {
	msg := &stunMessage{
		msgType: stunBindingRequest,
		cookie:  stunMagicCookie,
		transID: generateTransactionID(),
	}

	// USERNAME: remoteUfrag:localUfrag
	username := a.remoteUfrag + ":" + a.localUfrag
	msg.attributes = append(msg.attributes, stunAttribute{
		attrType: stunAttrUsername,
		length:   uint16(len(username)),
		value:    []byte(username),
	})

	// PRIORITY
	priorityBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(priorityBytes, pair.Local.Priority)
	msg.attributes = append(msg.attributes, stunAttribute{
		attrType: stunAttrPriority,
		length:   4,
		value:    priorityBytes,
	})

	// ICE-CONTROLLING or ICE-CONTROLLED with tie-breaker
	tieBreakerBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tieBreakerBytes, a.tieBreaker)

	if a.role == RoleControlling {
		msg.attributes = append(msg.attributes, stunAttribute{
			attrType: stunAttrIceControlling,
			length:   8,
			value:    tieBreakerBytes,
		})
		if useCandidate {
			msg.attributes = append(msg.attributes, stunAttribute{
				attrType: stunAttrUseCandidate,
				length:   0,
				value:    []byte{},
			})
		}
	} else {
		msg.attributes = append(msg.attributes, stunAttribute{
			attrType: stunAttrIceControlled,
			length:   8,
			value:    tieBreakerBytes,
		})
	}

	return msg
}

// marshal serializes a STUN message to bytes.
func (msg *stunMessage) marshal() []byte {
	totalAttrLen := 0
	for _, attr := range msg.attributes {
		totalAttrLen += 4 + int(attr.length)
		if attr.length%4 != 0 {
			totalAttrLen += 4 - int(attr.length%4)
		}
	}
	msg.length = uint16(totalAttrLen)

	buf := make([]byte, 20+totalAttrLen)
	binary.BigEndian.PutUint16(buf[0:2], msg.msgType)
	binary.BigEndian.PutUint16(buf[2:4], msg.length)
	binary.BigEndian.PutUint32(buf[4:8], msg.cookie)
	copy(buf[8:20], msg.transID[:])

	offset := 20
	for _, attr := range msg.attributes {
		binary.BigEndian.PutUint16(buf[offset:offset+2], attr.attrType)
		binary.BigEndian.PutUint16(buf[offset+2:offset+4], attr.length)
		copy(buf[offset+4:offset+4+int(attr.length)], attr.value)
		offset += 4 + int(attr.length)
		if attr.length%4 != 0 {
			offset += 4 - int(attr.length%4)
		}
	}
	return buf
}

// parseSTUNMessage parses a STUN message from raw bytes.
func parseSTUNMessage(data []byte) (*stunMessage, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("STUN message too short: %d bytes", len(data))
	}

	msg := &stunMessage{
		msgType: binary.BigEndian.Uint16(data[0:2]),
		length:  binary.BigEndian.Uint16(data[2:4]),
		cookie:  binary.BigEndian.Uint32(data[4:8]),
	}
	copy(msg.transID[:], data[8:20])

	offset := 20
	for offset < len(data) {
		if offset+4 > len(data) {
			break
		}
		attr := stunAttribute{
			attrType: binary.BigEndian.Uint16(data[offset : offset+2]),
			length:   binary.BigEndian.Uint16(data[offset+2 : offset+4]),
		}
		if offset+4+int(attr.length) > len(data) {
			break
		}
		attr.value = make([]byte, attr.length)
		copy(attr.value, data[offset+4:offset+4+int(attr.length)])
		msg.attributes = append(msg.attributes, attr)
		offset += 4 + int(attr.length)
		if attr.length%4 != 0 {
			offset += 4 - int(attr.length%4)
		}
	}

	return msg, nil
}

// hasAttribute checks if a STUN message contains an attribute of the given type.
func (msg *stunMessage) hasAttribute(attrType uint16) bool {
	for _, attr := range msg.attributes {
		if attr.attrType == attrType {
			return true
		}
	}
	return false
}

// createXorMappedAddressAttribute creates an XOR-MAPPED-ADDRESS STUN attribute
// for a binding response.
func createXorMappedAddressAttribute(addr *net.UDPAddr, transID [12]byte) stunAttribute {
	value := make([]byte, 8)
	binary.BigEndian.PutUint16(value[0:2], 1) // IPv4 family
	binary.BigEndian.PutUint16(value[2:4], uint16(addr.Port)^0x2112)

	cookie := []byte{0x21, 0x12, 0xA4, 0x42}
	ip4 := addr.IP.To4()
	for i := 0; i < 4; i++ {
		value[4+i] = ip4[i] ^ cookie[i]
	}
	return stunAttribute{
		attrType: stunAttrXorMappedAddr,
		length:   8,
		value:    value,
	}
}

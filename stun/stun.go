package stun

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const (
	// STUN message types
	STUN_BINDING_REQUEST  = 0x0001
	STUN_BINDING_RESPONSE = 0x0101

	// STUN attribute types
	STUN_ATTR_MAPPED_ADDRESS     = 0x0001
	STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020

	// STUN message header size
	STUN_HEADER_SIZE = 20

	// STUN magic cookie
	STUN_MAGIC_COOKIE = 0x2112A442
)

var ZERO_STUNQueryResult = STUNQueryResult{
	IP:    nil,
	Port:  0,
	Valid: false,
}

var PUBLIC_STUN_SERVERS = []string{
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun2.l.google.com:19302",
	"stun.stunprotocol.org:3478",
	"stun.cloudflare.com:3478",
}

type STUNMessage struct {
	MessageType   uint16
	MessageLength uint16
	MagicCookie   uint32
	TransactionID [12]byte
	Attributes    []byte
}

type STUNQueryResult struct {
	IP    net.IP
	Port  int
	Valid bool
}

func generateTransactionID() [12]byte {
	var id [12]byte
	rand.Read(id[:])
	return id
}

func createBindingRequest() []byte {
	msg := STUNMessage{
		MessageType:   STUN_BINDING_REQUEST,
		MessageLength: 0, // No attributes for basic request
		MagicCookie:   STUN_MAGIC_COOKIE,
		TransactionID: generateTransactionID(),
	}

	// Create the packet
	packet := make([]byte, STUN_HEADER_SIZE)
	binary.BigEndian.PutUint16(packet[0:2], msg.MessageType)
	binary.BigEndian.PutUint16(packet[2:4], msg.MessageLength)
	binary.BigEndian.PutUint32(packet[4:8], msg.MagicCookie)
	copy(packet[8:20], msg.TransactionID[:])

	return packet
}

func parseSTUNResponse(response []byte) (STUNQueryResult, error) {
	if len(response) < STUN_HEADER_SIZE {
		return ZERO_STUNQueryResult, fmt.Errorf("response too short")
	}

	messageType := binary.BigEndian.Uint16(response[0:2])
	messageLength := binary.BigEndian.Uint16(response[2:4])
	magicCookie := binary.BigEndian.Uint32(response[4:8])

	if messageType != STUN_BINDING_RESPONSE {
		return ZERO_STUNQueryResult, fmt.Errorf("unexpected message type: %x", messageType)
	}

	if magicCookie != STUN_MAGIC_COOKIE {
		return ZERO_STUNQueryResult, fmt.Errorf("invalid magic cookie")
	}

	// Parse attributes
	attributeData := response[STUN_HEADER_SIZE:]
	if len(attributeData) != int(messageLength) {
		return ZERO_STUNQueryResult, fmt.Errorf("message length mismatch")
	}

	return parseAttributes(attributeData, response[8:20])
}

func parseAttributes(data []byte, transactionID []byte) (STUNQueryResult, error) {
	offset := 0

	for offset < len(data) {
		if offset+4 > len(data) {
			break
		}

		attrType := binary.BigEndian.Uint16(data[offset : offset+2])
		attrLength := binary.BigEndian.Uint16(data[offset+2 : offset+4])

		if offset+4+int(attrLength) > len(data) {
			break
		}

		attrValue := data[offset+4 : offset+4+int(attrLength)]

		switch attrType {
		case STUN_ATTR_MAPPED_ADDRESS:
			if len(attrValue) >= 8 {
				family := binary.BigEndian.Uint16(attrValue[0:2])
				port := binary.BigEndian.Uint16(attrValue[2:4])

				if family == 0x01 { // IPv4
					ip := net.IPv4(attrValue[4], attrValue[5], attrValue[6], attrValue[7])
					return STUNQueryResult{IP: ip, Port: int(port), Valid: true}, nil
				}
			}

		case STUN_ATTR_XOR_MAPPED_ADDRESS:
			if len(attrValue) >= 8 {
				family := binary.BigEndian.Uint16(attrValue[0:2])
				xorPort := binary.BigEndian.Uint16(attrValue[2:4])

				if family == 0x01 { // IPv4
					// XOR with magic cookie for port
					port := xorPort ^ uint16(STUN_MAGIC_COOKIE>>16)

					// XOR with magic cookie for IP (IPv4 only uses magic cookie)
					xorIP := binary.BigEndian.Uint32(attrValue[4:8])
					realIP := xorIP ^ STUN_MAGIC_COOKIE

					ip := net.IPv4(
						byte(realIP>>24),
						byte(realIP>>16),
						byte(realIP>>8),
						byte(realIP),
					)
					return STUNQueryResult{IP: ip, Port: int(port), Valid: true}, nil
				} else if family == 0x02 && len(attrValue) >= 20 { // IPv6
					// XOR with magic cookie for port
					port := xorPort ^ uint16(STUN_MAGIC_COOKIE>>16)

					// For IPv6, XOR with magic cookie + transaction ID
					xorKey := make([]byte, 16)
					binary.BigEndian.PutUint32(xorKey[0:4], STUN_MAGIC_COOKIE)
					copy(xorKey[4:16], transactionID)

					// XOR the IPv6 address
					ipBytes := make([]byte, 16)
					for i := 0; i < 16; i++ {
						ipBytes[i] = attrValue[4+i] ^ xorKey[i]
					}

					ip := net.IP(ipBytes)

					return STUNQueryResult{IP: ip, Port: int(port), Valid: true}, nil
				}
			}
		}

		// Move to next attribute (with padding to 4-byte boundary)
		offset += 4 + int(attrLength)
		if offset%4 != 0 {
			offset += 4 - (offset % 4)
		}
	}

	return ZERO_STUNQueryResult, fmt.Errorf("no mapped address found")
}

func QuerySTUNServer(serverAddr string) (STUNQueryResult, error) {
	// Create UDP connection

	localAddr := &net.UDPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: 0,
	}

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return ZERO_STUNQueryResult, fmt.Errorf("failed to create UDP connection: %w", err)
	}

	defer conn.Close()

	return QuerySTUNServerWithConn(conn, serverAddr)
}

func QuerySTUNServerWithConn(conn *net.UDPConn, serverAddr string) (STUNQueryResult, error) {

	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return ZERO_STUNQueryResult, fmt.Errorf("failed to resolve %s: %w", serverAddr, err)
	}

	// Set timeout (2s is plenty for a STUN server; avoids blocking the ICE
	// agent for too long when querying through unreachable interfaces).
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Create and send STUN binding request
	request := createBindingRequest()
	_, err = conn.WriteToUDP(request, addr)
	if err != nil {
		return ZERO_STUNQueryResult, fmt.Errorf("failed to send request: %v", err)
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return ZERO_STUNQueryResult, fmt.Errorf("failed to read response: %v", err)
	}

	// Parse response
	return parseSTUNResponse(response[:n])
}

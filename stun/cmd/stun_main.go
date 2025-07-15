package main

import (
	"fmt"
	"net"

	"github.com/mainvec/mvnet/stun"
)

func main() {
	// List of public STUN servers
	stunServers := []string{
		"stun.l.google.com:19302",
		"stun1.l.google.com:19302",
		"stun2.l.google.com:19302",
		"stun.stunprotocol.org:3478",
	}

	fmt.Println("Querying STUN servers to discover public IP and port...")

	for _, server := range stunServers {
		fmt.Printf("\nTrying %s...\n", server)

		result, err := stun.QuerySTUNServer(server)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}

		fmt.Printf("Success!\n")
		fmt.Printf("Public IP: %s\n", result.IP)
		fmt.Printf("Public Port: %d\n", result.Port)

		// Get local address for comparison
		conn, err := net.Dial("udp", server)
		if err == nil {
			localAddr := conn.LocalAddr().(*net.UDPAddr)
			fmt.Printf("Local IP: %s\n", localAddr.IP.String())
			fmt.Printf("Local Port: %d\n", localAddr.Port)
			conn.Close()
		}

		return
	}

	fmt.Println("Failed to get public IP from any STUN server")
}

package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/mainvec/mvnet/nat"
	"github.com/mainvec/mvnet/punch"
)

var remoteAddr string

func init() { // Initialize logging or any other setup if needed
	//get params
	if len(os.Args) == 2 {
		remoteAddr = os.Args[1]
	}
	// remoteAddr := os.Args[1]
	// if remoteAddr == "" {
	// 	fmt.Println("Remote address cannot be empty")
	// 	os.Exit(1)
	// }

}

func main() {

	//detect NAT type and initialize the HolePuncher
	localAddr := &net.UDPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: 0,
	}

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		panic(fmt.Errorf("failed to create UDP connection: %w", err))
	}
	detector, err := nat.NewNATDetectorWithConn(conn, nil)
	if err != nil {
		panic(fmt.Errorf("failed to create NAT detector: %w", err))
	}

	// Detect NAT type
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	natType, results, err := detector.DetectNATType(ctx)
	if err != nil {
		panic(fmt.Errorf("failed to detect NAT type: %w", err))
	}
	if natType == nat.NATTypeEasyNAT || natType == nat.NATTypeOpen {
		fmt.Printf("NAT type is %s, using HolePuncher\n", natType)
	} else {
		fmt.Printf("NAT type is %s, using HolePuncher with caution\n", natType)
	}

	//if nat type is direct or easy get the first successful result
	var stunResult *nat.STUNResult
	//if natType == nat.NATTypeOpen || natType == nat.NATTypeEasyNAT {
	for _, result := range results {
		if result.Success {
			stunResult = &result
			break
		}
	}

	if stunResult == nil {
		fmt.Println("No successful STUN result found, cannot proceed with HolePuncher")
		return
	}

	mappedAddress := stunResult.MappedAddr

	fmt.Printf("Local  Address: %s\n", conn.LocalAddr().String())
	fmt.Printf("Mapped Address: %s\n", mappedAddress)
	if remoteAddr == "" {
		//Read remote address from stdin
		fmt.Print("Enter remote address (IP:Port): ")
		fmt.Scanln(&remoteAddr)
		if remoteAddr == "" {
			fmt.Println("Remote address cannot be empty")
			return
		}
		if remoteAddr[0] == ':' {
			remoteAddr = "127.0.0.1" + remoteAddr
			fmt.Printf("Using remote address: %s\n", remoteAddr)
		}

		//parse remote address

	}
	config := punch.DefaultConfig()

	hp, err := punch.NewHolePuncherWithConn(conn, remoteAddr, config, false)
	if err != nil {
		log.Fatalf("Error creating HolePuncher: %v", err)
	}
	//defer hp.Close()

	log.Printf("Starting hole punching from %s to %s", localAddr, remoteAddr)

	// Start the hole punching process
	go func() {
		if err := hp.Start(); err != nil {
			log.Printf("Error during hole punching: %v", err)
		}
	}()

	// Monitor progress
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-hp.Done():
			state := hp.GetState()
			metrics := hp.GetMetrics()
			log.Printf("Hole punching completed with state: %s", state)
			log.Printf("Metrics: %+v", metrics)
			if hp.GetState() == punch.StateSuccessful {
				log.Printf("Hole punching was successful!")
				startChat(hp, remoteAddr)
			}
			return
		case <-ticker.C:
			state := hp.GetState()
			metrics := hp.GetMetrics()
			log.Printf("Current state: %s, Metrics: %+v", state, metrics)
		}
	}

}

func startChat(hp *punch.HolePuncher, remoteAddr string) {
	fmt.Println("HolePuncher is ready for chat")
	if hp.GetState() != punch.StateSuccessful {
		fmt.Println("HolePuncher is not in a successful state, cannot start chat")
		return
	}

	conn := hp.GetConnection()
	if conn == nil {
		fmt.Println("HolePuncher connection is nil")
		return
	}

	fmt.Printf("Connected to remote address: %s\n", remoteAddr)

	go func() {
		for {
			buf := make([]byte, 1024)

			conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // Set a read timeout
			n, addr, err := conn.ReadFromUDP(buf)

			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				fmt.Printf("Error reading from UDP: %v\n", err)
				return
			}
			fmt.Printf("Received message from %s: %s\n", addr, string(buf[:n]))
		}
	}()

	// Chat loop
	go func() {
		for {
			var msg string
			fmt.Print("ME: ")
			reader := bufio.NewReader(os.Stdin)
			msg, err := reader.ReadString('\n')
			if err != nil {
				fmt.Printf("Error reading input: %v\n", err)
				return
			}
			if msg == "" {
				fmt.Println("Message cannot be empty")
				continue
			}
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second)) // Set a write timeout

			_, err = conn.WriteToUDP([]byte(msg), hp.GetRemoteAddr())
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // Timeout, just skip
				}
				fmt.Printf("Error sending message: %v\n", err)
				return
			}
		}
	}()

	fmt.Println("Chat started. Type your messages below:")
	// Keep the main goroutine alive to allow chat to continue
	select {} // Block forever, or you can implement a graceful shutdown mechanism
}

// Example usage
// func main() {
// 	localAddr := ":12345"
// 	remoteAddr := "127.0.0.1:12346" // Replace with actual remote IP address
// 	config := DefaultConfig()

// 	hp, err := NewHolePuncher(localAddr, remoteAddr, config)
// 	if err != nil {
// 		log.Fatalf("Error creating HolePuncher: %v", err)
// 	}
// 	defer hp.Close()

// 	log.Printf("Starting hole punching from %s to %s", localAddr, remoteAddr)

// 	// Start the hole punching process
// 	go func() {
// 		if err := hp.Start(); err != nil {
// 			log.Printf("Error during hole punching: %v", err)
// 		}
// 	}()

// 	// Monitor progress
// 	ticker := time.NewTicker(5 * time.Second)
// 	defer ticker.Stop()

// 	for {
// 		select {
// 		case <-hp.done:
// 			state := hp.GetState()
// 			metrics := hp.GetMetrics()
// 			log.Printf("Hole punching completed with state: %s", state)
// 			log.Printf("Metrics: %+v", metrics)
// 			return
// 		case <-ticker.C:
// 			state := hp.GetState()
// 			metrics := hp.GetMetrics()
// 			log.Printf("Current state: %s, Metrics: %+v", state, metrics)
// 		}
// 	}
// }

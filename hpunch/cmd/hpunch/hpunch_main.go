package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/mainvec/mvnet/hpunch"
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

	hp, err := hpunch.NewHolePuncher(context.Background())
	if err != nil {
		panic(err)
	}

	if hp.State() != hpunch.HPPuncherReady {
		fmt.Println("HolePuncher is not ready")
		fmt.Printf("Current state: %d\n", hp.State())
		return
	} else {
		fmt.Println("HolePuncher is ready")
	}

	fmt.Printf("Created HolePuncher with NAT type: %s\n", hp.GetNATType())

	mappedAddress, err := hp.GetMappedAddress()
	if err != nil {
		fmt.Printf("Error getting local mapped address: %v\n", err)
		return
	}
	fmt.Printf("Local  Address: %s\n", hp.LocalAddr().String())
	fmt.Printf("Mapped Address: %s\n", mappedAddress)
	if hp.CanPunch() {
		fmt.Println("✅ HolePuncher can punch holes")
	} else {
		fmt.Printf("❌ HolePuncher likely not to success. NAT type: %s\n", hp.GetNATType())

	}
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
		remoteUDPAddress, err := net.ResolveUDPAddr("udp", remoteAddr)
		if err != nil {
			fmt.Printf("Error resolving remote address: %v\n", err)
			return
		}
		fmt.Printf("Resolved remote address: %s\n", remoteUDPAddress)
		err = hp.StartPunching(context.Background(), remoteUDPAddress)
		if err != nil {
			fmt.Printf("Error starting hole punching: %v\n", err)
			return
		}
		if hp.State() != hpunch.HPPuncherSuccess {
			fmt.Printf("Hole punching failed with state: %d\n", hp.State())
			return
		}
		fmt.Println("Hole punching succeeded")

		conn := hp.GetConn()

		if conn == nil {
			fmt.Println("HolePuncher connection is nil")
			return
		}

		go func() {
			for {
				buf := make([]byte, 1024)
				conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // Set a read timeout
				n, raddr, err := conn.ReadFromUDP(buf)
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue // Timeout, just skip
					}
					fmt.Printf("Error reading from UDP: %v\n", err)
					return
				}
				fmt.Printf("From %s: %s\n", raddr.String(), string(buf[:n]))
			}
		}()

		go func() {
			for {
				var msg string
				fmt.Print("ME: ")
				reader := bufio.NewReader(os.Stdin)
				msg, err := reader.ReadString('\n')
				if err != nil {
					fmt.Printf("Error reading input: %v\n", err)
					continue
				}
				if msg == "" {
					fmt.Println("Message cannot be empty")
					continue
				}
				conn.SetWriteDeadline(time.Now().Add(5 * time.Second)) // Set a write timeout

				_, err = conn.WriteToUDP([]byte(msg), remoteUDPAddress)
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue // Timeout, just skip
					}
					fmt.Printf("Error sending message: %v\n", err)
					return
				}
				fmt.Printf("Sent message to %s: %s\n", remoteUDPAddress.String(), msg)
			}
		}()

		//wait for a system signal to exit
		fmt.Println("Press Ctrl+C to exit")
		select {} // Block forever

	}

}

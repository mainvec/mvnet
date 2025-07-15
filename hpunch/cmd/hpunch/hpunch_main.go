package main

import (
	"context"
	"fmt"
	"net"
	"os"

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

	}

}

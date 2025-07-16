package main

import (
	"fmt"

	"github.com/mainvec/mvnet/upnp"
)

func main() {
	// Run network diagnostics first
	//upnp.DiagnoseNetworkSetup()
	fmt.Println()

	// Example usage
	client, err := upnp.NewUPnPClient()
	if err != nil {
		fmt.Printf("Error creating UPnP client: %v\n", err)
		return
	}

	fmt.Printf("Gateway: %s\n", client.Gateway)
	fmt.Printf("Local IP: %s\n", client.LocalIP)
	fmt.Printf("Control URL: %s\n", client.ControlURL)
	fmt.Printf("NAT-PMP Support: %v\n", client.SupportsNATPMP)
	fmt.Printf("Gateway IP: %s\n", client.GatewayIP)

	// Request port mapping
	externalPort := 51000
	internalPort := 51000
	protocol := "UDP"
	description := "My Application"

	fmt.Printf("\nRequesting port mapping: external %d -> internal %d (%s)\n",
		externalPort, internalPort, protocol)

	err = client.AddPortMapping(externalPort, internalPort, protocol, description)
	if err != nil {
		fmt.Printf("Failed to add port mapping: %v\n", err)
		return
	}

	fmt.Printf("Port mapping added successfully!\n")
	fmt.Printf("External port %d is now forwarded to %s:%d\n",
		externalPort, client.LocalIP, internalPort)

	// Show which protocol was used
	if client.ControlURL != "" {
		fmt.Println("Used protocol: UPnP")
	} else if client.SupportsNATPMP {
		fmt.Println("Used protocol: NAT-PMP")
	}

	// Optional: Remove the mapping after some time
	fmt.Println("\nPress Enter to remove the port mapping...")
	fmt.Scanln()

	err = client.RemovePortMapping(externalPort, protocol)
	if err != nil {
		fmt.Printf("Failed to remove port mapping: %v\n", err)
		return
	}

	fmt.Println("Port mapping removed successfully!")
}

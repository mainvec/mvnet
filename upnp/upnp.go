package upnp

import (
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// UPnPClient represents a UPnP client
type UPnPClient struct {
	Gateway        string
	LocalIP        string
	ControlURL     string
	SupportsNATPMP bool
	GatewayIP      string
}

// NAT-PMP constants
const (
	NATPMP_PORT        = 5351
	NATPMP_VERSION     = 0
	NATPMP_OP_MAP_UDP  = 1
	NATPMP_OP_MAP_TCP  = 2
	NATPMP_OP_GET_INFO = 0
)

// NAT-PMP response structure
type NATPMPResponse struct {
	Version      uint8
	Opcode       uint8
	ResultCode   uint16
	Epoch        uint32
	InternalPort uint16
	ExternalPort uint16
	Lifetime     uint32
}

// SOAP envelope for UPnP requests
type soapEnvelope struct {
	XMLName xml.Name `xml:"soap:Envelope"`
	Soap    string   `xml:"xmlns:soap,attr"`
	Body    soapBody `xml:"soap:Body"`
}

type soapBody struct {
	AddPortMapping addPortMapping `xml:"u:AddPortMapping"`
}

type addPortMapping struct {
	XMLName                   xml.Name `xml:"u:AddPortMapping"`
	Xmlns                     string   `xml:"xmlns:u,attr"`
	NewRemoteHost             string   `xml:"NewRemoteHost"`
	NewExternalPort           int      `xml:"NewExternalPort"`
	NewProtocol               string   `xml:"NewProtocol"`
	NewInternalPort           int      `xml:"NewInternalPort"`
	NewInternalClient         string   `xml:"NewInternalClient"`
	NewEnabled                int      `xml:"NewEnabled"`
	NewPortMappingDescription string   `xml:"NewPortMappingDescription"`
	NewLeaseDuration          int      `xml:"NewLeaseDuration"`
}

// checkNATPMPSupport tests if the gateway supports NAT-PMP
func checkNATPMPSupport(gatewayIP string) bool {
	fmt.Printf("Testing NAT-PMP support on %s...\n", gatewayIP)

	// Create UDP connection to gateway on NAT-PMP port
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.ParseIP(gatewayIP),
		Port: NATPMP_PORT,
	})
	if err != nil {
		fmt.Printf("❌ Cannot connect to NAT-PMP port: %v\n", err)
		return false
	}
	defer conn.Close()

	// Send NAT-PMP info request (2 bytes)
	request := make([]byte, 2)
	request[0] = NATPMP_VERSION     // Version = 0
	request[1] = NATPMP_OP_GET_INFO // Opcode = 0 (get info)

	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write(request)
	if err != nil {
		fmt.Printf("❌ Failed to send NAT-PMP request: %v\n", err)
		return false
	}

	// Read response
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	response := make([]byte, 12)
	n, err := conn.Read(response)
	if err != nil {
		fmt.Printf("❌ No NAT-PMP response: %v\n", err)
		return false
	}

	if n >= 8 && response[0] == NATPMP_VERSION && response[1] == (NATPMP_OP_GET_INFO+128) {
		// NAT-PMP responses have opcode = request_opcode + 128
		resultCode := binary.BigEndian.Uint16(response[2:4])
		if resultCode == 0 {
			fmt.Println("✅ NAT-PMP is supported!")
			return true
		} else {
			fmt.Printf("❌ NAT-PMP error code: %d\n", resultCode)
			return false
		}
	}

	fmt.Println("❌ Invalid NAT-PMP response")
	return false
}

// discoverGateway discovers the UPnP gateway using SSDP with multiple attempts
func discoverGateway() (string, error) {
	fmt.Println("Discovering UPnP gateway...")

	// Try multiple search targets
	searchTargets := []string{
		"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
		"urn:schemas-upnp-org:device:InternetGatewayDevice:2",
		"urn:schemas-upnp-org:service:WANIPConnection:1",
		"upnp:rootdevice",
	}

	for _, st := range searchTargets {
		fmt.Printf("Trying search target: %s\n", st)
		location, err := ssdpSearch(st)
		if err == nil {
			fmt.Printf("Found gateway at: %s\n", location)
			return location, nil
		}
		fmt.Printf("Search failed: %v\n", err)
	}

	return "", fmt.Errorf("no UPnP gateway found after trying multiple search targets")
}

func ssdpSearch(searchTarget string) (string, error) {
	// Create a UDP connection for multicast
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: 0,
	})
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Destination multicast address
	dst := &net.UDPAddr{
		IP:   net.ParseIP("239.255.255.250"),
		Port: 1900,
	}

	// SSDP search request - exactly like miniupnpc format
	searchMsg := fmt.Sprintf("M-SEARCH * HTTP/1.1\r\n"+
		"HOST: 239.255.255.250:1900\r\n"+
		"ST: %s\r\n"+
		"MAN: \"ssdp:discover\"\r\n"+
		"MX: 3\r\n\r\n", searchTarget)

	//fmt.Printf("Sending SSDP request to %s:\n%s", dst, searchMsg)

	// Send the request
	_, err = conn.WriteToUDP([]byte(searchMsg), dst)
	if err != nil {
		return "", err
	}

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read responses
	buffer := make([]byte, 2048)
	for attempts := 0; attempts < 10; attempts++ {
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				fmt.Printf("Timeout after %d attempts\n", attempts+1)
				break
			}
			return "", err
		}

		response := string(buffer[:n])
		//fmt.Printf("Received response from %s (%d bytes):\n%s\n", addr, n, response)

		// Parse response for Location header
		lines := strings.Split(response, "\r\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToUpper(line), "LOCATION:") {
				location := strings.TrimSpace(line[9:])
				if strings.HasPrefix(location, "http://") {
					fmt.Printf("✅ Found location: %s\n", location)
					return location, nil
				}
			}
		}
	}

	return "", fmt.Errorf("no valid location found in SSDP responses")
}

// getControlURL extracts the control URL from the device description
func getControlURL(location string) (string, error) {
	resp, err := http.Get(location)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	content := string(body)
	fmt.Printf("Device description XML:\n%s\n", content)

	// Look specifically for WANIPConnection service and its controlURL
	wanIPConnIndex := strings.Index(content, "urn:schemas-upnp-org:service:WANIPConnection:1")
	if wanIPConnIndex == -1 {
		return "", fmt.Errorf("WANIPConnection service not found")
	}

	// Find the controlURL after the WANIPConnection service type
	remaining := content[wanIPConnIndex:]
	controlStart := strings.Index(remaining, "<controlURL>")
	if controlStart == -1 {
		return "", fmt.Errorf("controlURL not found for WANIPConnection service")
	}

	controlStart += 12 // length of "<controlURL>"
	controlEnd := strings.Index(remaining[controlStart:], "</controlURL>")
	if controlEnd == -1 {
		return "", fmt.Errorf("controlURL end tag not found")
	}

	controlURL := remaining[controlStart : controlStart+controlEnd]
	fmt.Printf("✅ Found WANIPConnection controlURL: %s\n", controlURL)

	// Make it absolute URL
	if strings.HasPrefix(controlURL, "/") {
		parts := strings.Split(location, "/")
		if len(parts) >= 3 {
			baseURL := strings.Join(parts[:3], "/")
			fullURL := baseURL + controlURL
			fmt.Printf("Full control URL: %s\n", fullURL)
			return fullURL, nil
		}
	}

	return controlURL, nil
}

// getLocalIP gets the local IP address
func getLocalIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

// getDefaultGateway gets the default gateway IP
func getDefaultGateway() (string, error) {
	// This is a simple approach - connect to external IP and see what interface we use
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	localIP := localAddr.IP.String()

	// For most home networks, gateway is typically .1 of the same subnet
	parts := strings.Split(localIP, ".")
	if len(parts) == 4 {
		// Try common gateway patterns
		gatewayPatterns := []string{
			parts[0] + "." + parts[1] + "." + parts[2] + ".1",
			parts[0] + "." + parts[1] + "." + parts[2] + ".254",
		}

		for _, gateway := range gatewayPatterns {
			// Test if this IP responds
			timeout := 1 * time.Second
			testConn, err := net.DialTimeout("tcp", gateway+":80", timeout)
			if err == nil {
				testConn.Close()
				return gateway, nil
			}
		}

		// Default to .1 pattern if no response
		return parts[0] + "." + parts[1] + "." + parts[2] + ".1", nil
	}

	return "", fmt.Errorf("could not determine gateway IP")
}

// tryDirectGatewayConnection attempts to connect directly to known router
func tryDirectGatewayConnection(gw string) (string, error) {
	// Based on upnpc output, we know the router is at this location
	// knownLocation := "http://192.168.0.1:1900/uixaz/rootDesc.xml"

	// fmt.Printf("Trying known location from upnpc: %s\n", knownLocation)

	client := &http.Client{Timeout: 5 * time.Second}
	// resp, err := client.Get(knownLocation)
	// if err == nil {
	// 	defer resp.Body.Close()
	// 	if resp.StatusCode == 200 {
	// 		fmt.Printf("✅ Successfully connected to known UPnP device\n")
	// 		return knownLocation, nil
	// 	}
	// }

	// Fallback to common gateway discovery
	commonGateways := []string{
		// "192.168.1.1",
		// "192.168.0.1",
		// "192.168.1.254",
		// "10.0.0.1",
		// "172.16.0.1",
		gw,
	}

	for _, gateway := range commonGateways {
		fmt.Printf("Trying direct connection to %s\n", gateway)

		// Try common UPnP ports and paths
		testURLs := []string{
			fmt.Sprintf("http://%s:1900/uixaz/rootDesc.xml", gateway), // Your router's pattern
			fmt.Sprintf("http://%s:49152/rootDesc.xml", gateway),
			fmt.Sprintf("http://%s:5000/rootDesc.xml", gateway),
			fmt.Sprintf("http://%s:49153/rootDesc.xml", gateway),
		}

		for _, testURL := range testURLs {
			resp, err := client.Get(testURL)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == 200 {
					fmt.Printf("Found UPnP device at %s\n", testURL)
					return testURL, nil
				}
			}
		}
	}

	return "", fmt.Errorf("no UPnP gateway found via direct connection")
}

// NewUPnPClient creates a new UPnP client
func NewUPnPClient() (*UPnPClient, error) {
	var gateway string
	var err error

	localIP, err := getLocalIP()
	if err != nil {
		return nil, fmt.Errorf("failed to get local IP: %v", err)
	}

	gatewayIP, err := getDefaultGateway()
	if err != nil {
		return nil, fmt.Errorf("failed to get gateway IP: %v", err)
	}

	fmt.Printf("Local IP: %s, Gateway IP: %s\n", localIP, gatewayIP)

	// Test NAT-PMP support first (it's faster)
	supportsNATPMP := checkNATPMPSupport(gatewayIP)

	// Try UPnP discovery
	gateway, err = discoverGateway()
	if err != nil {
		fmt.Printf("SSDP discovery failed: %v\n", err)
		fmt.Println("Trying direct gateway connection...")

		// Fallback to direct connection
		gateway, err = tryDirectGatewayConnection(gatewayIP)
		if err != nil {
			if supportsNATPMP {
				fmt.Println("UPnP failed, but NAT-PMP is available")
				return &UPnPClient{
					Gateway:        "NAT-PMP",
					LocalIP:        localIP,
					ControlURL:     "",
					SupportsNATPMP: true,
					GatewayIP:      gatewayIP,
				}, nil
			}
			return nil, fmt.Errorf("both SSDP discovery and direct connection failed: %v", err)
		}
	}

	var controlURL string
	if gateway != "" {
		controlURL, err = getControlURL(gateway)
		if err != nil {
			fmt.Printf("Failed to get UPnP control URL: %v\n", err)
			if supportsNATPMP {
				fmt.Println("UPnP control URL failed, but NAT-PMP is available")
				return &UPnPClient{
					Gateway:        gateway,
					LocalIP:        localIP,
					ControlURL:     "",
					SupportsNATPMP: true,
					GatewayIP:      gatewayIP,
				}, nil
			}
			return nil, fmt.Errorf("failed to get control URL: %v", err)
		}
	}

	return &UPnPClient{
		Gateway:        gateway,
		LocalIP:        localIP,
		ControlURL:     controlURL,
		SupportsNATPMP: supportsNATPMP,
		GatewayIP:      gatewayIP,
	}, nil
}

// addPortMappingNATPMP adds a port mapping using NAT-PMP
func (c *UPnPClient) addPortMappingNATPMP(externalPort, internalPort int, protocol, description string) error {
	if !c.SupportsNATPMP {
		return fmt.Errorf("NAT-PMP not supported by this gateway")
	}

	fmt.Printf("Adding port mapping via NAT-PMP: %d -> %d (%s)\n", externalPort, internalPort, protocol)

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.ParseIP(c.GatewayIP),
		Port: NATPMP_PORT,
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	// Create NAT-PMP port mapping request (12 bytes)
	request := make([]byte, 12)
	request[0] = NATPMP_VERSION
	if protocol == "TCP" {
		request[1] = NATPMP_OP_MAP_TCP
	} else {
		request[1] = NATPMP_OP_MAP_UDP
	}
	// bytes 2-3 are reserved (0)
	binary.BigEndian.PutUint16(request[4:6], uint16(internalPort))
	binary.BigEndian.PutUint16(request[6:8], uint16(externalPort))
	binary.BigEndian.PutUint32(request[8:12], 3600) // 1 hour lifetime

	fmt.Printf("Sending NAT-PMP request: %v\n", request)

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(request)
	if err != nil {
		return err
	}

	// Read response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	response := make([]byte, 16)
	n, err := conn.Read(response)
	if err != nil {
		return err
	}

	if n >= 16 {
		var resp NATPMPResponse
		resp.Version = response[0]
		resp.Opcode = response[1]
		resp.ResultCode = binary.BigEndian.Uint16(response[2:4])
		resp.Epoch = binary.BigEndian.Uint32(response[4:8])
		resp.InternalPort = binary.BigEndian.Uint16(response[8:10])
		resp.ExternalPort = binary.BigEndian.Uint16(response[10:12])
		resp.Lifetime = binary.BigEndian.Uint32(response[12:16])

		fmt.Printf("NAT-PMP Response: Version=%d, Opcode=%d, Result=%d\n",
			resp.Version, resp.Opcode, resp.ResultCode)
		fmt.Printf("Port mapping: Internal=%d, External=%d, Lifetime=%d\n",
			resp.InternalPort, resp.ExternalPort, resp.Lifetime)

		if resp.ResultCode == 0 {
			return nil
		} else {
			return fmt.Errorf("NAT-PMP error code: %d", resp.ResultCode)
		}
	}

	return fmt.Errorf("invalid NAT-PMP response length: %d", n)
}

// removePortMappingNATPMP removes a port mapping using NAT-PMP
func (c *UPnPClient) removePortMappingNATPMP(externalPort int, protocol string) error {
	if !c.SupportsNATPMP {
		return fmt.Errorf("NAT-PMP not supported by this gateway")
	}

	fmt.Printf("Removing port mapping via NAT-PMP: %d (%s)\n", externalPort, protocol)

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.ParseIP(c.GatewayIP),
		Port: NATPMP_PORT,
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	// Create NAT-PMP port mapping removal request (lifetime = 0)
	request := make([]byte, 12)
	request[0] = NATPMP_VERSION
	if protocol == "TCP" {
		request[1] = NATPMP_OP_MAP_TCP
	} else {
		request[1] = NATPMP_OP_MAP_UDP
	}
	// Internal port = 0, External port = port to remove, Lifetime = 0
	binary.BigEndian.PutUint16(request[4:6], 0)
	binary.BigEndian.PutUint16(request[6:8], uint16(externalPort))
	binary.BigEndian.PutUint32(request[8:12], 0) // Lifetime = 0 means remove

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(request)
	if err != nil {
		return err
	}

	// Read response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	response := make([]byte, 16)
	n, err := conn.Read(response)
	if err != nil {
		return err
	}

	if n >= 16 {
		resultCode := binary.BigEndian.Uint16(response[2:4])
		if resultCode == 0 {
			fmt.Println("✅ NAT-PMP port mapping removed successfully")
			return nil
		} else {
			return fmt.Errorf("NAT-PMP error code: %d", resultCode)
		}
	}

	return fmt.Errorf("invalid NAT-PMP response length: %d", n)
}

// addPortMappingUPnP adds a port mapping using UPnP
func (c *UPnPClient) addPortMappingUPnP(externalPort, internalPort int, protocol, description string) error {
	// Use raw XML format that works better with TP-Link routers
	xmlData := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>%d</NewExternalPort>
<NewProtocol>%s</NewProtocol>
<NewInternalPort>%d</NewInternalPort>
<NewInternalClient>%s</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>%s</NewPortMappingDescription>
<NewLeaseDuration>0</NewLeaseDuration>
</u:AddPortMapping>
</s:Body>
</s:Envelope>`, externalPort, protocol, internalPort, c.LocalIP, description)

	//fmt.Printf("Sending UPnP SOAP request:\n%s\n", xmlData)

	// Create HTTP request
	req, err := http.NewRequest("POST", c.ControlURL, strings.NewReader(xmlData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", "\"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(xmlData)))

	// Send request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Read response for debugging
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("UPnP Response Status: %s\n", resp.Status)
	//fmt.Printf("UPnP Response Body: %s\n", string(body))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("UPnP request failed: %s - %s", resp.Status, string(body))
	}

	return nil
}

// removePortMappingUPnP removes a port mapping using UPnP
func (c *UPnPClient) removePortMappingUPnP(externalPort int, protocol string) error {
	// Similar to AddPortMapping but with DeletePortMapping action
	xmlData := fmt.Sprintf(`<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<soap:Body>
<u:DeletePortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>%d</NewExternalPort>
<NewProtocol>%s</NewProtocol>
</u:DeletePortMapping>
</soap:Body>
</soap:Envelope>`, externalPort, protocol)

	req, err := http.NewRequest("POST", c.ControlURL, strings.NewReader(xmlData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", "\"urn:schemas-upnp-org:service:WANIPConnection:1#DeletePortMapping\"")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("UPnP request failed: %s - %s", resp.Status, string(body))
	}

	return nil
}

// AddPortMapping adds a port mapping (tries UPnP first, then NAT-PMP)
func (c *UPnPClient) AddPortMapping(externalPort, internalPort int, protocol, description string) error {

	// Try NAT-PMP if supported
	if c.SupportsNATPMP {
		fmt.Println("Trying NAT-PMP port mapping...")
		err := c.addPortMappingNATPMP(externalPort, internalPort, protocol, description)
		if err == nil {
			fmt.Println("✅ NAT-PMP port mapping successful!")
			return nil
		}
		fmt.Printf("❌ NAT-PMP failed: %v\n", err)
	}

	// Try UPnP first if we have a control URL
	if c.ControlURL != "" {
		fmt.Println("Trying UPnP port mapping...")
		err := c.addPortMappingUPnP(externalPort, internalPort, protocol, description)
		if err == nil {
			fmt.Println("✅ UPnP port mapping successful!")
			return nil
		}
		fmt.Printf("❌ UPnP failed: %v\n", err)
	}

	return fmt.Errorf("both UPnP and NAT-PMP port mapping failed")
}

// RemovePortMapping removes a port mapping (tries UPnP first, then NAT-PMP)
func (c *UPnPClient) RemovePortMapping(externalPort int, protocol string) error {
	// Try UPnP first if available
	if c.ControlURL != "" {
		fmt.Println("Trying UPnP port removal...")
		err := c.removePortMappingUPnP(externalPort, protocol)
		if err == nil {
			fmt.Println("✅ UPnP port removal successful!")
			return nil
		}
		fmt.Printf("❌ UPnP removal failed: %v\n", err)
	}

	// Try NAT-PMP if supported
	if c.SupportsNATPMP {
		fmt.Println("Trying NAT-PMP port removal...")
		err := c.removePortMappingNATPMP(externalPort, protocol)
		if err == nil {
			fmt.Println("✅ NAT-PMP port removal successful!")
			return nil
		}
		fmt.Printf("❌ NAT-PMP removal failed: %v\n", err)
	}

	return fmt.Errorf("both UPnP and NAT-PMP port removal failed")
}

// diagnoseNetworkSetup helps diagnose network issues
func DiagnoseNetworkSetup() {
	fmt.Println("=== Network Diagnostics ===")

	// Check local IP
	localIP, err := getLocalIP()
	if err != nil {
		fmt.Printf("❌ Failed to get local IP: %v\n", err)
	} else {
		fmt.Printf("✅ Local IP: %s\n", localIP)
	}

	// Check default gateway
	fmt.Println("📡 Checking common gateway addresses...")
	gateways := []string{"192.168.1.1", "192.168.0.1", "10.0.0.1"}

	for _, gw := range gateways {
		timeout := 2 * time.Second
		conn, err := net.DialTimeout("tcp", gw+":80", timeout)
		if err == nil {
			conn.Close()
			fmt.Printf("✅ Gateway %s is reachable on HTTP\n", gw)
		} else {
			fmt.Printf("❌ Gateway %s HTTP not reachable: %v\n", gw, err)
		}

		// Also test NAT-PMP port specifically
		conn2, err := net.DialTimeout("udp", gw+":5351", timeout)
		if err == nil {
			conn2.Close()
			fmt.Printf("📡 Gateway %s NAT-PMP port 5351 is open\n", gw)
		} else {
			fmt.Printf("❌ Gateway %s NAT-PMP port 5351: %v\n", gw, err)
		}
	}

	// Test multicast capability
	fmt.Println("🔍 Testing multicast capability...")
	addr, err := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
	if err != nil {
		fmt.Printf("❌ Cannot resolve multicast address: %v\n", err)
		return
	}

	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		fmt.Printf("❌ Cannot create multicast connection: %v\n", err)
		return
	}
	conn.Close()
	fmt.Println("✅ Multicast connection possible")

	fmt.Println("\n💡 Troubleshooting Tips:")
	fmt.Println("   • Some routers support NAT-PMP but block external requests")
	fmt.Println("   • Check router settings for 'NAT-PMP' or 'Bonjour Gateway'")
	fmt.Println("   • UPnP and NAT-PMP might be on different gateway IPs")

	fmt.Println("\n💡 If UPnP discovery fails:")
	fmt.Println("   1. Enable UPnP/IGD in your router settings")
	fmt.Println("   2. Check if firewall blocks multicast traffic")
	fmt.Println("   3. Try running as administrator/root")
	fmt.Println("   4. Some routers call it 'Universal Plug and Play' or 'IGD'")
}

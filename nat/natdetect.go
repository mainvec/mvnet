package nat

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mainvec/mvnet/stun"
)

// NATType represents the different types of NAT behavior
type NATType int

const (
	NATTypeUnknown      NATType = iota
	NATTypeOpen                 // No NAT (direct internet connection)
	NATTypeEasyNAT              // Endpoint-Independent Mapping (EIM)
	NATTypeHardNAT              // Endpoint-Dependent Mapping (EDM)
	NATTypeSymmetricNAT         // Symmetric NAT (worst case)
	NATTypeBlocked              // UDP blocked or very restrictive firewall
)

var (
	DEFAULT_STUN_SERVERS = []string{
		"stun.l.google.com:19302",
		"stun1.l.google.com:19302",
		"stun2.l.google.com:19302",
		"stun.cloudflare.com:3478",
		"stun.ekiga.net:3478",
	}
)

func (n NATType) String() string {
	switch n {
	case NATTypeOpen:
		return "Open (No NAT)"
	case NATTypeEasyNAT:
		return "Easy NAT (Endpoint-Independent)"
	case NATTypeHardNAT:
		return "Hard NAT (Endpoint-Dependent)"
	case NATTypeSymmetricNAT:
		return "Symmetric NAT"
	case NATTypeBlocked:
		return "Blocked/Firewall"
	default:
		return "Unknown"
	}
}

// STUNResult contains the result of a STUN query
type STUNResult struct {
	Server       string
	LocalAddr    *net.UDPAddr
	MappedAddr   *net.UDPAddr
	Success      bool
	Error        error
	ResponseTime time.Duration
}

// NATDetector detects NAT type using multiple STUN servers
type NATDetector struct {
	udpConn     *net.UDPConn
	stunServers []string
	timeout     time.Duration
	singleUse   bool // Whether to use single-use UDP sockets
}

// NewNATDetector creates a new NAT detector
func NewNATDetector(localAddr *net.UDPAddr, stunServers []string) (*NATDetector, error) {
	if localAddr == nil {
		localAddr = &net.UDPAddr{
			IP:   net.ParseIP("0.0.0.0"),
			Port: 0,
		}
	}

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP connection: %w", err)
	}

	natDetector, err := NewNATDetectorWithConn(conn, stunServers)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create NAT detector: %w", err)
	}
	natDetector.singleUse = true // Use single-use sockets for this detector
	return natDetector, nil
}

// NewNATDetectorWithConn creates a new NAT detector using existing UDP Conn
func NewNATDetectorWithConn(conn *net.UDPConn, stunServers []string) (*NATDetector, error) {
	if conn == nil {
		return nil, errors.New("invalid udp conn")
	}

	if len(stunServers) == 0 {
		stunServers = DEFAULT_STUN_SERVERS
	}

	return &NATDetector{
		udpConn:     conn,
		stunServers: stunServers,
		timeout:     5 * time.Second,
	}, nil
}

// DetectNATType performs comprehensive NAT type detection
func (n *NATDetector) DetectNATType(ctx context.Context) (NATType, []STUNResult, error) {
	slog.Debug("Starting NAT type detection")
	slog.Debug("Local socket", "addr", n.udpConn.LocalAddr())

	// Phase 1: Query multiple STUN servers simultaneously
	results := n.queryMultipleSTUNServers(ctx)

	// Phase 2: Analyze results to determine NAT type
	natType := n.analyzeSTUNResults(results)

	// Phase 3: Additional tests for edge cases
	if natType == NATTypeUnknown && len(results) > 0 {
		natType = n.performAdditionalTests(ctx, results)
	}

	return natType, results, nil
}

// queryMultipleSTUNServers queries multiple STUN servers in parallel
func (n *NATDetector) queryMultipleSTUNServers(ctx context.Context) []STUNResult {
	var wg sync.WaitGroup
	results := make([]STUNResult, len(n.stunServers))

	for i, server := range n.stunServers {
		wg.Add(1)
		go func(index int, serverAddr string) {
			defer wg.Done()

			start := time.Now()
			result := STUNResult{
				Server:    serverAddr,
				LocalAddr: n.udpConn.LocalAddr().(*net.UDPAddr),
			}

			mappedAddr, err := n.querySTUNServer(ctx, serverAddr)
			result.ResponseTime = time.Since(start)

			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.MappedAddr = mappedAddr
				result.Success = true
			}

			results[index] = result
		}(i, server)
	}

	wg.Wait()
	return results
}

// querySTUNServer queries a single STUN server
func (n *NATDetector) querySTUNServer(ctx context.Context, serverAddr string) (*net.UDPAddr, error) {
	// Resolve server address

	stunResult, err := stun.QuerySTUNServerWithConn(n.udpConn, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to query STUN server %s: %w", serverAddr, err)
	}
	if !stunResult.Valid {
		return nil, fmt.Errorf("STUN server %s returned invalid response", serverAddr)
	}
	return &net.UDPAddr{
		IP:   stunResult.IP,
		Port: stunResult.Port,
	}, nil
}

// analyzeSTUNResults analyzes STUN results to determine NAT type
func (n *NATDetector) analyzeSTUNResults(results []STUNResult) NATType {
	// Filter successful results
	var successfulResults []STUNResult
	for _, result := range results {
		if result.Success {
			successfulResults = append(successfulResults, result)
		}
	}

	if len(successfulResults) == 0 {
		return NATTypeBlocked
	}

	// Check if we have a direct connection (no NAT)
	localAddr := n.udpConn.LocalAddr().(*net.UDPAddr)
	firstResult := successfulResults[0]

	if firstResult.MappedAddr.IP.Equal(localAddr.IP) &&
		firstResult.MappedAddr.Port == localAddr.Port {
		return NATTypeOpen
	}

	// Analyze port consistency across different STUN servers
	return n.analyzePortConsistency(successfulResults)
}

// analyzePortConsistency determines NAT type based on port mapping consistency
func (n *NATDetector) analyzePortConsistency(results []STUNResult) NATType {
	if len(results) < 2 {
		return NATTypeUnknown
	}

	// Group results by public IP
	ipGroups := make(map[string][]STUNResult)
	for _, result := range results {
		ip := result.MappedAddr.IP.String()
		ipGroups[ip] = append(ipGroups[ip], result)
	}

	// Check port consistency within each IP group
	allConsistent := true
	someConsistent := false
	hasMultipleIPs := len(ipGroups) > 1
	differentIPsDifferentPorts := false

	for ip, groupResults := range ipGroups {
		if len(groupResults) < 2 {
			continue
		}

		// Check if all ports in this group are the same
		firstPort := groupResults[0].MappedAddr.Port
		groupConsistent := true

		for _, result := range groupResults[1:] {
			if result.MappedAddr.Port != firstPort {
				groupConsistent = false
				break
			}
		}

		if groupConsistent {
			someConsistent = true
			slog.Debug("Consistent ports for IP", "ip", ip, "port", firstPort)
			//fmt.Printf("✅ Consistent ports for IP %s: %d\n", ip, firstPort)
		} else {
			allConsistent = false
			slog.Debug("Inconsistent ports for IP", "ip", ip)
			//fmt.Printf("❌ Inconsistent ports for IP %s: ", ip)
			// for _, result := range groupResults {
			// 	fmt.Printf("%d ", result.MappedAddr.Port)
			// }
			// fmt.Println()
		}
	}

	// Check if different IPs get different ports (sign of symmetric NAT)
	if hasMultipleIPs && len(ipGroups) >= 2 {
		ports := make(map[string]int)
		for ip, groupResults := range ipGroups {
			if len(groupResults) > 0 {
				ports[ip] = groupResults[0].MappedAddr.Port
			}
		}

		// Check if all IPs have different ports
		portValues := make([]int, 0, len(ports))
		for _, port := range ports {
			portValues = append(portValues, port)
		}

		allDifferent := true
		for i := 0; i < len(portValues); i++ {
			for j := i + 1; j < len(portValues); j++ {
				if portValues[i] == portValues[j] {
					allDifferent = false
					break
				}
			}
			if !allDifferent {
				break
			}
		}

		if allDifferent {
			differentIPsDifferentPorts = true
			slog.Debug("Different IPs have different ports (potential Symmetric NAT)")
		}
	}

	// Determine NAT type based on analysis
	if allConsistent && someConsistent && !differentIPsDifferentPorts {
		return NATTypeEasyNAT
	} else if !allConsistent && differentIPsDifferentPorts {
		return NATTypeSymmetricNAT
	} else if !allConsistent {
		return NATTypeHardNAT
	}

	return NATTypeUnknown
}

// performAdditionalTests performs additional tests for edge cases
func (n *NATDetector) performAdditionalTests(ctx context.Context, initialResults []STUNResult) NATType {
	//fmt.Println("\nPerforming additional NAT behavior tests...")

	// Test 1: Multiple queries to the same server
	if len(initialResults) > 0 {
		firstServer := initialResults[0].Server
		stabilityResult := n.testPortStabilityOverTime(ctx, firstServer)

		// Test 2: Symmetric NAT detection with port prediction
		if stabilityResult == NATTypeHardNAT {
			symmetricResult := n.testSymmetricNATBehavior(ctx, initialResults)
			if symmetricResult == NATTypeSymmetricNAT {
				return NATTypeSymmetricNAT
			}
		}

		return stabilityResult
	}

	return NATTypeUnknown
}

// testSymmetricNATBehavior performs advanced symmetric NAT detection
func (n *NATDetector) testSymmetricNATBehavior(ctx context.Context, results []STUNResult) NATType {
	fmt.Println("Testing for Symmetric NAT behavior...")

	if len(results) < 2 {
		return NATTypeUnknown
	}

	// Test pattern: Query same server multiple times to look for port patterns
	server := results[0].Server
	var ports []int

	fmt.Printf("Querying %s multiple times to analyze port allocation...\n", server)
	for i := 0; i < 5; i++ {
		if mappedAddr, err := n.querySTUNServer(ctx, server); err == nil {
			ports = append(ports, mappedAddr.Port)
			fmt.Printf("  Query %d: port %d\n", i+1, mappedAddr.Port)
		}
		time.Sleep(100 * time.Millisecond)
	}

	if len(ports) < 3 {
		fmt.Println("❌ Insufficient data for symmetric NAT detection")
		return NATTypeUnknown
	}

	// Analyze port allocation patterns
	isSequential := n.isSequentialPortAllocation(ports)
	isRandom := n.isRandomPortAllocation(ports)
	allDifferent := n.areAllPortsDifferent(ports)

	fmt.Printf("Port analysis: Sequential=%v, Random=%v, AllDifferent=%v\n",
		isSequential, isRandom, allDifferent)

	// Symmetric NAT indicators:
	// 1. All ports are different (endpoint-dependent)
	// 2. Ports follow a predictable pattern OR are completely random
	// 3. No port reuse even for same destination

	if allDifferent && (isSequential || isRandom) {
		fmt.Println("🔴 Symmetric NAT detected!")
		return NATTypeSymmetricNAT
	}

	return NATTypeHardNAT
}

// isSequentialPortAllocation checks if ports follow a sequential pattern
func (n *NATDetector) isSequentialPortAllocation(ports []int) bool {
	if len(ports) < 3 {
		return false
	}

	// Check for sequential increment
	sequential := true
	for i := 1; i < len(ports); i++ {
		if ports[i] != ports[i-1]+1 {
			sequential = false
			break
		}
	}

	if sequential {
		return true
	}

	// Check for sequential with fixed increment
	if len(ports) >= 3 {
		increment := ports[1] - ports[0]
		if increment > 0 && increment <= 10 {
			consistent := true
			for i := 2; i < len(ports); i++ {
				if ports[i]-ports[i-1] != increment {
					consistent = false
					break
				}
			}
			if consistent {
				return true
			}
		}
	}

	return false
}

// isRandomPortAllocation checks if ports appear to be randomly allocated
func (n *NATDetector) isRandomPortAllocation(ports []int) bool {
	if len(ports) < 3 {
		return false
	}

	// Check if ports have no obvious pattern
	// Simple heuristic: if differences between consecutive ports vary widely
	differences := make([]int, 0, len(ports)-1)
	for i := 1; i < len(ports); i++ {
		diff := ports[i] - ports[i-1]
		if diff < 0 {
			diff = -diff
		}
		differences = append(differences, diff)
	}

	// If differences vary significantly, it's likely random
	if len(differences) >= 2 {
		minDiff := differences[0]
		maxDiff := differences[0]
		for _, diff := range differences[1:] {
			if diff < minDiff {
				minDiff = diff
			}
			if diff > maxDiff {
				maxDiff = diff
			}
		}

		// Random if difference range is large
		return maxDiff-minDiff > 1000
	}

	return false
}

// areAllPortsDifferent checks if all ports are different
func (n *NATDetector) areAllPortsDifferent(ports []int) bool {
	seen := make(map[int]bool)
	for _, port := range ports {
		if seen[port] {
			return false
		}
		seen[port] = true
	}
	return len(seen) == len(ports)
}

// testPortStabilityOverTime tests if the same server gives consistent results over time
func (n *NATDetector) testPortStabilityOverTime(ctx context.Context, server string) NATType {
	//fmt.Printf("Testing port stability with %s...\n", server)
	slog.Debug("Testing port stability", "server", server)
	var ports []int
	for i := 0; i < 3; i++ {
		if mappedAddr, err := n.querySTUNServer(ctx, server); err == nil {
			ports = append(ports, mappedAddr.Port)
			//fmt.Printf("  Query %d: port %d\n", i+1, mappedAddr.Port)
		}
		time.Sleep(100 * time.Millisecond)
	}

	if len(ports) < 2 {
		return NATTypeUnknown
	}

	// Check if ports are consistent
	firstPort := ports[0]
	for _, port := range ports[1:] {
		if port != firstPort {
			return NATTypeHardNAT
		}
	}

	return NATTypeEasyNAT
}

// PrintDetailedResults prints detailed analysis of the results
func (n *NATDetector) PrintDetailedResults(natType NATType, results []STUNResult) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("DETAILED NAT DETECTION RESULTS")
	fmt.Println(strings.Repeat("=", 60))

	fmt.Printf("🔍 NAT Type: %s\n", natType)
	fmt.Printf("📍 Local Address: %s\n", n.udpConn.LocalAddr())
	fmt.Printf("📊 Total STUN Queries: %d\n", len(results))

	successCount := 0
	for _, result := range results {
		if result.Success {
			successCount++
		}
	}
	fmt.Printf("✅ Successful Queries: %d\n", successCount)

	fmt.Println("\nSTUN Server Results:")
	fmt.Println("-------------------")

	for i, result := range results {
		fmt.Printf("%d. %s\n", i+1, result.Server)
		if result.Success {
			fmt.Printf("   ✅ Success: %s (%.2fms)\n",
				result.MappedAddr, float64(result.ResponseTime.Nanoseconds())/1_000_000)
		} else {
			fmt.Printf("   ❌ Failed: %v\n", result.Error)
		}
	}

	// Analysis and recommendations
	fmt.Println("\nAnalysis & Recommendations:")
	fmt.Println("---------------------------")

	switch natType {
	case NATTypeOpen:
		fmt.Println("🎉 No NAT detected - direct internet connection")
		fmt.Println("   • P2P connections should work easily")
		fmt.Println("   • No special NAT traversal needed")

	case NATTypeEasyNAT:
		fmt.Println("✅ Easy NAT (Endpoint-Independent Mapping)")
		fmt.Println("   • Same port used for all destinations")
		fmt.Println("   • STUN-based NAT traversal should work")
		fmt.Println("   • Good success rate for P2P connections")

	case NATTypeHardNAT:
		fmt.Println("⚠️  Hard NAT (Endpoint-Dependent Mapping)")
		fmt.Println("   • Different ports for different destinations")
		fmt.Println("   • STUN alone is insufficient")
		fmt.Println("   • Need advanced techniques (ICE, birthday paradox)")
		fmt.Println("   • Consider using relay servers as fallback")

	case NATTypeSymmetricNAT:
		fmt.Println("🔴 Symmetric NAT")
		fmt.Println("   • Very difficult to traverse")
		fmt.Println("   • Relay servers strongly recommended")
		fmt.Println("   • Limited P2P connectivity options")

	case NATTypeBlocked:
		fmt.Println("🚫 UDP Blocked or Firewall")
		fmt.Println("   • UDP traffic may be blocked")
		fmt.Println("   • Consider TCP-based alternatives")
		fmt.Println("   • Relay servers via HTTP/HTTPS")

	default:
		fmt.Println("❓ Unknown NAT behavior")
		fmt.Println("   • Unable to determine NAT type")
		fmt.Println("   • Try additional diagnostic tools")
	}
}

// GetNATTraversalStrategy returns recommended strategies based on NAT type
func (n *NATDetector) GetNATTraversalStrategy(natType NATType) []string {
	switch natType {
	case NATTypeOpen:
		return []string{"Direct connection", "No NAT traversal needed"}

	case NATTypeEasyNAT:
		return []string{
			"STUN-based discovery",
			"Simple hole punching",
			"UPnP port mapping (if available)",
		}

	case NATTypeHardNAT:
		return []string{
			"ICE with multiple candidates",
			"Birthday paradox port scanning",
			"TURN relay as fallback",
			"UPnP port mapping (if available)",
		}

	case NATTypeSymmetricNAT:
		return []string{
			"TURN relay servers",
			"HTTP/HTTPS tunneling",
			"Avoid direct P2P if possible",
		}

	case NATTypeBlocked:
		return []string{
			"TCP-based protocols",
			"HTTP/HTTPS tunneling",
			"WebSocket connections",
		}

	default:
		return []string{"Further analysis needed"}
	}
}

// Close closes the UDP connection
func (n *NATDetector) Close() error {
	if n.udpConn == nil {
		return nil
	}
	if n.singleUse {
		return n.udpConn.Close()
	}
	return nil

}

// Additional utility functions for more detailed analysis
type NATBehaviorAnalyzer struct {
	detector *NATDetector
}

func NewNATBehaviorAnalyzer(detector *NATDetector) *NATBehaviorAnalyzer {
	return &NATBehaviorAnalyzer{detector: detector}
}

// TestPortAllocation tests how ports are allocated for different destinations
func (n *NATBehaviorAnalyzer) TestPortAllocation(ctx context.Context) {
	fmt.Println("\nTesting Port Allocation Behavior:")
	fmt.Println("=================================")

	servers := []string{
		"stun.l.google.com:19302",
		"stun.cloudflare.com:3478",
	}

	for i, server := range servers {
		fmt.Printf("Test %d - Server: %s\n", i+1, server)

		// Query the same server multiple times
		for j := 0; j < 3; j++ {
			if mappedAddr, err := n.detector.querySTUNServer(ctx, server); err == nil {
				fmt.Printf("  Query %d: %s\n", j+1, mappedAddr)
			} else {
				fmt.Printf("  Query %d: Failed - %v\n", j+1, err)
			}
			time.Sleep(100 * time.Millisecond)
		}
		fmt.Println()
	}
}

// TestFirewallBehavior tests firewall filtering behavior
func (n *NATBehaviorAnalyzer) TestFirewallBehavior(ctx context.Context) {
	fmt.Println("Testing Firewall Behavior:")
	fmt.Println("==========================")

	// This would test different firewall behaviors
	// Implementation would depend on having cooperative test servers
	fmt.Println("Note: Comprehensive firewall testing requires specialized test servers")
}

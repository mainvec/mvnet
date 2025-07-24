package punch

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Message types for the hole punching protocol
const (
	MessagePunch             = "punch"
	MessageAck               = "ack"
	MessageAckAck            = "ack_ack"
	MessageKeepAlive         = "keepalive"
	MessageKeepAliveAck      = "keepalive_ack"
	MessageConnectionTest    = "connection_test"
	MessageConnectionTestAck = "connection_test_ack"
)

// HolePunchState represents the different states of the hole punching process
type HolePunchState int32

const (
	StateInitializing HolePunchState = iota
	StatePunching
	StateEstablishing
	StateVerifying
	StateSuccessful
	StateFailed
)

func (s HolePunchState) String() string {
	switch s {
	case StateInitializing:
		return "Initializing"
	case StatePunching:
		return "Punching"
	case StateEstablishing:
		return "Establishing"
	case StateVerifying:
		return "Verifying"
	case StateSuccessful:
		return "Successful"
	case StateFailed:
		return "Failed"
	default:
		return "Unknown"
	}
}

// ConnectionState represents the state of the connection establishment
type ConnectionState int32

const (
	ConnStateUnknown ConnectionState = iota
	ConnStateEstablishing
	ConnStateEstablished
	ConnStateVerified
)

// HolePuncherConfig holds configuration parameters
type HolePuncherConfig struct {
	PunchInterval        time.Duration
	ReadTimeout          time.Duration
	WriteTimeout         time.Duration
	OverallTimeout       time.Duration
	KeepAliveInterval    time.Duration
	VerificationTimeout  time.Duration
	MaxConsecutiveErrors int
	MaxRetries           int
	MaxMissedKeepAlives  int
	RetryConfig          RetryConfig
}

// RetryConfig holds retry-specific configuration
type RetryConfig struct {
	InitialInterval time.Duration
	MaxInterval     time.Duration
	MaxRetries      int
	BackoffFactor   float64
}

// DefaultConfig returns a default configuration
func DefaultConfig() HolePuncherConfig {
	return HolePuncherConfig{
		PunchInterval:        1 * time.Second,
		ReadTimeout:          2 * time.Second,
		WriteTimeout:         2 * time.Second,
		OverallTimeout:       120 * time.Second,
		KeepAliveInterval:    10 * time.Second,
		VerificationTimeout:  5 * time.Second,
		MaxConsecutiveErrors: 5,
		MaxRetries:           120,
		MaxMissedKeepAlives:  3,
		RetryConfig: RetryConfig{
			InitialInterval: 500 * time.Millisecond,
			MaxInterval:     5 * time.Second,
			MaxRetries:      5,
			BackoffFactor:   1.5,
		},
	}
}

// HolePuncher manages the hole punching process
type HolePuncher struct {
	localAddr  *net.UDPAddr
	remoteAddr *net.UDPAddr
	conn       *net.UDPConn
	config     HolePuncherConfig

	// State management
	state      atomic.Int32
	connState  atomic.Int32
	done       chan struct{}
	closeOnce  sync.Once
	doneClosed bool
	mu         sync.RWMutex

	// Connection management
	closeConn bool

	// Protocol state tracking
	receivedPunch  atomic.Bool
	receivedAck    atomic.Bool
	receivedAckAck atomic.Bool

	// Keep-alive management
	keepAliveCtx     context.Context
	keepAliveCancel  context.CancelFunc
	missedKeepAlives int64

	// Metrics
	punchPacketsSent         int64
	ackPacketsSent           int64
	ackAckPacketsSent        int64
	keepAlivePacketsSent     int64
	punchPacketsReceived     int64
	ackPacketsReceived       int64
	ackAckPacketsReceived    int64
	keepAlivePacketsReceived int64

	// Verification
	verificationPending atomic.Bool
	verificationResult  chan bool
}

// NewHolePuncher creates a new HolePuncher with local and remote addresses
func NewHolePuncher(localAddr, remoteAddr string, config HolePuncherConfig) (*HolePuncher, error) {
	localUDPAddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve local address: %w", err)
	}

	conn, err := net.ListenUDP("udp", localUDPAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on UDP: %w", err)
	}

	return NewHolePuncherWithConn(conn, remoteAddr, config, true)
}

// NewHolePuncherWithConn creates a new HolePuncher with an existing connection
func NewHolePuncherWithConn(conn *net.UDPConn, remoteAddr string, config HolePuncherConfig, closeConn bool) (*HolePuncher, error) {
	remoteUDPAddr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve remote address: %w", err)
	}

	keepAliveCtx, keepAliveCancel := context.WithCancel(context.Background())

	hp := &HolePuncher{
		localAddr:          conn.LocalAddr().(*net.UDPAddr),
		remoteAddr:         remoteUDPAddr,
		conn:               conn,
		config:             config,
		done:               make(chan struct{}),
		closeConn:          closeConn,
		keepAliveCtx:       keepAliveCtx,
		keepAliveCancel:    keepAliveCancel,
		verificationResult: make(chan bool, 1),
	}

	hp.state.Store(int32(StateInitializing))
	hp.connState.Store(int32(ConnStateUnknown))
	return hp, nil
}

// Done returns a channel that is closed when the hole punching process is complete
func (hp *HolePuncher) Done() <-chan struct{} {
	return hp.done
}

// setState safely transitions to a new state
func (hp *HolePuncher) setState(newState HolePunchState) bool {
	currentState := hp.state.Load()

	// Define valid state transitions
	switch HolePunchState(currentState) {
	case StateInitializing:
		if newState == StatePunching {
			return hp.state.CompareAndSwap(currentState, int32(newState))
		}
	case StatePunching:
		if newState == StateEstablishing || newState == StateFailed {
			return hp.state.CompareAndSwap(currentState, int32(newState))
		}
	case StateEstablishing:
		if newState == StateVerifying || newState == StateFailed {
			return hp.state.CompareAndSwap(currentState, int32(newState))
		}
	case StateVerifying:
		if newState == StateSuccessful || newState == StateFailed {
			return hp.state.CompareAndSwap(currentState, int32(newState))
		}
	}
	return false
}

// GetState returns the current state
func (hp *HolePuncher) GetState() HolePunchState {
	return HolePunchState(hp.state.Load())
}

// GetConnectionState returns the current connection state
func (hp *HolePuncher) GetConnectionState() ConnectionState {
	return ConnectionState(hp.connState.Load())
}

// safeDone safely closes the done channel
func (hp *HolePuncher) safeDone() {
	hp.closeOnce.Do(func() {
		hp.mu.Lock()
		hp.doneClosed = true
		hp.mu.Unlock()
		close(hp.done)
	})
}

// isDone checks if the process is done
func (hp *HolePuncher) isDone() bool {
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	return hp.doneClosed
}

// isFromRemotePeer checks if the address matches the remote peer
func (hp *HolePuncher) isFromRemotePeer(addr *net.UDPAddr) bool {
	return hp.remoteAddr.IP.Equal(addr.IP) && hp.remoteAddr.Port == addr.Port
}

// Start begins the hole punching process
func (hp *HolePuncher) Start() error {
	return hp.StartWithContext(context.Background())
}

// StartWithContext begins the hole punching process with a context
func (hp *HolePuncher) StartWithContext(ctx context.Context) error {
	if !hp.setState(StatePunching) {
		return fmt.Errorf("HolePuncher is not in correct state to start (current: %s)", hp.GetState())
	}

	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, hp.config.OverallTimeout)
	defer cancel()

	// Start goroutines
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		hp.listenForMessagesWithContext(timeoutCtx)
	}()

	go func() {
		defer wg.Done()
		hp.punchWithContext(timeoutCtx)
	}()

	// Wait for completion or timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-timeoutCtx.Done():
		log.Println("Hole punching timed out")
		hp.setState(StateFailed)
		hp.safeDone()
		return fmt.Errorf("hole punching timed out after %v", hp.config.OverallTimeout)
	case <-done:
		state := hp.GetState()
		if state == StateSuccessful {
			log.Println("Hole punching completed successfully")
			// Start keep-alive monitoring
			go hp.startKeepAlive()
			return nil
		}
		return fmt.Errorf("hole punching failed with state: %s", state)
	}
}

// punchWithContext sends punch packets until connection is established
func (hp *HolePuncher) punchWithContext(ctx context.Context) {
	punchPacket := []byte(MessagePunch)
	ticker := time.NewTicker(hp.config.PunchInterval)
	defer ticker.Stop()

	consecutiveErrors := 0
	retryCount := 0

	for {
		select {
		case <-ctx.Done():
			log.Println("Punch process cancelled")
			return
		case <-hp.Done():
			log.Println("Stopping punch process")
			return
		case <-ticker.C:
			currentState := hp.GetState()
			if currentState == StateSuccessful || currentState == StateFailed {
				return
			}

			if retryCount >= hp.config.MaxRetries {
				log.Printf("Maximum retries (%d) reached", hp.config.MaxRetries)
				hp.setState(StateFailed)
				hp.safeDone()
				return
			}

			// Send punch packet with retry logic
			err := hp.sendPacketWithRetry(ctx, punchPacket)
			if err != nil {
				consecutiveErrors++
				log.Printf("Error sending punch packet (%d/%d): %v", consecutiveErrors, hp.config.MaxConsecutiveErrors, err)

				if consecutiveErrors >= hp.config.MaxConsecutiveErrors {
					log.Println("Too many consecutive errors")
					hp.setState(StateFailed)
					hp.safeDone()
					return
				}
				continue
			}

			consecutiveErrors = 0
			retryCount++
			atomic.AddInt64(&hp.punchPacketsSent, 1)
			log.Printf("Punch packet sent (attempt %d)", retryCount)
		}
	}
}

// sendPacketWithRetry sends a packet with exponential backoff retry
func (hp *HolePuncher) sendPacketWithRetry(ctx context.Context, packet []byte) error {
	interval := hp.config.RetryConfig.InitialInterval

	for i := 0; i < hp.config.RetryConfig.MaxRetries; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			hp.conn.SetWriteDeadline(time.Now().Add(hp.config.WriteTimeout))
			_, err := hp.conn.WriteToUDP(packet, hp.remoteAddr)
			if err == nil {
				return nil
			}

			log.Printf("Send retry %d failed: %v", i+1, err)

			if i < hp.config.RetryConfig.MaxRetries-1 {
				time.Sleep(interval)
				interval = time.Duration(float64(interval) * hp.config.RetryConfig.BackoffFactor)
				if interval > hp.config.RetryConfig.MaxInterval {
					interval = hp.config.RetryConfig.MaxInterval
				}
			}
		}
	}

	return fmt.Errorf("max retries exceeded")
}

// listenForMessagesWithContext listens for incoming messages
func (hp *HolePuncher) listenForMessagesWithContext(ctx context.Context) {
	buffer := make([]byte, 1024)

	for {
		select {
		case <-ctx.Done():
			log.Println("Message listener cancelled")
			return
		case <-hp.Done():
			log.Println("Stopping message listener")
			return
		default:
			hp.conn.SetReadDeadline(time.Now().Add(hp.config.ReadTimeout))
			n, addr, err := hp.conn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				log.Printf("Error reading from UDP: %v", err)
				continue
			}

			if !hp.isFromRemotePeer(addr) {
				log.Printf("Received message from unexpected address: %s", addr.String())
				continue
			}

			message := string(buffer[:n])
			log.Printf("Received message from %s: %s", addr.String(), message)
			hp.handleMessage(message, addr)
		}
	}
}

// handleMessage processes incoming messages
func (hp *HolePuncher) handleMessage(message string, addr *net.UDPAddr) {
	switch message {
	case MessagePunch:
		atomic.AddInt64(&hp.punchPacketsReceived, 1)
		hp.handlePunchPacket(addr)
	case MessageAck:
		atomic.AddInt64(&hp.ackPacketsReceived, 1)
		hp.handleAckPacket(addr)
	case MessageAckAck:
		atomic.AddInt64(&hp.ackAckPacketsReceived, 1)
		hp.handleAckAckPacket(addr)
	case MessageKeepAlive:
		atomic.AddInt64(&hp.keepAlivePacketsReceived, 1)
		hp.handleKeepAlivePacket(addr)
	case MessageKeepAliveAck:
		hp.handleKeepAliveAckPacket(addr)
	case MessageConnectionTest:
		hp.handleConnectionTestPacket(addr)
	case MessageConnectionTestAck:
		hp.handleConnectionTestAckPacket(addr)
	default:
		log.Printf("Unknown message type: %s", message)
	}
}

// handlePunchPacket processes incoming punch packets
func (hp *HolePuncher) handlePunchPacket(addr *net.UDPAddr) {
	log.Printf("Received punch packet from %s", addr.String())

	if !hp.receivedPunch.Load() {
		hp.receivedPunch.Store(true)
		log.Println("First punch packet received")
	}

	// Send ACK response
	ackPacket := []byte(MessageAck)
	hp.conn.SetWriteDeadline(time.Now().Add(hp.config.WriteTimeout))
	_, err := hp.conn.WriteToUDP(ackPacket, addr)
	if err != nil {
		log.Printf("Error sending ACK: %v", err)
		return
	}

	atomic.AddInt64(&hp.ackPacketsSent, 1)
	log.Println("ACK packet sent")

	// Transition to establishing state if not already there
	if hp.GetState() == StatePunching {
		hp.setState(StateEstablishing)
		hp.connState.Store(int32(ConnStateEstablishing))
	}
}

// handleAckPacket processes incoming ACK packets
func (hp *HolePuncher) handleAckPacket(addr *net.UDPAddr) {
	log.Printf("Received ACK packet from %s", addr.String())

	if !hp.receivedAck.Load() {
		hp.receivedAck.Store(true)
		log.Println("First ACK packet received")
	}

	// Send ACK-ACK response
	ackAckPacket := []byte(MessageAckAck)
	hp.conn.SetWriteDeadline(time.Now().Add(hp.config.WriteTimeout))
	_, err := hp.conn.WriteToUDP(ackAckPacket, addr)
	if err != nil {
		log.Printf("Error sending ACK-ACK: %v", err)
		return
	}

	atomic.AddInt64(&hp.ackAckPacketsSent, 1)
	log.Println("ACK-ACK packet sent")

	// Transition to establishing state if not already there
	if hp.GetState() == StatePunching {
		hp.setState(StateEstablishing)
		hp.connState.Store(int32(ConnStateEstablishing))
	}

	// Check if we should start verification
	hp.checkForVerification()
}

// handleAckAckPacket processes incoming ACK-ACK packets
func (hp *HolePuncher) handleAckAckPacket(addr *net.UDPAddr) {
	log.Printf("Received ACK-ACK packet from %s", addr.String())

	if !hp.receivedAckAck.Load() {
		hp.receivedAckAck.Store(true)
		log.Println("First ACK-ACK packet received")
	}

	// Update connection state
	hp.connState.Store(int32(ConnStateEstablished))

	// Check if we should start verification
	hp.checkForVerification()
}

// checkForVerification checks if we should start the verification process
func (hp *HolePuncher) checkForVerification() {
	if hp.receivedPunch.Load() && hp.receivedAck.Load() && hp.receivedAckAck.Load() {
		if hp.setState(StateVerifying) {
			log.Println("All handshake packets received, starting verification")
			go hp.startVerification()
		}
	}
}

// startVerification starts the connection verification process
func (hp *HolePuncher) startVerification() {
	if !hp.verificationPending.CompareAndSwap(false, true) {
		log.Println("Verification already in progress")
		return
	}

	defer hp.verificationPending.Store(false)

	// Send connection test packet
	testPacket := []byte(MessageConnectionTest)
	hp.conn.SetWriteDeadline(time.Now().Add(hp.config.WriteTimeout))
	_, err := hp.conn.WriteToUDP(testPacket, hp.remoteAddr)
	if err != nil {
		log.Printf("Error sending connection test: %v", err)
		hp.setState(StateFailed)
		hp.safeDone()
		return
	}

	log.Println("Connection test packet sent")

	// Wait for verification result with timeout
	select {
	case success := <-hp.verificationResult:
		if success {
			log.Println("Connection verification successful")
			hp.connState.Store(int32(ConnStateVerified))
			hp.setState(StateSuccessful)
			log.Println("Hole punching completed successfully")
			hp.safeDone()
		} else {
			log.Println("Connection verification failed")
			hp.setState(StateFailed)
		}
		hp.safeDone()
	case <-time.After(hp.config.VerificationTimeout):
		log.Println("Connection verification timed out")
		hp.setState(StateFailed)
		hp.safeDone()
	}
}

// handleConnectionTestPacket processes incoming connection test packets
func (hp *HolePuncher) handleConnectionTestPacket(addr *net.UDPAddr) {
	log.Printf("Received connection test packet from %s", addr.String())

	// Send connection test ACK
	testAckPacket := []byte(MessageConnectionTestAck)
	hp.conn.SetWriteDeadline(time.Now().Add(hp.config.WriteTimeout))
	_, err := hp.conn.WriteToUDP(testAckPacket, addr)
	if err != nil {
		log.Printf("Error sending connection test ACK: %v", err)
		return
	}

	log.Println("Connection test ACK sent")
}

// handleConnectionTestAckPacket processes incoming connection test ACK packets
func (hp *HolePuncher) handleConnectionTestAckPacket(addr *net.UDPAddr) {
	log.Printf("Received connection test ACK packet from %s", addr.String())

	// Signal verification success
	select {
	case hp.verificationResult <- true:
		log.Println("Verification result sent: success")
	default:
		log.Println("Verification result channel full or closed")
	}
}

// handleKeepAlivePacket processes incoming keep-alive packets
func (hp *HolePuncher) handleKeepAlivePacket(addr *net.UDPAddr) {
	log.Printf("Received keep-alive packet from %s", addr.String())

	// Reset missed keep-alive counter
	atomic.StoreInt64(&hp.missedKeepAlives, 0)

	// Send keep-alive ACK
	keepAliveAckPacket := []byte(MessageKeepAliveAck)
	hp.conn.SetWriteDeadline(time.Now().Add(hp.config.WriteTimeout))
	_, err := hp.conn.WriteToUDP(keepAliveAckPacket, addr)
	if err != nil {
		log.Printf("Error sending keep-alive ACK: %v", err)
		return
	}

	log.Println("Keep-alive ACK sent")
}

// handleKeepAliveAckPacket processes incoming keep-alive ACK packets
func (hp *HolePuncher) handleKeepAliveAckPacket(addr *net.UDPAddr) {
	log.Printf("Received keep-alive ACK packet from %s", addr.String())

	// Reset missed keep-alive counter
	atomic.StoreInt64(&hp.missedKeepAlives, 0)
}

// startKeepAlive starts the keep-alive monitoring process
func (hp *HolePuncher) startKeepAlive() {
	if hp.GetState() != StateSuccessful {
		log.Println("Cannot start keep-alive: connection not successful")
		return
	}

	log.Println("Starting keep-alive monitoring")
	ticker := time.NewTicker(hp.config.KeepAliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-hp.keepAliveCtx.Done():
			log.Println("Keep-alive monitoring stopped")
			return
		case <-hp.Done():
			log.Println("Keep-alive monitoring stopped: hole puncher done")
			return
		case <-ticker.C:
			// Check if we've missed too many keep-alives
			missed := atomic.LoadInt64(&hp.missedKeepAlives)
			if missed >= int64(hp.config.MaxMissedKeepAlives) {
				log.Printf("Too many missed keep-alives (%d), connection failed", missed)
				hp.setState(StateFailed)
				hp.safeDone()
				return
			}

			// Send keep-alive packet
			keepAlivePacket := []byte(MessageKeepAlive)
			hp.conn.SetWriteDeadline(time.Now().Add(hp.config.WriteTimeout))
			_, err := hp.conn.WriteToUDP(keepAlivePacket, hp.remoteAddr)
			if err != nil {
				log.Printf("Error sending keep-alive: %v", err)
				atomic.AddInt64(&hp.missedKeepAlives, 1)
				continue
			}

			atomic.AddInt64(&hp.keepAlivePacketsSent, 1)
			atomic.AddInt64(&hp.missedKeepAlives, 1)
			log.Println("Keep-alive packet sent")
		}
	}
}

// GetMetrics returns current metrics
func (hp *HolePuncher) GetMetrics() map[string]int64 {
	return map[string]int64{
		"punch_packets_sent":          atomic.LoadInt64(&hp.punchPacketsSent),
		"ack_packets_sent":            atomic.LoadInt64(&hp.ackPacketsSent),
		"ack_ack_packets_sent":        atomic.LoadInt64(&hp.ackAckPacketsSent),
		"keep_alive_packets_sent":     atomic.LoadInt64(&hp.keepAlivePacketsSent),
		"punch_packets_received":      atomic.LoadInt64(&hp.punchPacketsReceived),
		"ack_packets_received":        atomic.LoadInt64(&hp.ackPacketsReceived),
		"ack_ack_packets_received":    atomic.LoadInt64(&hp.ackAckPacketsReceived),
		"keep_alive_packets_received": atomic.LoadInt64(&hp.keepAlivePacketsReceived),
		"missed_keep_alives":          atomic.LoadInt64(&hp.missedKeepAlives),
	}
}

// GetConnection returns the underlying UDP connection
func (hp *HolePuncher) GetConnection() *net.UDPConn {
	return hp.conn
}

// GetLocalAddr returns the local address
func (hp *HolePuncher) GetLocalAddr() *net.UDPAddr {
	return hp.localAddr
}

// GetRemoteAddr returns the remote address
func (hp *HolePuncher) GetRemoteAddr() *net.UDPAddr {
	return hp.remoteAddr
}

// IsConnected returns true if the connection is established and verified
func (hp *HolePuncher) IsConnected() bool {
	return hp.GetState() == StateSuccessful && hp.GetConnectionState() == ConnStateVerified
}

// Close closes the hole puncher and optionally the underlying connection
func (hp *HolePuncher) Close() error {
	log.Println("Closing HolePuncher")

	// Cancel keep-alive monitoring
	if hp.keepAliveCancel != nil {
		hp.keepAliveCancel()
	}

	// Set state to failed to stop all operations
	hp.setState(StateFailed)

	// Signal completion
	hp.safeDone()

	// Close connection if we own it
	if hp.closeConn && hp.conn != nil {
		return hp.conn.Close()
	}

	return nil
}

// SendData sends data over the established connection
func (hp *HolePuncher) SendData(data []byte) error {
	if !hp.IsConnected() {
		return fmt.Errorf("connection not established")
	}

	hp.conn.SetWriteDeadline(time.Now().Add(hp.config.WriteTimeout))
	_, err := hp.conn.WriteToUDP(data, hp.remoteAddr)
	return err
}

// ReceiveData receives data from the established connection
func (hp *HolePuncher) ReceiveData(buffer []byte) (int, *net.UDPAddr, error) {
	if !hp.IsConnected() {
		return 0, nil, fmt.Errorf("connection not established")
	}

	hp.conn.SetReadDeadline(time.Now().Add(hp.config.ReadTimeout))
	return hp.conn.ReadFromUDP(buffer)
}

// WaitForCompletion waits for the hole punching process to complete
func (hp *HolePuncher) WaitForCompletion() error {
	<-hp.Done()

	state := hp.GetState()
	if state == StateSuccessful {
		return nil
	}

	return fmt.Errorf("hole punching failed with state: %s", state)
}

// WaitForCompletionWithTimeout waits for completion with a timeout
func (hp *HolePuncher) WaitForCompletionWithTimeout(timeout time.Duration) error {
	select {
	case <-hp.Done():
		state := hp.GetState()
		if state == StateSuccessful {
			return nil
		}
		return fmt.Errorf("hole punching failed with state: %s", state)
	case <-time.After(timeout):
		return fmt.Errorf("wait for completion timed out after %v", timeout)
	}
}

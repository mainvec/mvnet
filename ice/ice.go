package ice

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/mainvec/mvnet/stun"
)

// Config holds ICE agent configuration.
type Config struct {
	STUNServers       []string      // STUN servers for server-reflexive candidate discovery.
	CheckTimeout      time.Duration // Per-check response timeout (default 3s).
	NominationTimeout time.Duration // How long controlled agent waits for nomination (default 10s).
	MaxChecks         int           // Maximum candidate pairs to check (default 20).
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		STUNServers:       stun.PUBLIC_STUN_SERVERS,
		CheckTimeout:      1500 * time.Millisecond,
		NominationTimeout: 10 * time.Second,
		MaxChecks:         20,
	}
}

// Agent manages ICE candidate gathering, connectivity checking, and nomination.
//
// Usage:
//
//	agent := ice.NewAgent(ice.DefaultConfig(), ice.RoleControlling)
//	agent.GatherCandidates(ctx)
//	// Exchange candidates/credentials via signaling...
//	agent.SetRemoteCredentials(remoteUfrag, remotePwd)
//	agent.AddRemoteCandidates(remoteCandidates)
//	pair, err := agent.RunChecks(ctx)
//	if pair != nil {
//	    conn := pair.Local.Conn  // UDP socket ready for QUIC
//	    agent.CloseUnselected()
//	}
type Agent struct {
	config         Config
	role           AgentRole
	tieBreaker     uint64
	localUfrag     string
	localPassword  string
	remoteUfrag    string
	remotePassword string

	localCandidates  []*Candidate
	remoteCandidates []*Candidate
	checklist        []*CandidatePair
	validPairs       []*CandidatePair
	selectedPair     *CandidatePair

	readers      map[*net.UDPConn]*socketReader
	readersWg    sync.WaitGroup
	nominationCh chan *CandidatePair
	mu           sync.RWMutex
	logf         func(format string, args ...any)
}

// NewAgent creates a new ICE agent with the given configuration and role.
func NewAgent(config Config, role AgentRole) *Agent {
	var tieBreaker uint64
	binary.Read(rand.Reader, binary.BigEndian, &tieBreaker)

	return &Agent{
		config:        config,
		role:          role,
		tieBreaker:    tieBreaker,
		localUfrag:    generateCredential(8),
		localPassword: generateCredential(24),
		readers:       make(map[*net.UDPConn]*socketReader),
		nominationCh:  make(chan *CandidatePair, 1),
		logf:          func(format string, args ...any) { log.Printf("[ice] "+format, args...) },
	}
}

// SetLogger sets the logging function. Signature matches log.Printf.
func (a *Agent) SetLogger(f func(format string, args ...any)) {
	a.logf = f
}

// GetLocalCredentials returns the local ICE ufrag and password for signaling.
func (a *Agent) GetLocalCredentials() (ufrag, password string) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.localUfrag, a.localPassword
}

// SetRemoteCredentials sets the remote peer's ICE credentials from signaling.
func (a *Agent) SetRemoteCredentials(ufrag, password string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.remoteUfrag = ufrag
	a.remotePassword = password
}

// GetLocalCandidates returns gathered local candidates for signaling exchange.
// Candidates are returned as copies (safe for JSON marshaling).
func (a *Agent) GetLocalCandidates() []Candidate {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]Candidate, len(a.localCandidates))
	for i, c := range a.localCandidates {
		out[i] = *c
	}
	return out
}

// AddRemoteCandidates adds remote candidates received via signaling.
// Must be called before RunChecks.
func (a *Agent) AddRemoteCandidates(candidates []Candidate) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range candidates {
		c := candidates[i] // copy
		a.remoteCandidates = append(a.remoteCandidates, &c)
	}
}

// SelectedPair returns the nominated candidate pair, or nil if none selected.
func (a *Agent) SelectedPair() *CandidatePair {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.selectedPair
}

// ---------- Candidate Gathering ----------

// GatherCandidates discovers host and server-reflexive candidates.
// Call this before exchanging candidates via signaling.
func (a *Agent) GatherCandidates(ctx context.Context) error {
	if err := a.gatherHostCandidates(); err != nil {
		return fmt.Errorf("host candidates: %w", err)
	}

	a.gatherServerReflexiveCandidates(ctx)

	// Sort by priority (highest first).
	a.mu.Lock()
	sort.Slice(a.localCandidates, func(i, j int) bool {
		return a.localCandidates[i].Priority > a.localCandidates[j].Priority
	})
	a.mu.Unlock()

	return nil
}

func (a *Agent) gatherHostCandidates() error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("list interfaces: %w", err)
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil || ipNet.IP.IsLinkLocalUnicast() {
				continue
			}

			conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ipNet.IP, Port: 0})
			if err != nil {
				a.logf("bind %s failed: %v", ipNet.IP, err)
				continue
			}

			actualAddr := conn.LocalAddr().(*net.UDPAddr)
			c := &Candidate{
				Type:       CandidateHost,
				Foundation: fmt.Sprintf("host_%s", ipNet.IP),
				Component:  1,
				Address:    ipNet.IP,
				Port:       actualAddr.Port,
				Conn:       conn,
			}
			c.calculatePriority()

			a.mu.Lock()
			a.localCandidates = append(a.localCandidates, c)
			a.mu.Unlock()

			a.logf("host candidate: %s", c.String())
		}
	}
	return nil
}

func (a *Agent) gatherServerReflexiveCandidates(ctx context.Context) {
	a.mu.RLock()
	hosts := make([]*Candidate, 0, len(a.localCandidates))
	for _, c := range a.localCandidates {
		if c.Type == CandidateHost && c.Conn != nil {
			hosts = append(hosts, c)
		}
	}
	a.mu.RUnlock()

	for _, hc := range hosts {
		for _, server := range a.config.STUNServers {
			if ctx.Err() != nil {
				return
			}
			result, err := stun.QuerySTUNServerWithConn(hc.Conn, server)
			// Reset deadline set by stun package.
			hc.Conn.SetDeadline(time.Time{})
			if err != nil {
				a.logf("STUN %s via %s failed: %v", server, hc.Address, err)
				continue
			}

			c := &Candidate{
				Type:        CandidateServerReflexive,
				Foundation:  fmt.Sprintf("srflx_%s_%d", result.IP, result.Port),
				Component:   1,
				Address:     result.IP,
				Port:        result.Port,
				RelatedIP:   hc.Address,
				RelatedPort: hc.Port,
				Conn:        hc.Conn, // Share the host candidate's socket (fixes srflx socket reuse).
			}
			c.calculatePriority()

			a.mu.Lock()
			a.localCandidates = append(a.localCandidates, c)
			a.mu.Unlock()

			a.logf("srflx candidate: %s (via %s)", c.String(), server)
			break // One srflx per host candidate.
		}
	}
}

// ---------- Connectivity Checks ----------

// RunChecks performs ICE connectivity checks and nomination.
// Both remote candidates and credentials must be set before calling.
// Returns the nominated CandidatePair with a usable Local.Conn, or an error.
//
// Checks run in parallel with 20ms pacing to avoid UDP bursts.
// A host-host success triggers early termination of remaining checks.
func (a *Agent) RunChecks(ctx context.Context) (*CandidatePair, error) {
	a.formCandidatePairs()
	if len(a.checklist) == 0 {
		return nil, fmt.Errorf("no candidate pairs to check")
	}

	// Start socket readers for all local candidate sockets.
	a.startReaders(ctx)
	defer a.stopReaders()

	pairs := a.checklist
	if len(pairs) > a.config.MaxChecks {
		pairs = pairs[:a.config.MaxChecks]
	}

	a.logf("checking %d candidate pairs in parallel (role=%s)", len(pairs), a.role)

	// Launch all checks with 20ms pacing.
	checkCtx, checkCancel := context.WithCancel(ctx)
	defer checkCancel()

	type checkResult struct {
		pair    *CandidatePair
		success bool
	}
	resultCh := make(chan checkResult, len(pairs))

	for i, pair := range pairs {
		delay := time.Duration(i) * 20 * time.Millisecond
		go func(p *CandidatePair, d time.Duration) {
			select {
			case <-time.After(d):
			case <-checkCtx.Done():
				resultCh <- checkResult{p, false}
				return
			}
			success := a.performConnectivityCheck(checkCtx, p, false)
			resultCh <- checkResult{p, success}
		}(pair, delay)
	}

	// Collect results; break early on host-host success.
	foundHostHost := false
	for i := 0; i < len(pairs) && !foundHostHost; i++ {
		select {
		case r := <-resultCh:
			if r.success {
				r.pair.State = PairStateSucceeded
				r.pair.Valid = true
				a.mu.Lock()
				a.validPairs = append(a.validPairs, r.pair)
				a.mu.Unlock()
				a.logf("valid pair: %s", r.pair.String())

				if r.pair.Local.Type == CandidateHost && r.pair.Remote.Type == CandidateHost {
					a.logf("host-host pair found, cancelling remaining checks")
					checkCancel()
					foundHostHost = true
				}
			} else {
				r.pair.State = PairStateFailed
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Nomination phase.
	if a.role == RoleControlling {
		return a.nominate(ctx)
	}
	return a.waitForNomination(ctx)
}

func (a *Agent) formCandidatePairs() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.checklist = nil
	for _, local := range a.localCandidates {
		if local.Conn == nil {
			continue
		}
		for _, remote := range a.remoteCandidates {
			pair := &CandidatePair{
				Local:      local,
				Remote:     remote,
				State:      PairStateWaiting,
				Foundation: local.Foundation + "_" + remote.Foundation,
			}
			pair.calculatePriority(a.role == RoleControlling)
			a.checklist = append(a.checklist, pair)
		}
	}

	sort.Slice(a.checklist, func(i, j int) bool {
		return a.checklist[i].Priority > a.checklist[j].Priority
	})

	a.logf("formed %d candidate pairs", len(a.checklist))
}

func (a *Agent) performConnectivityCheck(ctx context.Context, pair *CandidatePair, useCandidate bool) bool {
	reader := a.getReader(pair.Local.Conn)
	if reader == nil {
		return false
	}

	req := a.createICEBindingRequest(pair, useCandidate)
	respCh := reader.registerPending(req.transID)
	defer reader.unregisterPending(req.transID)

	remoteAddr := pair.Remote.addr()
	reqData := req.marshal()

	// Send initial request.
	if _, err := pair.Local.Conn.WriteToUDP(reqData, remoteAddr); err != nil {
		a.logf("send check to %s failed: %v", remoteAddr, err)
		return false
	}

	// Retransmit every 500ms until timeout (handles startup race where
	// the remote agent's readers aren't running yet).
	retransmit := time.NewTicker(500 * time.Millisecond)
	defer retransmit.Stop()
	deadline := time.After(a.config.CheckTimeout)

	for {
		select {
		case resp := <-respCh:
			return resp != nil && resp.msgType == stunBindingResponse
		case <-retransmit.C:
			pair.Local.Conn.WriteToUDP(reqData, remoteAddr) // retry, ignore error
		case <-deadline:
			return false
		case <-ctx.Done():
			return false
		}
	}
}

// ---------- Nomination ----------

func (a *Agent) nominate(ctx context.Context) (*CandidatePair, error) {
	a.mu.RLock()
	if len(a.validPairs) == 0 {
		a.mu.RUnlock()
		return nil, fmt.Errorf("no valid pairs for nomination")
	}
	best := a.validPairs[0]
	for _, p := range a.validPairs[1:] {
		if p.Priority > best.Priority {
			best = p
		}
	}
	a.mu.RUnlock()

	a.logf("nominating: %s", best.String())

	// Send USE-CANDIDATE check.
	if !a.performConnectivityCheck(ctx, best, true) {
		return nil, fmt.Errorf("nomination check failed for %s", best.String())
	}

	best.Nominated = true
	a.mu.Lock()
	a.selectedPair = best
	a.mu.Unlock()

	a.logf("nominated: %s", best.String())
	return best, nil
}

func (a *Agent) waitForNomination(ctx context.Context) (*CandidatePair, error) {
	a.logf("waiting for nomination (timeout=%s)", a.config.NominationTimeout)

	select {
	case pair := <-a.nominationCh:
		a.logf("received nomination: %s", pair.String())
		return pair, nil
	case <-time.After(a.config.NominationTimeout):
		// Fallback: pick best valid pair if nomination signal was missed.
		a.mu.RLock()
		defer a.mu.RUnlock()
		if len(a.validPairs) > 0 {
			best := a.validPairs[0]
			for _, p := range a.validPairs[1:] {
				if p.Priority > best.Priority {
					best = p
				}
			}
			best.Nominated = true
			a.selectedPair = best
			a.logf("nomination timeout, using best valid pair: %s", best.String())
			return best, nil
		}
		return nil, fmt.Errorf("nomination timeout, no valid pairs")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ---------- Socket Readers ----------

// socketReader manages incoming STUN messages on a UDP socket, demuxing
// binding responses to pending checks by transaction ID.
type socketReader struct {
	conn    *net.UDPConn
	agent   *Agent
	pending map[[12]byte]chan *stunMessage
	mu      sync.Mutex
	stopCh  chan struct{}
}

func (a *Agent) startReaders(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()

	seen := make(map[*net.UDPConn]bool)
	for _, c := range a.localCandidates {
		if c.Conn == nil || seen[c.Conn] {
			continue
		}
		seen[c.Conn] = true

		sr := &socketReader{
			conn:    c.Conn,
			agent:   a,
			pending: make(map[[12]byte]chan *stunMessage),
			stopCh:  make(chan struct{}),
		}
		a.readers[c.Conn] = sr
		a.readersWg.Add(1)
		go func() {
			defer a.readersWg.Done()
			sr.readLoop(ctx)
		}()
	}
}

func (a *Agent) stopReaders() {
	a.mu.Lock()
	for _, sr := range a.readers {
		close(sr.stopCh)
	}
	// Force blocking reads to unblock immediately.
	for conn := range a.readers {
		conn.SetReadDeadline(time.Now())
	}
	a.mu.Unlock()

	// Wait for all reader goroutines to exit.
	a.readersWg.Wait()

	// Reset deadlines so sockets are clean for post-ICE use.
	a.mu.Lock()
	for conn := range a.readers {
		conn.SetReadDeadline(time.Time{})
	}
	a.readers = make(map[*net.UDPConn]*socketReader)
	a.mu.Unlock()
}

func (a *Agent) getReader(conn *net.UDPConn) *socketReader {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.readers[conn]
}

func (sr *socketReader) readLoop(ctx context.Context) {
	buf := make([]byte, 1500)
	for {
		select {
		case <-sr.stopCh:
			return
		case <-ctx.Done():
			return
		default:
		}

		sr.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, remoteAddr, err := sr.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return // Socket closed or fatal error.
		}

		msg, err := parseSTUNMessage(buf[:n])
		if err != nil {
			continue
		}

		switch msg.msgType {
		case stunBindingRequest:
			sr.agent.handleBindingRequest(sr.conn, msg, remoteAddr)
		case stunBindingResponse:
			sr.mu.Lock()
			if ch, ok := sr.pending[msg.transID]; ok {
				select {
				case ch <- msg:
				default:
				}
				delete(sr.pending, msg.transID)
			}
			sr.mu.Unlock()
		}
	}
}

func (sr *socketReader) registerPending(transID [12]byte) chan *stunMessage {
	ch := make(chan *stunMessage, 1)
	sr.mu.Lock()
	sr.pending[transID] = ch
	sr.mu.Unlock()
	return ch
}

func (sr *socketReader) unregisterPending(transID [12]byte) {
	sr.mu.Lock()
	delete(sr.pending, transID)
	sr.mu.Unlock()
}

// handleBindingRequest processes an incoming STUN binding request and sends a response.
func (a *Agent) handleBindingRequest(conn *net.UDPConn, req *stunMessage, remoteAddr *net.UDPAddr) {
	// Build response with XOR-MAPPED-ADDRESS.
	resp := &stunMessage{
		msgType: stunBindingResponse,
		cookie:  stunMagicCookie,
		transID: req.transID,
	}
	resp.attributes = append(resp.attributes, createXorMappedAddressAttribute(remoteAddr, req.transID))

	if _, err := conn.WriteToUDP(resp.marshal(), remoteAddr); err != nil {
		a.logf("send binding response failed: %v", err)
		return
	}

	// Handle USE-CANDIDATE (nomination from controlling agent).
	if req.hasAttribute(stunAttrUseCandidate) && a.role == RoleControlled {
		a.handleNomination(conn, remoteAddr)
	}
}

// handleNomination processes a USE-CANDIDATE from the controlling agent.
func (a *Agent) handleNomination(conn *net.UDPConn, remoteAddr *net.UDPAddr) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Look for the matching pair in the valid list first.
	for _, pair := range a.validPairs {
		if pair.Local.Conn == conn &&
			pair.Remote.Address.Equal(remoteAddr.IP) &&
			pair.Remote.Port == remoteAddr.Port {
			pair.Nominated = true
			a.selectedPair = pair
			a.logf("nominated by controlling: %s", pair.String())
			select {
			case a.nominationCh <- pair:
			default:
			}
			return
		}
	}

	// Triggered check scenario: pair not yet validated from our side.
	// Create a valid pair from the candidate lists.
	for _, lc := range a.localCandidates {
		if lc.Conn != conn {
			continue
		}
		for _, rc := range a.remoteCandidates {
			if rc.Address.Equal(remoteAddr.IP) && rc.Port == remoteAddr.Port {
				pair := &CandidatePair{
					Local:      lc,
					Remote:     rc,
					State:      PairStateSucceeded,
					Nominated:  true,
					Valid:      true,
					Foundation: lc.Foundation + "_" + rc.Foundation,
				}
				pair.calculatePriority(false)
				a.selectedPair = pair
				a.validPairs = append(a.validPairs, pair)
				a.logf("nominated (triggered): %s", pair.String())
				select {
				case a.nominationCh <- pair:
				default:
				}
				return
			}
		}
	}

	a.logf("nomination for unknown pair from %s", remoteAddr)
}

// ---------- Cleanup ----------

// CloseUnselected closes all candidate sockets except the selected pair's socket.
// Call after RunChecks succeeds to free unused sockets.
func (a *Agent) CloseUnselected() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.selectedPair == nil {
		return fmt.Errorf("no selected pair")
	}

	selectedConn := a.selectedPair.Local.Conn
	closed := make(map[*net.UDPConn]bool)
	for _, c := range a.localCandidates {
		if c.Conn != nil && c.Conn != selectedConn && !closed[c.Conn] {
			c.Conn.Close()
			closed[c.Conn] = true
		}
	}
	return nil
}

// Close closes all candidate sockets including the selected pair's.
func (a *Agent) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	closed := make(map[*net.UDPConn]bool)
	for _, c := range a.localCandidates {
		if c.Conn != nil && !closed[c.Conn] {
			c.Conn.Close()
			closed[c.Conn] = true
		}
	}
	return nil
}

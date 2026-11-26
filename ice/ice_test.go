package ice

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"
)

func TestCandidatePriority(t *testing.T) {
	c := &Candidate{Type: CandidateHost, Component: 1}
	c.calculatePriority()
	if c.Priority == 0 {
		t.Fatal("host priority should not be zero")
	}

	s := &Candidate{Type: CandidateServerReflexive, Component: 1}
	s.calculatePriority()
	if s.Priority >= c.Priority {
		t.Fatalf("srflx priority %d should be less than host priority %d", s.Priority, c.Priority)
	}
}

func TestCandidateJSON(t *testing.T) {
	c := Candidate{
		Type:       CandidateHost,
		Foundation: "host_192.168.1.10",
		Component:  1,
		Priority:   2130706175,
		Address:    net.ParseIP("192.168.1.10"),
		Port:       12345,
	}

	data, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Candidate
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Type != c.Type {
		t.Errorf("type: got %v want %v", decoded.Type, c.Type)
	}
	if !decoded.Address.Equal(c.Address) {
		t.Errorf("address: got %v want %v", decoded.Address, c.Address)
	}
	if decoded.Port != c.Port {
		t.Errorf("port: got %d want %d", decoded.Port, c.Port)
	}
	if decoded.Priority != c.Priority {
		t.Errorf("priority: got %d want %d", decoded.Priority, c.Priority)
	}
	if decoded.Foundation != c.Foundation {
		t.Errorf("foundation: got %s want %s", decoded.Foundation, c.Foundation)
	}
}

func TestCandidateJSONWithRelated(t *testing.T) {
	c := Candidate{
		Type:        CandidateServerReflexive,
		Foundation:  "srflx_1.2.3.4_5678",
		Component:   1,
		Priority:    1694498815,
		Address:     net.ParseIP("1.2.3.4"),
		Port:        5678,
		RelatedIP:   net.ParseIP("192.168.1.10"),
		RelatedPort: 12345,
	}

	data, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Candidate
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !decoded.RelatedIP.Equal(c.RelatedIP) {
		t.Errorf("relatedIP: got %v want %v", decoded.RelatedIP, c.RelatedIP)
	}
	if decoded.RelatedPort != c.RelatedPort {
		t.Errorf("relatedPort: got %d want %d", decoded.RelatedPort, c.RelatedPort)
	}
}

func TestPairPriority(t *testing.T) {
	local := &Candidate{Priority: 2130706175}
	remote := &Candidate{Priority: 1694498815}

	pair := &CandidatePair{Local: local, Remote: remote}
	pair.calculatePriority(true)
	if pair.Priority == 0 {
		t.Fatal("pair priority should not be zero")
	}

	// Same pair from controlled side should have the same priority.
	pair2 := &CandidatePair{Local: remote, Remote: local}
	pair2.calculatePriority(false)
	if pair.Priority != pair2.Priority {
		t.Errorf("pair priorities should match: controlling=%d controlled=%d", pair.Priority, pair2.Priority)
	}
}

func TestSTUNMarshalParse(t *testing.T) {
	msg := &stunMessage{
		msgType: stunBindingRequest,
		cookie:  stunMagicCookie,
		transID: generateTransactionID(),
	}
	msg.attributes = append(msg.attributes, stunAttribute{
		attrType: stunAttrUsername,
		length:   5,
		value:    []byte("hello"),
	})

	data := msg.marshal()
	parsed, err := parseSTUNMessage(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if parsed.msgType != msg.msgType {
		t.Errorf("type: got %x want %x", parsed.msgType, msg.msgType)
	}
	if parsed.transID != msg.transID {
		t.Error("transaction ID mismatch")
	}
	if len(parsed.attributes) != 1 {
		t.Fatalf("attributes: got %d want 1", len(parsed.attributes))
	}
	if string(parsed.attributes[0].value) != "hello" {
		t.Errorf("attr value: got %q want %q", parsed.attributes[0].value, "hello")
	}
}

func TestSTUNHasAttribute(t *testing.T) {
	msg := &stunMessage{
		attributes: []stunAttribute{
			{attrType: stunAttrUseCandidate, length: 0},
			{attrType: stunAttrPriority, length: 4, value: []byte{0, 0, 0, 1}},
		},
	}

	if !msg.hasAttribute(stunAttrUseCandidate) {
		t.Error("should have USE-CANDIDATE")
	}
	if msg.hasAttribute(stunAttrUsername) {
		t.Error("should not have USERNAME")
	}
}

func TestXorMappedAddress(t *testing.T) {
	addr := &net.UDPAddr{
		IP:   net.ParseIP("192.168.1.100"),
		Port: 54321,
	}
	transID := generateTransactionID()

	attr := createXorMappedAddressAttribute(addr, transID)
	if attr.attrType != stunAttrXorMappedAddr {
		t.Errorf("attr type: got %x want %x", attr.attrType, stunAttrXorMappedAddr)
	}
	if attr.length != 8 {
		t.Errorf("attr length: got %d want 8", attr.length)
	}
}

func TestAgentCredentials(t *testing.T) {
	agent := NewAgent(DefaultConfig(), RoleControlling)

	ufrag, pwd := agent.GetLocalCredentials()
	if len(ufrag) != 8 {
		t.Errorf("ufrag length: got %d want 8", len(ufrag))
	}
	if len(pwd) != 24 {
		t.Errorf("password length: got %d want 24", len(pwd))
	}

	agent.SetRemoteCredentials("remoteUfrag", "remotePassword")
	if agent.remoteUfrag != "remoteUfrag" {
		t.Error("remote ufrag not set")
	}
}

func TestGatherHostCandidates(t *testing.T) {
	agent := NewAgent(DefaultConfig(), RoleControlling)
	defer agent.Close()

	err := agent.gatherHostCandidates()
	if err != nil {
		t.Fatalf("gather host: %v", err)
	}

	candidates := agent.GetLocalCandidates()
	if len(candidates) == 0 {
		t.Fatal("expected at least one host candidate")
	}

	for _, c := range candidates {
		if c.Type != CandidateHost {
			t.Errorf("expected host type, got %s", c.Type)
		}
		if c.Port == 0 {
			t.Error("candidate port should not be 0")
		}
		if c.Priority == 0 {
			t.Error("candidate priority should not be 0")
		}
	}
}

func TestFormCandidatePairs(t *testing.T) {
	agentA := NewAgent(DefaultConfig(), RoleControlling)
	defer agentA.Close()
	agentB := NewAgent(DefaultConfig(), RoleControlled)
	defer agentB.Close()

	if err := agentA.gatherHostCandidates(); err != nil {
		t.Fatalf("gather A: %v", err)
	}
	if err := agentB.gatherHostCandidates(); err != nil {
		t.Fatalf("gather B: %v", err)
	}

	candA := agentA.GetLocalCandidates()
	candB := agentB.GetLocalCandidates()

	ufragA, pwdA := agentA.GetLocalCredentials()
	ufragB, pwdB := agentB.GetLocalCredentials()

	agentA.SetRemoteCredentials(ufragB, pwdB)
	agentA.AddRemoteCandidates(candB)
	agentB.SetRemoteCredentials(ufragA, pwdA)
	agentB.AddRemoteCandidates(candA)

	agentA.formCandidatePairs()
	agentB.formCandidatePairs()

	if len(agentA.checklist) == 0 {
		t.Fatal("agent A should have candidate pairs")
	}
	if len(agentB.checklist) == 0 {
		t.Fatal("agent B should have candidate pairs")
	}

	expected := len(candA) * len(candB)
	if len(agentA.checklist) != expected {
		t.Errorf("agent A pairs: got %d want %d", len(agentA.checklist), expected)
	}
}

// TestLocalICE runs a full ICE exchange between two agents on the same machine.
// This validates that same-LAN connectivity works with host candidates only.
func TestLocalICE(t *testing.T) {
	cfg := Config{
		STUNServers:       nil, // No STUN — host candidates only.
		CheckTimeout:      2 * time.Second,
		NominationTimeout: 5 * time.Second,
		MaxChecks:         20,
	}

	agentA := NewAgent(cfg, RoleControlling)
	defer agentA.Close()
	agentB := NewAgent(cfg, RoleControlled)
	defer agentB.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Gather host candidates only.
	if err := agentA.GatherCandidates(ctx); err != nil {
		t.Fatalf("gather A: %v", err)
	}
	if err := agentB.GatherCandidates(ctx); err != nil {
		t.Fatalf("gather B: %v", err)
	}

	candA := agentA.GetLocalCandidates()
	candB := agentB.GetLocalCandidates()
	t.Logf("Agent A: %d candidates, Agent B: %d candidates", len(candA), len(candB))

	if len(candA) == 0 || len(candB) == 0 {
		t.Fatal("both agents need at least one candidate")
	}

	// Exchange credentials and candidates.
	ufragA, pwdA := agentA.GetLocalCredentials()
	ufragB, pwdB := agentB.GetLocalCredentials()

	agentA.SetRemoteCredentials(ufragB, pwdB)
	agentA.AddRemoteCandidates(candB)
	agentB.SetRemoteCredentials(ufragA, pwdA)
	agentB.AddRemoteCandidates(candA)

	// Run checks concurrently.
	type result struct {
		pair *CandidatePair
		err  error
	}

	chA := make(chan result, 1)
	chB := make(chan result, 1)

	go func() {
		p, err := agentA.RunChecks(ctx)
		chA <- result{p, err}
	}()
	go func() {
		p, err := agentB.RunChecks(ctx)
		chB <- result{p, err}
	}()

	resA := <-chA
	resB := <-chB

	if resA.err != nil {
		t.Fatalf("agent A RunChecks: %v", resA.err)
	}
	if resB.err != nil {
		t.Fatalf("agent B RunChecks: %v", resB.err)
	}

	if resA.pair == nil {
		t.Fatal("agent A should have selected pair")
	}
	if resB.pair == nil {
		t.Fatal("agent B should have selected pair")
	}

	t.Logf("Agent A selected: %s", resA.pair.String())
	t.Logf("Agent B selected: %s", resB.pair.String())

	if !resA.pair.Nominated {
		t.Error("agent A pair should be nominated")
	}
	if !resB.pair.Nominated {
		t.Error("agent B pair should be nominated")
	}

	// Verify the selected sockets can exchange data.
	if resA.pair.Local.Conn == nil || resB.pair.Local.Conn == nil {
		t.Fatal("selected pair sockets should not be nil")
	}

	testMsg := []byte("ice-test-payload")
	remoteB := resB.pair.Local.addr()
	if _, err := resA.pair.Local.Conn.WriteToUDP(testMsg, remoteB); err != nil {
		t.Fatalf("send test message: %v", err)
	}

	buf := make([]byte, 1500)
	resB.pair.Local.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := resB.pair.Local.Conn.ReadFromUDP(buf)
	resB.pair.Local.Conn.SetReadDeadline(time.Time{})
	if err != nil {
		t.Fatalf("receive test message: %v", err)
	}
	if string(buf[:n]) != string(testMsg) {
		t.Errorf("received %q want %q", buf[:n], testMsg)
	}

	t.Log("ICE connectivity verified — direct data exchange works")
}

func TestCloseUnselected(t *testing.T) {
	agent := NewAgent(DefaultConfig(), RoleControlling)

	conn1, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	conn2, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}

	c1 := &Candidate{Conn: conn1, Address: net.ParseIP("127.0.0.1"), Port: conn1.LocalAddr().(*net.UDPAddr).Port}
	c2 := &Candidate{Conn: conn2, Address: net.ParseIP("127.0.0.1"), Port: conn2.LocalAddr().(*net.UDPAddr).Port}

	agent.localCandidates = []*Candidate{c1, c2}
	agent.selectedPair = &CandidatePair{Local: c1, Remote: &Candidate{}}

	if err := agent.CloseUnselected(); err != nil {
		t.Fatalf("CloseUnselected: %v", err)
	}

	// conn2 should be closed.
	_, err = conn2.WriteToUDP([]byte("test"), &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1})
	if err == nil {
		t.Error("conn2 should be closed")
	}

	conn1.Close() // clean up
}

func TestCandidateTypeString(t *testing.T) {
	tests := []struct {
		ct   CandidateType
		want string
	}{
		{CandidateHost, "host"},
		{CandidateServerReflexive, "srflx"},
		{CandidatePeerReflexive, "prflx"},
		{CandidateRelay, "relay"},
		{CandidateType(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.ct.String(); got != tt.want {
			t.Errorf("%d.String() = %q want %q", tt.ct, got, tt.want)
		}
	}
}

func TestParseCandidateType(t *testing.T) {
	tests := []struct {
		s    string
		want CandidateType
	}{
		{"host", CandidateHost},
		{"srflx", CandidateServerReflexive},
		{"prflx", CandidatePeerReflexive},
		{"relay", CandidateRelay},
		{"unknown", CandidateHost},
	}
	for _, tt := range tests {
		if got := parseCandidateType(tt.s); got != tt.want {
			t.Errorf("parseCandidateType(%q) = %v want %v", tt.s, got, tt.want)
		}
	}
}

// TestNominationNoRace ensures repeated USE-CANDIDATE nominations (the
// controlling agent retransmits them) don't race with the controlled agent
// formatting the nominated pair. Run with -race.
func TestNominationNoRace(t *testing.T) {
	agent := NewAgent(DefaultConfig(), RoleControlled)
	agent.SetLogger(func(string, ...any) {})

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	remote := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}
	local := &Candidate{Conn: conn, Address: net.ParseIP("127.0.0.1"), Port: conn.LocalAddr().(*net.UDPAddr).Port}
	pair := &CandidatePair{
		Local:  local,
		Remote: &Candidate{Address: remote.IP, Port: remote.Port},
		State:  PairStateSucceeded,
		Valid:  true,
	}
	agent.validPairs = []*CandidatePair{pair}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			agent.handleNomination(conn, remote)
		}
	}()

	got, err := agent.waitForNomination(context.Background())
	if err != nil {
		t.Fatalf("waitForNomination: %v", err)
	}
	<-done
	if got != pair {
		t.Fatal("unexpected nominated pair")
	}
	if !got.Nominated {
		t.Error("pair should be nominated")
	}
}

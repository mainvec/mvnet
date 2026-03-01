// Package ice implements ICE (Interactive Connectivity Establishment) for
// NAT traversal. It gathers host and server-reflexive candidates, performs
// connectivity checks via STUN, and nominates the best working pair.
package ice

import (
	"encoding/json"
	"fmt"
	"net"
)

// CandidateType represents the type of an ICE candidate.
type CandidateType int

const (
	CandidateHost            CandidateType = iota
	CandidateServerReflexive               // srflx
	CandidatePeerReflexive                 // prflx (not yet implemented)
	CandidateRelay                         // relay (not yet implemented)
)

func (ct CandidateType) String() string {
	switch ct {
	case CandidateHost:
		return "host"
	case CandidateServerReflexive:
		return "srflx"
	case CandidatePeerReflexive:
		return "prflx"
	case CandidateRelay:
		return "relay"
	default:
		return "unknown"
	}
}

func parseCandidateType(s string) CandidateType {
	switch s {
	case "host":
		return CandidateHost
	case "srflx":
		return CandidateServerReflexive
	case "prflx":
		return CandidatePeerReflexive
	case "relay":
		return CandidateRelay
	default:
		return CandidateHost
	}
}

// AgentRole represents the ICE agent role in negotiation.
type AgentRole int

const (
	RoleControlling AgentRole = iota
	RoleControlled
)

func (r AgentRole) String() string {
	switch r {
	case RoleControlling:
		return "controlling"
	case RoleControlled:
		return "controlled"
	default:
		return "unknown"
	}
}

// PairState represents the state of a candidate pair connectivity check.
type PairState int

const (
	PairStateWaiting PairState = iota
	PairStateInProgress
	PairStateSucceeded
	PairStateFailed
	PairStateFrozen
)

func (ps PairState) String() string {
	switch ps {
	case PairStateWaiting:
		return "waiting"
	case PairStateInProgress:
		return "in-progress"
	case PairStateSucceeded:
		return "succeeded"
	case PairStateFailed:
		return "failed"
	case PairStateFrozen:
		return "frozen"
	default:
		return "unknown"
	}
}

// Candidate represents an ICE connectivity candidate.
type Candidate struct {
	Type        CandidateType
	Foundation  string
	Component   int
	Priority    uint32
	Address     net.IP
	Port        int
	RelatedIP   net.IP
	RelatedPort int
	Conn        *net.UDPConn // Bound UDP socket. Nil for remote candidates.
}

func (c *Candidate) String() string {
	return fmt.Sprintf("%s %s:%d (priority: %d)", c.Type, c.Address, c.Port, c.Priority)
}

// Close closes the candidate's UDP socket.
func (c *Candidate) Close() error {
	if c.Conn != nil {
		return c.Conn.Close()
	}
	return nil
}

// addr returns the candidate's address as *net.UDPAddr.
func (c *Candidate) addr() *net.UDPAddr {
	return &net.UDPAddr{IP: c.Address, Port: c.Port}
}

// calculatePriority computes RFC 5245 priority for this candidate.
func (c *Candidate) calculatePriority() {
	var typePref uint32
	switch c.Type {
	case CandidateHost:
		typePref = 126
	case CandidateServerReflexive:
		typePref = 100
	case CandidatePeerReflexive:
		typePref = 110
	case CandidateRelay:
		typePref = 0
	}
	localPref := uint32(65535)
	componentID := uint32(c.Component)
	c.Priority = (1<<24)*typePref + (1<<8)*localPref + (256 - componentID)
}

// candidateJSON is the JSON representation used for signaling exchange.
type candidateJSON struct {
	Type        string `json:"type"`
	Foundation  string `json:"foundation"`
	Component   int    `json:"component"`
	Priority    uint32 `json:"priority"`
	Address     string `json:"address"`
	Port        int    `json:"port"`
	RelatedAddr string `json:"relatedAddr,omitempty"`
	RelatedPort int    `json:"relatedPort,omitempty"`
}

// MarshalJSON implements json.Marshaler for signaling exchange.
func (c Candidate) MarshalJSON() ([]byte, error) {
	j := candidateJSON{
		Type:       c.Type.String(),
		Foundation: c.Foundation,
		Component:  c.Component,
		Priority:   c.Priority,
		Address:    c.Address.String(),
		Port:       c.Port,
	}
	if c.RelatedIP != nil {
		j.RelatedAddr = c.RelatedIP.String()
		j.RelatedPort = c.RelatedPort
	}
	return json.Marshal(j)
}

// UnmarshalJSON implements json.Unmarshaler for signaling exchange.
func (c *Candidate) UnmarshalJSON(data []byte) error {
	var j candidateJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	c.Type = parseCandidateType(j.Type)
	c.Foundation = j.Foundation
	c.Component = j.Component
	c.Priority = j.Priority
	c.Address = net.ParseIP(j.Address)
	c.Port = j.Port
	if j.RelatedAddr != "" {
		c.RelatedIP = net.ParseIP(j.RelatedAddr)
		c.RelatedPort = j.RelatedPort
	}
	return nil
}

// CandidatePair represents a local-remote candidate pair for connectivity checking.
type CandidatePair struct {
	Local      *Candidate
	Remote     *Candidate
	Priority   uint64
	State      PairState
	Nominated  bool
	Foundation string
	Valid      bool
}

func (cp *CandidatePair) String() string {
	return fmt.Sprintf("Pair[%s -> %s] (priority: %d, state: %s, nominated: %t)",
		cp.Local.String(), cp.Remote.String(), cp.Priority, cp.State, cp.Nominated)
}

// calculatePriority computes RFC 5245 candidate pair priority.
func (cp *CandidatePair) calculatePriority(controlling bool) {
	var G, D uint64
	if controlling {
		G = uint64(cp.Local.Priority)
		D = uint64(cp.Remote.Priority)
	} else {
		G = uint64(cp.Remote.Priority)
		D = uint64(cp.Local.Priority)
	}
	cp.Priority = (1<<32)*min(G, D) + 2*max(G, D)
	if G > D {
		cp.Priority++
	}
}

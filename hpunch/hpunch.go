package hpunch

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/mainvec/mvnet/nat"
)

// NATType represents the different types of NAT behavior
type HPuncherState int

const (
	HPPuncherNA       HPuncherState = iota // Not Available
	HPPuncherReady                         // Ready for hole punching
	HPPuncherPunching                      // Currently punching holes
	HPPuncherFailed                        // Hole punching failed
	HPPuncherSuccess                       // Hole punching succeeded
)

type HolePuncher struct { // Add any required fields here

	conn          *net.UDPConn // UDP connection for hole punching
	natType       nat.NATType
	stunResult    *nat.STUNResult
	state         HPuncherState // Current state of the hole puncher
	localAddr     *net.UDPAddr  // Local address used for hole punching
	remoteAddr    *net.UDPAddr  // Remote address to punch holes to
	hpMsgReceived bool
}

func NewHolePuncher(ctx context.Context) (*HolePuncher, error) {
	//detect NAT type and initialize the HolePuncher
	localAddr := &net.UDPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: 0,
	}

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP connection: %w", err)
	}
	detector, err := nat.NewNATDetectorWithConn(conn, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create NAT detector: %w", err)
	}

	// Detect NAT type
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	natType, results, err := detector.DetectNATType(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to detect NAT type: %w", err)
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
	//	}
	return &HolePuncher{
		natType:    natType,
		stunResult: stunResult,
		conn:       conn,
		state:      HPPuncherReady,
		localAddr:  conn.LocalAddr().(*net.UDPAddr),
	}, nil
}

func (hp *HolePuncher) GetNATType() nat.NATType {
	return hp.natType
}

func (hp *HolePuncher) CanPunch() bool {
	// Check if the NAT type is suitable for hole punching
	return hp.natType == nat.NATTypeOpen || hp.natType == nat.NATTypeEasyNAT
}

func (hp *HolePuncher) LocalAddr() *net.UDPAddr {
	return hp.localAddr
}
func (hp *HolePuncher) GetMappedAddress() (*net.UDPAddr, error) {
	if hp.stunResult == nil {
		return nil, fmt.Errorf("no STUN result available")
	}
	return hp.stunResult.MappedAddr, nil
}

func (hp *HolePuncher) State() HPuncherState {
	return hp.state
}

func (hp *HolePuncher) StartPunching(ctx context.Context, remoteAddr *net.UDPAddr) error {
	if !hp.CanPunch() {
		slog.Warn("Hole punching not supported for this NAT type. Unlikely to succeed.", "natType", hp.natType)
		//return fmt.Errorf("hole punching not supported for NAT type: %s", hp.natType)
	}

	hp.state = HPPuncherPunching
	hp.remoteAddr = remoteAddr
	holePunched := make(chan bool)

	go hp.startReceiving(holePunched)
	//assuming remotePeer using same port as locl peer, i.e. rxport
	go hp.startHolePunching(remoteAddr, holePunched)

	select {
	case <-ctx.Done():
		hp.state = HPPuncherFailed
		slog.Error("hole punching timed out", "remoteAddr", remoteAddr.String())
		return fmt.Errorf("hole punching timed out: %w", ctx.Err())
	case <-holePunched:
		if !hp.hpMsgReceived {
			hp.state = HPPuncherFailed
			slog.Error("hole punching failed, no message received from remote peer", "remoteAddr", remoteAddr.String())
			return fmt.Errorf("hole punching failed, no message received from remote peer: %s", remoteAddr.String())
		}
		hp.state = HPPuncherSuccess
		slog.Info("Hole punching successful", "remoteAddr", remoteAddr.String())
		return nil
	}

}

func (hp *HolePuncher) startReceiving(holePunched chan bool) {
	b := make([]byte, 1024)
	firstMsgReceived := false
	slog.Info("started receiving.", "listeningOn", hp.conn.LocalAddr().String())

	for hp.state == HPPuncherPunching {

		hp.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, raddr, err := hp.conn.ReadFromUDP(b)
		if err != nil {
			//check if error is timeout
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			} else {
				slog.Error("error reading from UDP", "error", err)

				return
			}

		}
		if n < 1 {
			continue
		}
		if !raddr.IP.Equal(hp.remoteAddr.IP) || (raddr.Port != hp.remoteAddr.Port) {
			slog.Warn("Received message from unexpected address", "expected", hp.remoteAddr, "received", raddr)
			continue
		}
		if !firstMsgReceived {
			firstMsgReceived = true
			hp.hpMsgReceived = true
			close(holePunched)
			return

		}
	}
}

func (hp *HolePuncher) startHolePunching(radd *net.UDPAddr, holePunched chan bool) {
	punchMsg := []byte("PUNCH")
	msgNum := 1

	for {

		hp.conn.SetWriteDeadline(time.Now().Add(5 * time.Second)) // Short write timeout
		n, err := hp.conn.WriteToUDP(punchMsg, radd)
		if err != nil {
			//chekc if timeout
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				slog.Warn("write timeout, retrying", "msgNum", msgNum)
				continue
			} else {
				slog.Error("error writing to UDP", "error", err)
				hp.state = HPPuncherFailed
				close(holePunched)
				return
			}
		}
		if n > 1 {
			fmt.Printf("P%v ", msgNum)
		}

		select {
		case <-holePunched:
			slog.Info("stopping hole punching.")
			return
		default:
			time.Sleep(time.Millisecond * 500)
			msgNum++
			continue
		}
	}
}

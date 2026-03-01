package punch_test

import (
	"net"
	"strconv"
	"testing"

	"github.com/mainvec/mvnet/punch"
)

func TestSimpleLocalUDPPairPunch(t *testing.T) {
	peer1Conn, peer1Address := prepareLocalUDPConnection(t)
	peer2Conn, peer2Address := prepareLocalUDPConnection(t)

	defer peer1Conn.Close()
	defer peer2Conn.Close()

	config := punch.DefaultConfig()
	hp1, err := punch.NewHolePuncherWithConn(peer1Conn, peer2Address, config, false)
	if err != nil {
		t.Fatalf("failed to create HolePuncher for peer1: %v", err)
	}
	defer hp1.Close()

	hp2, err := punch.NewHolePuncherWithConn(peer2Conn, peer1Address, config, false)
	if err != nil {
		t.Fatalf("failed to create HolePuncher for peer2: %v", err)
	}
	defer hp2.Close()
	go hp1.Start()
	go hp2.Start()
	err = hp1.WaitForCompletion()
	if err != nil {
		t.Errorf("HolePuncher for peer1 failed: %v", err)
	}
	err = hp2.WaitForCompletion()
	if err != nil {
		t.Errorf("HolePuncher for peer2 failed: %v", err)
	}

	if hp1.GetState() != punch.StateSuccessful {
		t.Errorf("HolePuncher for peer1 failed with state: %d", hp1.GetState())
	}

	if hp2.GetState() != punch.StateSuccessful {
		t.Errorf("HolePuncher for peer2 failed with state: %d", hp2.GetState())
	}
	conn1 := hp1.GetConnection()
	if conn1 == nil {
		t.Error("HolePuncher connection for peer1 is nil")
	}
	conn2 := hp2.GetConnection()
	if conn2 == nil {
		t.Error("HolePuncher connection for peer2 is nil")
	}

}

func prepareLocalUDPConnection(t *testing.T) (*net.UDPConn, string) {
	t.Helper()
	localAddr := &net.UDPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: 0,
	}

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		t.Fatalf("failed to create UDP connection: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	address := "127.0.0.1:" + strconv.Itoa(port)
	return conn, address
}

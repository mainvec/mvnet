package stun_test

import (
	"net"
	"testing"

	"github.com/mainvec/mvnet/stun"
)

type args struct {
	serverAddr string
}

var tests = []struct {
	name      string
	args      args
	wantIP    bool
	wantPort  bool
	wantValid bool
	wantErr   bool
}{
	{
		name: "Valid STUN Server",
		args: args{
			serverAddr: "stun.l.google.com:19302",
		},
		wantPort:  true,
		wantIP:    true,
		wantValid: true,
		wantErr:   false,
	},
	{
		name: "Invalid STUN Server",
		args: args{
			serverAddr: "invalid.stun.server:12345",
		},
		wantPort:  false,
		wantIP:    false,
		wantValid: false,
		wantErr:   true,
	},
	{
		name: "Empty STUN Server",
		args: args{
			serverAddr: "",
		},
		wantPort:  false,
		wantIP:    false,
		wantValid: false,
		wantErr:   true,
	},
	{
		name: "Non-STUN Server",
		args: args{
			serverAddr: "google.com:80",
		},
		wantPort:  false,
		wantIP:    false,
		wantValid: false,
		wantErr:   true,
	},
}

func TestQuerySTUNServer(t *testing.T) {

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := stun.QuerySTUNServer(tt.args.serverAddr)
			gotIP := result.IP
			gotPort := result.Port
			isValid := result.Valid

			if (err != nil) != tt.wantErr {
				t.Errorf("QuerySTUNServer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (gotIP != nil) != tt.wantIP {
				t.Errorf("QuerySTUNServer() gotIP = %v, want %v", gotIP != nil, tt.wantIP)
			}
			if (gotPort != 0) != tt.wantPort {
				t.Errorf("QuerySTUNServer() gotPort = %v, want %v", gotPort != 0, tt.wantPort)
			}
			if tt.wantIP && gotIP == nil {
				t.Errorf("QuerySTUNServer() gotIP = nil, expected a valid IP")
			}
			if tt.wantPort && gotPort == 0 {
				t.Errorf("QuerySTUNServer() gotPort = 0, expected a valid port")
			}
			if isValid != tt.wantValid {
				t.Errorf("QuerySTUNServer() gotValid = %v, want %v", isValid, tt.wantValid)
			}
		})
	}
}

func TestQuerySTUNServerWithConn(t *testing.T) {

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			localAddr := &net.UDPAddr{
				IP:   net.ParseIP("0.0.0.0"),
				Port: 0,
			}

			conn, err := net.ListenUDP("udp", localAddr)
			if err != nil {
				t.Fatalf("failed to create UDP connection: %v", err)
			}
			defer conn.Close()
			result, err := stun.QuerySTUNServerWithConn(conn, tt.args.serverAddr)
			gotIP := result.IP
			gotPort := result.Port
			isValid := result.Valid
			if (err != nil) != tt.wantErr {
				t.Errorf("QuerySTUNServer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (gotIP != nil) != tt.wantIP {
				t.Errorf("QuerySTUNServer() gotIP = %v, want %v", gotIP != nil, tt.wantIP)
			}
			if (gotPort != 0) != tt.wantPort {
				t.Errorf("QuerySTUNServer() gotPort = %v, want %v", gotPort != 0, tt.wantPort)
			}
			if tt.wantIP && gotIP == nil {
				t.Errorf("QuerySTUNServer() gotIP = nil, expected a valid IP")
			}
			if tt.wantPort && gotPort == 0 {
				t.Errorf("QuerySTUNServer() gotPort = 0, expected a valid port")
			}
			if isValid != tt.wantValid {
				t.Errorf("QuerySTUNServer() gotValid = %v, want %v", isValid, tt.wantValid)
			}
		})
	}
}

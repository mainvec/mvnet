package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/mainvec/mvnet/speedtest"
)

func main() {

	config := speedtest.Config{
		TestDataSize: 100 * 1024 * 1024, // 20 MB
		BufferSize:   6 * 1024,          // 128 KB buffer
		Duration:     20 * time.Second,  // 15 second limit
	}

	// inMemoryConfig := speedtest.Config{
	// 	TestDataSize: 10 * 1024 * 1024, // 10 MB
	// 	BufferSize:   64 * 1024,        // 64 KB buffer
	// 	Duration:     5 * time.Second,  // 5 second limit
	// }
	// tcpConfig := speedtest.Config{
	// 	TestDataSize: 5 * 1024 * 1024,  // 5 MB
	// 	BufferSize:   32 * 1024,        // 32 KB buffer
	// 	Duration:     10 * time.Second, // 10 second limit
	// }
	// unixConfig := speedtest.Config{
	// 	TestDataSize: 20 * 1024 * 1024, // 20 MB
	// 	BufferSize:   128 * 1024,       // 128 KB buffer
	// 	Duration:     15 * time.Second, // 15 second limit
	// }
	// Example 1: Test with in-memory buffer
	fmt.Println("=== In-Memory Buffer Test ===")

	testInMemory(config)

	fmt.Println("\n=== TCP Connection Test ===")

	testTCP(config)

	fmt.Println("\n=== Unix Socket Test ===")

	testUnixSocket(config)
}

func testInMemory(config speedtest.Config) {
	// Create a buffer that acts as both reader and writer
	buffer := &bytes.Buffer{}

	// Create speed test instance
	st := speedtest.New(buffer, buffer, config)

	// Run send test
	fmt.Println("Running test...")
	result, err := st.RunBidirectionalTest()
	if err != nil {
		log.Printf("Send test failed: %v", err)
		return
	}

	fmt.Println(result.String())
}

func testTCP(config speedtest.Config) {
	// Start a simple echo server
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Printf("Failed to start server: %v", err)
		return
	}
	defer listener.Close()

	// Simple echo server
	srcConnChan := make(chan net.Conn)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}
			srcConnChan <- conn

		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Connect to server
	conn, err := net.Dial("tcp", ":8080")
	if err != nil {
		log.Printf("Failed to connect: %v", err)
		return
	}
	defer conn.Close()

	srcConn := <-srcConnChan

	// Create speed test instance using the TCP connection
	st := speedtest.New(conn, srcConn, config)

	// Run bidirectional test
	fmt.Println("Running bidirectional test...")
	result, err := st.RunBidirectionalTest()
	if err != nil {
		log.Printf("Bidirectional test failed: %v", err)
		return
	}

	fmt.Println(result.String())
}

func testUnixSocket(config speedtest.Config) {
	socketPath := "/tmp/speedtest.sock"

	// Clean up any existing socket
	os.Remove(socketPath)
	defer os.Remove(socketPath)

	// Create Unix socket pair
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Printf("Failed to create Unix socket: %v", err)
		return
	}
	if err != nil {
		log.Printf("Failed to start server: %v", err)
		return
	}
	defer listener.Close()

	// Simple echo server
	srcConnChan := make(chan net.Conn)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}
			srcConnChan <- conn

		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Connect to server
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		log.Printf("Failed to connect: %v", err)
		return
	}
	defer conn.Close()

	srcConn := <-srcConnChan

	// Create speed test instance using the TCP connection
	st := speedtest.New(conn, srcConn, config)

	// Run bidirectional test
	fmt.Println("Running bidirectional test...")
	result, err := st.RunBidirectionalTest()
	if err != nil {
		log.Printf("Bidirectional test failed: %v", err)
		return
	}

	fmt.Println(result.String())
}

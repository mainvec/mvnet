package speedtest

import (
	"crypto/rand"
	"fmt"
	"io"
	"time"
)

// Config holds the configuration for the speed test
type Config struct {
	// TestDataSize is the amount of data to send in bytes
	TestDataSize int64
	// BufferSize is the size of the buffer for reading/writing operations
	BufferSize int
	// Duration is the maximum duration for the test (optional, 0 means no limit)
	Duration time.Duration
}

// Result contains the results of the speed test
type Result struct {
	// BytesSent is the total number of bytes sent
	BytesSent int64
	// BytesReceived is the total number of bytes received
	BytesReceived int64
	// Duration is the actual time taken for the test
	Duration time.Duration
	// SendThroughput is the sending speed in bytes per second
	SendThroughput float64
	// ReceiveThroughput is the receiving speed in bytes per second
	ReceiveThroughput float64
	// SendThroughputMbps is the sending speed in Mbps
	SendThroughputMbps float64
	// ReceiveThroughputMbps is the receiving speed in Mbps
	ReceiveThroughputMbps float64
}

// SpeedTest represents a speed test instance
type SpeedTest struct {
	config Config
	writer io.Writer
	reader io.Reader
}

// New creates a new SpeedTest instance
func New(writer io.Writer, reader io.Reader, config Config) *SpeedTest {
	// Set default buffer size if not specified
	if config.BufferSize <= 0 {
		config.BufferSize = 64 * 1024 // 64KB default
	}

	return &SpeedTest{
		config: config,
		writer: writer,
		reader: reader,
	}
}

// RunSendTest performs a send-only speed test
func (st *SpeedTest) RunSendTest() (*Result, error) {

	// Generate test data
	testData := make([]byte, st.config.BufferSize)
	if _, err := rand.Read(testData); err != nil {
		return nil, fmt.Errorf("failed to generate test data: %w", err)
	}
	startTime := time.Now()

	var totalSent int64
	remaining := st.config.TestDataSize

	for remaining > 0 {
		// Check duration limit if set
		if st.config.Duration > 0 && time.Since(startTime) >= st.config.Duration {
			break
		}

		// Determine how much to send in this iteration
		toSend := int64(len(testData))
		if remaining < toSend {
			toSend = remaining
		}

		// Send data
		n, err := st.writer.Write(testData[:toSend])
		if err != nil {
			return nil, fmt.Errorf("failed to write data: %w", err)
		}

		totalSent += int64(n)
		remaining -= int64(n)
	}

	duration := time.Since(startTime)
	throughput := float64(totalSent) / duration.Seconds()
	throughputMbps := (throughput * 8) / (1024 * 1024) // Convert to Mbps

	return &Result{
		BytesSent:          totalSent,
		Duration:           duration,
		SendThroughput:     throughput,
		SendThroughputMbps: throughputMbps,
	}, nil
}

// RunReceiveTest performs a receive-only speed test
func (st *SpeedTest) RunReceiveTest() (*Result, error) {
	startTime := time.Now()

	buffer := make([]byte, st.config.BufferSize)
	var totalReceived int64
	remaining := st.config.TestDataSize

	for remaining > 0 {
		// Check duration limit if set
		if st.config.Duration > 0 && time.Since(startTime) >= st.config.Duration {
			break
		}

		// Read data
		n, err := st.reader.Read(buffer)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to read data: %w", err)
		}

		totalReceived += int64(n)
		remaining -= int64(n)
	}

	duration := time.Since(startTime)
	throughput := float64(totalReceived) / duration.Seconds()
	throughputMbps := (throughput * 8) / (1024 * 1024) // Convert to Mbps

	return &Result{
		BytesReceived:         totalReceived,
		Duration:              duration,
		ReceiveThroughput:     throughput,
		ReceiveThroughputMbps: throughputMbps,
	}, nil
}

// RunBidirectionalTest performs a bidirectional speed test
func (st *SpeedTest) RunBidirectionalTest() (*Result, error) {
	startTime := time.Now()

	// Channels for coordinating send and receive operations
	sendDone := make(chan *Result, 1)
	receiveDone := make(chan *Result, 1)
	sendErr := make(chan error, 1)
	receiveErr := make(chan error, 1)

	// Start sending in a goroutine
	go func() {
		result, err := st.RunSendTest()
		if err != nil {
			sendErr <- err
			return
		}
		sendDone <- result
	}()

	// Start receiving in a goroutine
	go func() {
		result, err := st.RunReceiveTest()
		if err != nil {
			receiveErr <- err
			return
		}
		receiveDone <- result
	}()

	// Wait for both operations to complete
	var sendResult, receiveResult *Result
	var err error

	for i := 0; i < 2; i++ {
		select {
		case result := <-sendDone:
			sendResult = result
		case result := <-receiveDone:
			receiveResult = result
		case err = <-sendErr:
			return nil, fmt.Errorf("send error: %w", err)
		case err = <-receiveErr:
			return nil, fmt.Errorf("receive error: %w", err)
		}
	}

	duration := time.Since(startTime)

	// Combine results
	combinedResult := &Result{
		Duration: duration,
	}

	if sendResult != nil {
		combinedResult.BytesSent = sendResult.BytesSent
		combinedResult.SendThroughput = sendResult.SendThroughput
		combinedResult.SendThroughputMbps = sendResult.SendThroughputMbps
	}

	if receiveResult != nil {
		combinedResult.BytesReceived = receiveResult.BytesReceived
		combinedResult.ReceiveThroughput = receiveResult.ReceiveThroughput
		combinedResult.ReceiveThroughputMbps = receiveResult.ReceiveThroughputMbps
	}

	return combinedResult, nil
}

// String returns a formatted string representation of the result
func (r *Result) String() string {
	return fmt.Sprintf(
		"Speed Test Results:\n"+
			"Duration: %v\n"+
			"Bytes Sent: %d (%.2f MB)\n"+
			"Bytes Received: %d (%.2f MB)\n"+
			"Send Throughput: %.2f MB/s (%.2f Mbps)\n"+
			"Receive Throughput: %.2f MB/s (%.2f Mbps)",
		r.Duration,
		r.BytesSent, float64(r.BytesSent)/(1024*1024),
		r.BytesReceived, float64(r.BytesReceived)/(1024*1024),
		r.SendThroughput/(1024*1024), r.SendThroughputMbps,
		r.ReceiveThroughput/(1024*1024), r.ReceiveThroughputMbps,
	)
}

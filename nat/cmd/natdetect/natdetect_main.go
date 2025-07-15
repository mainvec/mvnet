package main

import (
	"context"
	"fmt"
	"time"

	"github.com/mainvec/mvnet/nat"
)

// Example usage
func main() {
	fmt.Println("NAT Type Detection Tool")
	fmt.Println("======================")

	// Create detector
	detector, err := nat.NewNATDetector(nil, nil)
	if err != nil {
		panic(err)
	}
	defer detector.Close()

	// Detect NAT type
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	natType, results, err := detector.DetectNATType(ctx)
	if err != nil {
		panic(err)
	}

	// Print results
	detector.PrintDetailedResults(natType, results)

	// Show recommended strategies
	strategies := detector.GetNATTraversalStrategy(natType)
	fmt.Println("\nRecommended NAT Traversal Strategies:")
	fmt.Println("------------------------------------")
	for i, strategy := range strategies {
		fmt.Printf("%d. %s\n", i+1, strategy)
	}
}

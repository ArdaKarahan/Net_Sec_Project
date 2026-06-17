package main

import (
	"fmt"
	"os"
	"time"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func main() {
	nodeID := os.Getenv("NODE_ID")
	mode := os.Getenv("BLOCKCHAIN_MODE")
	peers := os.Getenv("PEERS")

	fmt.Printf("=== Starting Protocol Simulation: %s ===\n", nodeID)
	fmt.Printf("Cryptographic Engine Mode: %s\n", mode)
	fmt.Printf("Connected Peer Addresses: %s\n", peers)

	// Pulling the underlying C library version string to verify successful linking
	fmt.Println("Initializing Open Quantum Safe validation...")
	version := oqs.LiboqsVersion()
	fmt.Printf("OQS Status: Ready and Enabled. (liboqs version: %s)\n", version)

	// Keep the container alive to simulate a running node process
	for {
		time.Sleep(10 * time.Minute)
	}
}

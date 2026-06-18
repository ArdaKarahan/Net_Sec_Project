package main

import (
	"fmt"
	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func main() {
	fmt.Println("=== Enabled KEMs ===")
	for _, name := range oqs.EnabledKEMs() {
		fmt.Println(" ", name)
	}
	fmt.Println("=== Enabled Sigs ===")
	for _, name := range oqs.EnabledSigs() {
		fmt.Println(" ", name)
	}
}

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"sfs/internal/attacksurface"
)

func main() {
	target := "https://scanme.sh"
	if len(os.Args) > 1 {
		target = os.Args[1]
	}
	
	log.Printf("Menguji Attack Surface Discovery pada target: %s", target)
	log.Printf("Mohon tunggu, crawler sedang berjalan...")
	
	result, err := attacksurface.Discover(target, 1) // max depth 1 agar cepat
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	b, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println("\n=== HASIL DISCOVERY ===")
	fmt.Println(string(b))
}

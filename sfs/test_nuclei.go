package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"sfs/internal/vulnerability"
)

func main() {
	target := "scanme.sh"
	if len(os.Args) > 1 {
		target = os.Args[1]
	}

	log.Printf("Menguji Vulnerability Scanner (Nuclei) pada target: %s", target)
	log.Printf("Mohon tunggu, proses ini memakan waktu karena akan memuat ribuan template dan melakukan pemindaian...")

	results, err := vulnerability.Scan([]string{target})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	b, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println("\n=== HASIL VULNERABILITY SCAN ===")
	fmt.Println(string(b))
}

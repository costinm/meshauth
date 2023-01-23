package main

import (
	"log"

	"github.com/costinm/meshauth"
)

// Minimal service using only meshauth to validate the functionality.
//
//

func main() {
	// Auto-detect the environment and setup mesh certificates.
	ma, err := meshauth.FromEnv(nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(ma)
}

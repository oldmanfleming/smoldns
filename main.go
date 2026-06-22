package main

import (
	"log"
	"os"
)

func main() {
	name := os.Args[1:2][0]
	packet, err := executeQuery("198.41.0.4:53", name, TypeA)
	if err != nil {
		log.Fatalf("failed to execute query: %v", err)
	}
	log.Println(packet.toString())
}

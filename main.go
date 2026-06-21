package main

import (
	"log"
	"os"
)

func main() {
	name := os.Args[1:2][0]
	packet, err := executeQuery("8.8.8.8:53", name, 1)
	if err != nil {
		log.Fatalf("failed to execute query: %v", err)
	}
	log.Println(packet.toString())
}

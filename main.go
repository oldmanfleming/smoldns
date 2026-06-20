package main

import (
	"bytes"
	"log"
	"net"
	"os"
)

func main() {
	name := os.Args[1:2][0]
	query, err := buildQuery(name, 1)
	if err != nil {
		log.Fatalf("failed to build query: %v", err)
	}
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		log.Fatalf("failed to open connection: %v", err)
	}
	defer conn.Close()
	_, err = conn.Write(query)
	if err != nil {
		log.Fatalf("failed to write query: %v", err)
	}
	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		log.Fatalf("failed to read response: %v", err)
	}
	reader := bytes.NewReader(resp[:n])
	packet, err := parsePacket(reader)
	if err != nil {
		log.Fatalf("failed to parse packet: %v", err)
	}
	if len(packet.answers) == 0 {
		log.Fatalf("failed to get an answer")
	}
	answer := packet.answers[0]
	log.Printf("name: %s", answer.Name)
	log.Printf("ip address: %v", answer.Data)
}

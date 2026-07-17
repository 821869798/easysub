package util

import (
	"log"
	"testing"
)

func TestRegGetMatch(t *testing.T) {
	ssr := "example.com:8080:origin:aes-256-cfb:plain:password123"
	pattern := `(\S+):(\d+):(\S+):(\S+):(\S+):(\S+)`

	var server, port, protocol, method, obfs, password string

	err := RegGetMatch(ssr, pattern, &server, &port, &protocol, &method, &obfs, &password)
	if err != nil {
		log.Println("Error:", err)
		return
	}

	log.Println("Server:", server)
	log.Println("Port:", port)
	log.Println("Protocol:", protocol)
	log.Println("Method:", method)
	log.Println("Obfs:", obfs)
	log.Println("Password:", password)
}

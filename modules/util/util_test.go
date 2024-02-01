package util

import (
	"fmt"
	"testing"
)

func TestRegGetMatch(t *testing.T) {
	ssr := "example.com:8080:origin:aes-256-cfb:plain:password123"
	pattern := `(\S+):(\d+):(\S+):(\S+):(\S+):(\S+)`

	var server, port, protocol, method, obfs, password string

	err := RegGetMatch(ssr, pattern, &server, &port, &protocol, &method, &obfs, &password)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Server:", server)
	fmt.Println("Port:", port)
	fmt.Println("Protocol:", protocol)
	fmt.Println("Method:", method)
	fmt.Println("Obfs:", obfs)
	fmt.Println("Password:", password)
}

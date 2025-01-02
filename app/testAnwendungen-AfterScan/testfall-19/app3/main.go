package main

import (
	"log"

	"github.com/refoo0/sca-trnsitiv/websocketserver"
)

func main() {
	// Create a new WebSocket server on port 8080
	server := websocketserver.NewWebSocketServer("8080")

	// Start the WebSocket server
	err := server.Start()
	if err != nil {
		log.Fatal("error starting WebSocket server:", err)
	}

}

package main

import (
	"fmt"
	"log"
	"net/http"
	"testing"

	"github.com/gorilla/websocket"
)

// WebSocket Upgrader mit unsicherer Konfiguration
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// vulnerability: allow all origins
		return true
	},
}

func echo(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("error upgrading connection:", err)
		return
	}
	defer conn.Close()

	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			log.Println("read error:", err)
			break
		}
		fmt.Printf("Message received: %s\n", message)

		err = conn.WriteMessage(messageType, message)
		if err != nil {
			log.Println("write error:", err)
			break
		}
	}
}

func TestMain(m *testing.M) {
	fmt.Println("Starting server on port 8080")

	http.HandleFunc("/ws", echo)

	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("Server-error:", err)
	}
}

package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/refoo0/sca-trnsitiv/websocketserver"

	"github.com/refoo0/sca-trnsitiv/jwthelper"

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

func main() {
	server := websocketserver.NewWebSocketServer("8080")

	// Start the WebSocket server
	err := server.Start()
	if err != nil {
		log.Fatal("error starting WebSocket server:", err)
	}

	fmt.Println("Starting server on port 8080")

	http.HandleFunc("/ws", echo)

	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("Server-error:", err)
	}

	// install the WebSocket server
	secretKey := "supersecretkey"
	jwtService := jwthelper.NewJWTService(secretKey)

	//  Generate a new token"
	token, err := jwtService.GenerateToken("testuser", true, 72) // 72 hours
	if err != nil {
		log.Fatalf("error signing token: %v", err)
	}
	fmt.Println("✅ Token successfully signed:", token)

	//  Token validition
	claims, err := jwtService.ValidateToken(token)
	if err != nil {
		log.Fatalf("error verifying token: %v", err)
	}

	//  Print the claims
	fmt.Println("✅ Token successfully verified!")
	fmt.Printf("👤 User: %v\n", claims["user"])
	fmt.Printf("🔐 Admin rights: %v\n", claims["admin"])
}

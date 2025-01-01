package main

import (
	"fmt"
	"log"

	"github.com/refoo0/sca/app/apps/sca-trnsitiv/jwthelper"
	"github.com/refoo0/sca/app/apps/sca-trnsitiv/websocketserver"
)

func main() {
	// Create a new WebSocket server on port 8080
	server := websocketserver.NewWebSocketServer("8080")

	// Start the WebSocket server
	err := server.Start()
	if err != nil {
		log.Fatal("error starting WebSocket server:", err)
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

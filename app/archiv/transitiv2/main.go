package main

import (
	"fmt"
	"log"

	"github.com/refoo0/sca-trnsitiv/jwthelper"
	"github.com/refoo0/sca-trnsitiv/websocketserver"
)

func main() {
	// Create a new WebSocket server on port 8080
	server := websocketserver.NewWebSocketServer("8080")

	// Start the WebSocket server
	err := server.Start()
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}

	// 1️⃣ Initialisiere den JWT-Service mit dem geheimen Schlüssel
	secretKey := "supersecretkey"
	jwtService := jwthelper.NewJWTService(secretKey)

	// 2️⃣ Erstelle ein Token für den Benutzer "testuser"
	token, err := jwtService.GenerateToken("testuser", true, 72) // 72 Stunden (3 Tage) Gültigkeit
	if err != nil {
		log.Fatalf("Fehler beim Generieren des Tokens: %v", err)
	}
	fmt.Println("✅ Generiertes Token:", token)

	// 3️⃣ Token validieren (in einer realen Anwendung würde dieses Token aus einem HTTP-Request stammen)
	claims, err := jwtService.ValidateToken(token)
	if err != nil {
		log.Fatalf("Fehler beim Validieren des Tokens: %v", err)
	}

	// 4️⃣ Benutzerinformationen anzeigen
	fmt.Println("✅ Token erfolgreich validiert!")
	fmt.Printf("👤 Benutzer: %s\n", claims["user"])
	fmt.Printf("🔑 Admin-Rechte: %v\n", claims["admin"])
}

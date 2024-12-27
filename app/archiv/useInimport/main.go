package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/websocket" // Eine bekannte Bibliothek, die in der Vergangenheit Schwachstellen hatte
)

// WebSocket Upgrader mit unsicherer Konfiguration
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Sicherheitslücke: Dies erlaubt Verbindungen von jeder Quelle (Cross-Origin Request Forgery, CSRF)
		return true
	},
}

func echo(w http.ResponseWriter, r *http.Request) {
	// Upgrade der HTTP-Verbindung auf eine WebSocket-Verbindung
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Fehler beim Upgrade auf WebSocket:", err)
		return
	}
	defer conn.Close()

	for {
		// Nachrichten vom Client empfangen
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			log.Println("Lesefehler:", err)
			break
		}
		fmt.Printf("Nachricht erhalten: %s\n", message)

		// Nachricht zurücksenden (Echo)
		err = conn.WriteMessage(messageType, message)
		if err != nil {
			log.Println("Schreibfehler:", err)
			break
		}
	}
}

func main() {
	fmt.Println("Starte WebSocket-Server auf Port 8080...")

	http.HandleFunc("/ws", echo)

	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("Server-Fehler:", err)
	}
}

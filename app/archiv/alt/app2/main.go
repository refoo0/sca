package main

import (
	"fmt"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func main() {
	// Geheime Zeichenkette (secret key), die zum Signieren von Tokens verwendet wird
	secretKey := []byte("supersecretkey")

	// Ein JWT-Token mit "HS256"-Algorithmus erstellen
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user":  "testuser",
		"admin": true,
		"exp":   time.Now().Add(time.Hour * 72).Unix(),
	})

	// Token signieren
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		log.Fatalf("Fehler beim Signieren des Tokens: %v", err)
	}

	fmt.Println("Signiertes Token:", tokenString)

	// Schwachstelle: Token ohne Validierung des Algorithmus dekodieren
	// Hier ist die Schwachstelle: jwt-go erlaubt es, den "None"-Algorithmus zu akzeptieren
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Schwachstelle: Es wird nicht verifiziert, ob der Algorithmus dem erwarteten entspricht
		return secretKey, nil
	})

	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		fmt.Println("Token erfolgreich verifiziert!")
		fmt.Println("Benutzer:", claims["user"])
		fmt.Println("Admin-Rechte:", claims["admin"])
	} else {
		fmt.Println("Fehler beim Verifizieren des Tokens:", err)
	}
}

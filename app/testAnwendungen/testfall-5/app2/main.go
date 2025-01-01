package main

import (
	"fmt"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func main() {
	// secret key used to sign tokens
	secretKey := []byte("supersecretkey")

	// create a JWT token with "HS256" algorithm
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user":  "testuser",
		"admin": true,
		"exp":   time.Now().Add(time.Hour * 72).Unix(),
	})

	// sign the token
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		log.Fatalf("error signing token: %v", err)
	}

	fmt.Println("Signed token:", tokenString)

	// decode token without validating the algorithm
	// Here is the vulnerability: jwt-go allows to accept the "None" algorithm
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// vulnerability: it does not verify if the algorithm matches the expected one
		return secretKey, nil
	})

	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		fmt.Println("Token successfully verified!")
		fmt.Println("User:", claims["user"])
		fmt.Println("Admin rights:", claims["admin"])
	} else {
		fmt.Println("Error verifying token:", err)
	}
}

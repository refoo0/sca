package main

import (
	"log"
	"net/http"

	"golang.org/x/crypto/acme/autocert"
)

func main() {
	// Erstellen eines Zertifikat-Managers
	m := &autocert.Manager{
		Cache:      autocert.DirCache("certs"),                               // Zertifikate werden im Ordner "certs" gespeichert
		Prompt:     autocert.AcceptTOS,                                       // Automatische Zustimmung zu den Nutzungsbedingungen von Let's Encrypt
		HostPolicy: autocert.HostWhitelist("example.com", "www.example.com"), // Zulässige Domains
	}

	// Erstellen eines HTTPS-Servers mit automatischer Zertifikatsverwaltung
	server := &http.Server{
		Addr:      ":443",
		TLSConfig: m.TLSConfig(),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello, HTTPS world!"))
		}),
	}

	// Starten des Servers
	log.Println("Starting server on https://example.com")
	log.Fatal(server.ListenAndServeTLS("", "")) // Zertifikate werden automatisch von autocert verwaltet
}

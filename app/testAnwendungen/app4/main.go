package main

import (
	"fmt"
	"log"

	"golang.org/x/crypto/ssh"
)

func main() {
	// Konfiguration für die SSH-Verbindung
	config := &ssh.ClientConfig{
		User: "username",
		Auth: []ssh.AuthMethod{
			ssh.Password("your_password"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Achtung: In der Produktion eine sichere Host-Überprüfung implementieren
	}

	// Verbindung herstellen
	client, err := ssh.Dial("tcp", "remote.server.com:22", config)
	if err != nil {
		log.Fatalf("Failed to dial: %s", err)
	}
	defer client.Close()

	// Sitzung erstellen
	session, err := client.NewSession()
	if err != nil {
		log.Fatalf("Failed to create session: %s", err)
	}
	defer session.Close()

	// Befehl ausführen
	output, err := session.CombinedOutput("ls -l")
	if err != nil {
		log.Fatalf("Failed to run command: %s", err)
	}
	fmt.Println(string(output))
}

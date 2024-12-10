package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Structs für die JSON-Datei
type Counts struct {
	CountOSV     int    `json:"CountOSV"`
	CountSnyk    int    `json:"CountSnyk"`
	CountTrivy   int    `json:"CountTrivy"`
	Target       string `json:"Target"`
	TotalEntries int    `json:"TotalEntries"`
}

type Vulnerability struct {
	CVEID string `json:"CVE-ID"`
	GHSA  string `json:"GHSA"`
	GOID  string `json:"GO-ID"`
	OSV   bool   `json:"OSV"`
	Snyk  bool   `json:"Snyk"`
	Trivy bool   `json:"Trivy"`
}

type JSONData struct {
	Counts Counts          `json:"Counts"`
	Vuln   []Vulnerability `json:"Vuln"`
}

// Neue Struktur der Ausgabedatei
type OutputFile struct {
	Counts struct {
		Sum        int `json:"Sum"`
		OnlyOSV    int `json:"OnlyOSV"`
		OnlySnyk   int `json:"OnlySnyk"`
		OnlyTrivy  int `json:"OnlyTrivy"`
		OSV_Snyk   int `json:"OSV_Snyk"`
		OSV_Trivy  int `json:"OSV_Trivy"`
		Snyk_Trivy int `json:"Snyk_Trivy"`
		All        int `json:"All"`
	} `json:"Counts"`
	OSV   []string `json:"OSV"`
	Snyk  []string `json:"Snyk"`
	Trivy []string `json:"Trivy"`
}

// Funktion, um die Datei zu lesen und zu verarbeiten
func processJSONFile(filePath string, outputFilePath string) error {
	// Datei einlesen
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("Error by reading file: " + err.Error())
	}

	// JSON-Daten in die Struktur unmarshallen
	var inputData JSONData
	err = json.Unmarshal(fileData, &inputData)
	if err != nil {
		return fmt.Errorf("Error by unmarshalling JSON: " + err.Error())
	}

	// Ziel-Name (Target) aus der JSON-Datei extrahieren
	target := inputData.Counts.Target

	// Erstelle die Arrays für OSV, Snyk und Trivy
	var osvIDs []string
	var snykIDs []string
	var trivyIDs []string

	// Iteriere über die Schwachstellen
	for _, vuln := range inputData.Vuln {
		// IDs für OSV sammeln
		if vuln.OSV {
			id := fmt.Sprintf("%s_%s", target, vuln.CVEID)
			osvIDs = append(osvIDs, id)
		}
		// IDs für Snyk sammeln
		if vuln.Snyk {
			id := fmt.Sprintf("%s_%s", target, vuln.CVEID)
			snykIDs = append(snykIDs, id)
		}
		// IDs für Trivy sammeln
		if vuln.Trivy {
			id := fmt.Sprintf("%s_%s", target, vuln.CVEID)
			trivyIDs = append(trivyIDs, id)
		}
	}

	var all int
	var onlyOSV int
	var onlySnyk int
	var onlyTrivy int
	var osvSnyk int
	var osvTrivy int
	var snykTrivy int

	for _, vuln := range inputData.Vuln {
		if vuln.OSV && vuln.Snyk && vuln.Trivy {
			all++
		} else if vuln.OSV && vuln.Snyk {
			osvSnyk++
		} else if vuln.OSV && vuln.Trivy {
			osvTrivy++
		} else if vuln.Snyk && vuln.Trivy {
			snykTrivy++
		} else if vuln.OSV {
			onlyOSV++
		} else if vuln.Snyk {
			onlySnyk++
		} else if vuln.Trivy {
			onlyTrivy++
		}
	}

	// Neue JSON-Struktur erstellen
	var outputData OutputFile

	// Überprüfen, ob die Ausgabedatei existiert
	if _, err := os.Stat(outputFilePath); err == nil {
		// Datei existiert, also einlesen
		existingFileData, err := os.ReadFile(outputFilePath)
		if err != nil {
			return fmt.Errorf("Error by reading existing output file: " + err.Error())
		}

		// Unmarshal der bestehenden Ausgabedaten
		err = json.Unmarshal(existingFileData, &outputData)
		if err != nil {
			return fmt.Errorf("Error by unmarshalling existing output file: " + err.Error())
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("Error checking if output file exists: " + err.Error())
	}

	// Vorhandene Einträge mit neuen Einträgen zusammenführen
	outputData.OSV = mergeAndRemoveDuplicates(outputData.OSV, osvIDs)
	outputData.Snyk = mergeAndRemoveDuplicates(outputData.Snyk, snykIDs)
	outputData.Trivy = mergeAndRemoveDuplicates(outputData.Trivy, trivyIDs)

	fmt.Println(onlyOSV)

	// Zähler aktualisieren
	outputData.Counts.All += all
	outputData.Counts.OnlyOSV += onlyOSV
	outputData.Counts.OnlySnyk += onlySnyk
	outputData.Counts.OnlyTrivy += onlyTrivy
	outputData.Counts.OSV_Snyk += osvSnyk
	outputData.Counts.OSV_Trivy += osvTrivy
	outputData.Counts.Snyk_Trivy += snykTrivy
	outputData.Counts.Sum += len(inputData.Vuln)

	fmt.Println(outputData.Counts.OnlyOSV)

	// JSON-Daten in die Datei schreiben
	fileContent, err := json.MarshalIndent(outputData, "", "  ")
	if err != nil {
		return fmt.Errorf("Error by marshalling JSON: " + err.Error())
	}

	err = os.WriteFile(outputFilePath, fileContent, 0644)
	if err != nil {
		return fmt.Errorf("Error by writing file: " + err.Error())
	}

	fmt.Printf("Erfolgreich Ausgabedatei aktualisiert: %s\n", outputFilePath)
	return nil
}

// Funktion zum Zusammenführen von Arrays und Entfernen von Duplikaten
func mergeAndRemoveDuplicates(existing []string, newEntries []string) []string {
	// Verwende eine Map, um Duplikate zu entfernen
	entryMap := make(map[string]bool)
	// Vorhandene Einträge in die Map einfügen
	for _, entry := range existing {
		entryMap[entry] = true
	}
	// Neue Einträge in die Map einfügen
	for _, entry := range newEntries {
		entryMap[entry] = true
	}

	// Konvertiere die Map zurück zu einem Array
	mergedArray := make([]string, 0, len(entryMap))
	for entry := range entryMap {
		mergedArray = append(mergedArray, entry)
	}

	return mergedArray
}

// Funktion, um die Funktion processJSONFile für jede JSON-Datei in einem Ordner auszuführen
func Generate(inputDirPath, outputFilePath string) {
	// Überprüfen, ob der angegebene Pfad ein Verzeichnis ist
	files, err := os.ReadDir(inputDirPath)
	if err != nil {
		fmt.Printf("Fehler beim Lesen des Verzeichnisses %s: %v\n", inputDirPath, err)
		return
	}

	// Iteriere durch alle Dateien im Verzeichnis
	for _, file := range files {
		// Überprüfen, ob es sich um eine JSON-Datei handelt (mit .json-Endung)
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") {
			// Erstelle den vollständigen Pfad zur Datei
			inputFilePath := fmt.Sprintf("%s/%s", inputDirPath, file.Name())
			fmt.Printf("Verarbeite Datei: %s\n", inputFilePath)

			// Prozessiere die JSON-Datei
			err := processJSONFile(inputFilePath, outputFilePath)
			if err != nil {
				fmt.Printf("Fehler beim Verarbeiten der Datei %s: %v\n", inputFilePath, err)
			}
		}
	}
}

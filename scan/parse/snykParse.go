package parse

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// RawVulnerability beschreibt die Struktur der rohen JSON-Daten
type RawVulnerability struct {
	Vulnerabilities []struct {
		Identifiers struct {
			GO   []string `json:"GO"`
			CVE  []string `json:"CVE"`
			GHSA []string `json:"GHSA"`
		} `json:"identifiers"`
	} `json:"vulnerabilities"`
}

type VulnIDS struct {
	CVEID string `json:"CVE-ID"`
	GHSA  string `json:"GHSA"`
	GOID  string `json:"GO-ID"`
}

// processSnykJSON lädt die JSON-Datei vom angegebenen Pfad und aktualisiert die VulnInfo-Datei
func processSnykJSON(snykPath string, vulnInfo string) {

	// Dateiinhalt einlesen
	file, err := os.Open(snykPath)
	if err != nil {
		fmt.Println("Fehler beim Öffnen der Datei:", err)
		return
	}
	defer file.Close()

	// Read the second JSON file (contains Vuln entries)
	var secondFile VulnInfo
	err = readJSONFile(vulnInfo, &secondFile)
	if err != nil {
		fmt.Println("Fehler beim Lesen der zweiten Datei:", err)
		return
	}

	// Dateiinhalt in Byte-Array einlesen
	byteValue, err := io.ReadAll(file)
	if err != nil {
		fmt.Println("Fehler beim Einlesen der Datei:", err)
		return
	}

	// Rohe JSON-Daten in RawVulnerability-Struktur umwandeln
	var rawData RawVulnerability
	err = json.Unmarshal(byteValue, &rawData)
	if err != nil {
		fmt.Println("Fehler beim Unmarshaling der Rohdaten:", err)
		return
	}

	vulnSynk := []VulnIDS{}
	uniqueEntries := make(map[string]bool)
	// VulnInfo-Struktur basierend auf den rohen Daten erstellen
	for _, vuln := range rawData.Vulnerabilities {
		var cveID, ghsa, goID string

		// Überprüfen, ob es mindestens einen Eintrag für jedes Feld gibt
		if len(vuln.Identifiers.CVE) > 0 {
			cveID = vuln.Identifiers.CVE[0]
		}
		if len(vuln.Identifiers.GHSA) > 0 {
			ghsa = vuln.Identifiers.GHSA[0]
		}
		if len(vuln.Identifiers.GO) > 0 {
			goID = vuln.Identifiers.GO[0]
		}

		// Erstelle einen eindeutigen Schlüssel, der diese Felder kombiniert
		uniqueKey := cveID + "|" + ghsa + "|" + goID

		// Überprüfen, ob dieser Schlüssel bereits existiert
		if _, exists := uniqueEntries[uniqueKey]; !exists {
			// Füge den Eintrag zur Liste und der Map hinzu
			vulnSynk = append(vulnSynk, VulnIDS{
				CVEID: cveID,
				GHSA:  ghsa,
				GOID:  goID,
			})
			uniqueEntries[uniqueKey] = true
		}
	}

	// Create a map to store the indexes of existing CVE-IDs in the second file
	existingVulnIndexMap := make(map[string]int)
	for i, vuln := range secondFile.Vuln {
		existingVulnIndexMap[vuln.CVEID] = i
	}

	for _, record := range vulnSynk {
		if index, exists := existingVulnIndexMap[record.CVEID]; exists {
			// If the vulnerability exists, set Snyk to true
			secondFile.Vuln[index].Snyk = true
		} else {
			// If the vulnerability does not exist, add it to the second file
			newVuln := struct {
				CVEID string `json:"CVE-ID"`
				GHSA  string `json:"GHSA"`
				GOID  string `json:"GO-ID"`
				OSV   bool   `json:"OSV"`
				Trivy bool   `json:"Trivy"`
				Snyk  bool   `json:"Snyk"`
			}{
				CVEID: record.CVEID,
				GHSA:  record.GHSA,
				GOID:  record.GOID,
				OSV:   false,
				Trivy: false,
				Snyk:  true,
			}
			secondFile.Vuln = append(secondFile.Vuln, newVuln)
		}
	}

	//add the vulnerabilities that do not have a CVE-ID
	vulnSynkGO := []VulnIDS{}
	vulnSynkGHSA := []VulnIDS{}
	for _, record := range vulnSynk {
		if record.CVEID == "" {
			if record.GOID != "" {
				vulnSynkGO = append(vulnSynkGO, record)
			} else {
				vulnSynkGHSA = append(vulnSynkGHSA, record)
			}
		}
	}

	if len(vulnSynkGO) > 0 {
		for _, record := range vulnSynkGO {
			if index, exists := existingVulnIndexMap[record.GOID]; exists {
				// If the vulnerability exists, set Snyk to true
				secondFile.Vuln[index].Snyk = true
			} else {
				// If the vulnerability does not exist, add it to the second file
				newVuln := struct {
					CVEID string `json:"CVE-ID"`
					GHSA  string `json:"GHSA"`
					GOID  string `json:"GO-ID"`
					OSV   bool   `json:"OSV"`
					Trivy bool   `json:"Trivy"`
					Snyk  bool   `json:"Snyk"`
				}{
					CVEID: "",
					GHSA:  "",
					GOID:  record.GOID,
					OSV:   false,
					Trivy: false,
					Snyk:  true,
				}
				secondFile.Vuln = append(secondFile.Vuln, newVuln)
			}
		}
	}

	if len(vulnSynkGHSA) > 0 {
		for _, record := range vulnSynkGHSA {
			if index, exists := existingVulnIndexMap[record.GHSA]; exists {
				// If the vulnerability exists, set Snyk to true
				secondFile.Vuln[index].Snyk = true
			} else {
				// If the vulnerability does not exist, add it to the second file
				newVuln := struct {
					CVEID string `json:"CVE-ID"`
					GHSA  string `json:"GHSA"`
					GOID  string `json:"GO-ID"`
					OSV   bool   `json:"OSV"`
					Trivy bool   `json:"Trivy"`
					Snyk  bool   `json:"Snyk"`
				}{
					CVEID: "",
					GHSA:  record.GHSA,
					GOID:  "",
					OSV:   false,
					Trivy: false,
					Snyk:  true,
				}
				secondFile.Vuln = append(secondFile.Vuln, newVuln)
			}
		}
	}

	// Write the updated second file
	err = writeJSONFile(vulnInfo, &secondFile)
	if err != nil {
		fmt.Println("Fehler beim Schreiben der aktualisierten Datei:", err)
		return
	}

	fmt.Println("Datei erfolgreich aktualisiert")
}

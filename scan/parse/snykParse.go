package parse

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/refoo0/sca/scan/modul"
)

// VulnIDS beschreibt die Struktur von CVE, GHSA und GO IDs
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
	var secondFile modul.VulnInfo
	err = readJSONFileSnyk(vulnInfo, &secondFile)
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

	// Rohe JSON-Daten dynamisch parsen
	var rawData interface{}
	err = json.Unmarshal(byteValue, &rawData)
	if err != nil {
		fmt.Println("Fehler beim Unmarshaling der Rohdaten:", err)
		return
	}

	vulnSynk := []VulnIDS{}
	uniqueEntries := make(map[string]bool)

	// Überprüfen, ob rawData eine Liste oder ein einzelnes Objekt ist
	switch data := rawData.(type) {
	case []interface{}:
		for _, item := range data {
			if entry, ok := item.(map[string]interface{}); ok {
				if vulnerabilities, exists := entry["vulnerabilities"]; exists {
					extractVulnerabilities(vulnerabilities, &vulnSynk, uniqueEntries)
				}
			}
		}
	case map[string]interface{}:
		if vulnerabilities, exists := data["vulnerabilities"]; exists {
			extractVulnerabilities(vulnerabilities, &vulnSynk, uniqueEntries)
		}
	default:
		fmt.Println("Unbekanntes JSON-Format für Vulnerabilities")
	}

	// Create a map to store the indexes of existing CVE-IDs in the second file
	existingVulnIndexMap := make(map[string]int)
	for i, vuln := range secondFile.Vuln {
		existingVulnIndexMap[vuln.CVEID] = i
	}

	for _, record := range vulnSynk {
		if index, exists := existingVulnIndexMap[record.CVEID]; exists {
			secondFile.Vuln[index].Snyk = true
		} else {
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

	err = writeJSONFileSnyk(vulnInfo, &secondFile)
	if err != nil {
		fmt.Println("Fehler beim Schreiben der aktualisierten Datei:", err)
		return
	}

	fmt.Println("Datei erfolgreich aktualisiert")
}

// extractVulnerabilities extrahiert die Einträge aus dem "vulnerabilities"-Feld
func extractVulnerabilities(vulnerabilities interface{}, vulnSynk *[]VulnIDS, uniqueEntries map[string]bool) {
	switch vulnList := vulnerabilities.(type) {
	case []interface{}:
		for _, vuln := range vulnList {
			if vulnMap, ok := vuln.(map[string]interface{}); ok {
				var cveID, ghsa, goID string
				if identifiers, ok := vulnMap["identifiers"].(map[string]interface{}); ok {
					if cves, ok := identifiers["CVE"].([]interface{}); ok && len(cves) > 0 {
						cveID = fmt.Sprintf("%v", cves[0])
					}
					if ghsas, ok := identifiers["GHSA"].([]interface{}); ok && len(ghsas) > 0 {
						ghsa = fmt.Sprintf("%v", ghsas[0])
					}
					if gos, ok := identifiers["GO"].([]interface{}); ok && len(gos) > 0 {
						goID = fmt.Sprintf("%v", gos[0])
					}
				}
				uniqueKey := cveID + "|" + ghsa + "|" + goID
				if _, exists := uniqueEntries[uniqueKey]; !exists {
					*vulnSynk = append(*vulnSynk, VulnIDS{
						CVEID: cveID,
						GHSA:  ghsa,
						GOID:  goID,
					})
					uniqueEntries[uniqueKey] = true
				}
			}
		}
	default:
		fmt.Println("'vulnerabilities' hat ein unerwartetes Format")
	}
}

// readJSONFileSnyk liest eine JSON-Datei in die angegebene Struktur
func readJSONFileSnyk(path string, target interface{}) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	byteValue, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	return json.Unmarshal(byteValue, target)
}

// writeJSONFileSnyk schreibt die JSON-Daten zurück in eine Datei
func writeJSONFileSnyk(path string, data interface{}) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

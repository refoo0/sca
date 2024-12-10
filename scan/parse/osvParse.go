package parse

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/refoo0/sca/scan/modul"
)

type OSVJSON struct {
	Results []struct {
		Packages []struct {
			Groups []struct {
				IDs     []string `json:"ids"`
				Aliases []string `json:"aliases"`
			} `json:"groups"`
		} `json:"packages"`
	} `json:"results"`
}

type VulnRecord struct {
	CVEID string
	GHSA  string
	GOID  string
}

// processJSON parses the input JSON file and maps CVE-ID, GHSA, and GO-ID into the required structure
func processOSVJSON(filePath string) (modul.VulnInfo, error) {
	// Open the JSON file
	file, err := os.Open(filePath)
	if err != nil {
		return modul.VulnInfo{}, fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	// Read the JSON file contents
	data, err := io.ReadAll(file)
	if err != nil {
		return modul.VulnInfo{}, fmt.Errorf("error reading file: %v", err)
	}

	// Parse the JSON data into the OSVJSON structure
	var inputData OSVJSON
	err = json.Unmarshal(data, &inputData)
	if err != nil {
		return modul.VulnInfo{}, fmt.Errorf("error unmarshaling JSON: %v", err)
	}

	// Use a map to avoid duplicates and to store CVE, GHSA, and GO-IDs together
	uniqueVulns := make(map[string]VulnRecord)

	// Extract the data for CVE-ID, GHSA, and GO-ID
	for _, result := range inputData.Results {
		for _, pkg := range result.Packages {
			for _, group := range pkg.Groups {
				var cveID, ghsaID, goID string

				// Identify CVE-ID, GHSA, and GO-ID from the aliases
				for _, alias := range group.Aliases {
					if len(alias) > 3 && alias[:4] == "CVE-" {
						cveID = alias
					} else if len(alias) > 4 && alias[:4] == "GHSA" {
						ghsaID = alias
					} else if len(alias) > 3 && alias[:3] == "GO-" {
						goID = alias
					}
				}

				// Use a unique key for each combination of CVE-ID, GHSA, and GO-ID to avoid duplicates
				uniqueKey := cveID + ghsaID + goID
				if uniqueKey != "" {
					uniqueVulns[uniqueKey] = VulnRecord{
						CVEID: cveID,
						GHSA:  ghsaID,
						GOID:  goID,
					}
				}
			}
		}
	}

	// Convert the map to a slice
	var vulnList []struct {
		CVEID string `json:"CVE-ID"`
		GHSA  string `json:"GHSA"`
		GOID  string `json:"GO-ID"`
		OSV   bool   `json:"OSV"`
		Trivy bool   `json:"Trivy"`
		Snyk  bool   `json:"Snyk"`
	}
	for _, record := range uniqueVulns {
		vulnList = append(vulnList, struct {
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
			OSV:   true,
		})
	}

	// Return the final output JSON structure
	return modul.VulnInfo{Vuln: vulnList}, nil
}

func saveOSVOutputJSON(filePath string, outputData modul.VulnInfo) error {
	// Convert the output structure to JSON
	jsonData, err := json.MarshalIndent(outputData, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling output JSON: %v", err)
	}

	// Write the JSON data to a new file
	err = os.WriteFile(filePath, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("error writing output JSON file: %v", err)
	}

	return nil
}

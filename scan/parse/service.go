package parse

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/refoo0/sca/scan/modul"
)

// Function to read JSON file and unmarshal it
func readJSONFile(path string, v interface{}) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %v", path, err)
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %v", path, err)
	}

	err = json.Unmarshal(bytes, v)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON from file %s: %v", path, err)
	}

	return nil
}

// Function to write JSON file
func writeJSONFile(path string, v interface{}) error {
	bytes, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	err = os.WriteFile(path, bytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file %s: %v", path, err)
	}

	return nil
}

func updateVulns(existingVulns []modul.Vuln, newVulns []modul.Vuln, scanType string) []modul.Vuln {

	existingCVEIDs := make(map[string]bool)
	existingCVEIDsInt := make(map[string]int)
	existingCVESGHSAs := make(map[string][]string)

	existingGHSAs := make(map[string]bool)
	existingGHSAsInt := make(map[string]int)

	for i, vuln := range existingVulns {

		if vuln.ID[:4] == "CVE-" {
			existingCVEIDs[vuln.ID] = true
			existingCVEIDsInt[vuln.ID] = i
			existingCVESGHSAs[vuln.ID] = vuln.GhsaIDs

		} else if vuln.ID[:4] == "GHSA" {
			existingGHSAs[vuln.ID] = true
			existingGHSAsInt[vuln.ID] = i
		}

	}

	for _, vuln := range newVulns {
		if vuln.ID[:4] == "CVE-" {
			if existingCVEIDs[vuln.ID] {
				existingVulns[existingCVEIDsInt[vuln.ID]].Scanner.SetScanType(scanType)
				existingVulns[existingCVEIDsInt[vuln.ID]].GhsaIDs = append(existingCVESGHSAs[vuln.ID], vuln.GhsaIDs...)
			} else {
				existingVulns = append(existingVulns, vuln)
			}

		} else if vuln.ID[:4] == "GHSA" {
			if existingGHSAs[vuln.ID] {
				existingVulns[existingGHSAsInt[vuln.ID]].Scanner.SetScanType(scanType)

			} else {
				existingVulns = append(existingVulns, vuln)
			}
		} else {
			existingVulns = append(existingVulns, vuln)
		}

	}

	return existingVulns
}

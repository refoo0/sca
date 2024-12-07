package parse

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type Vulnerability struct {
	VulnerabilityID string `json:"VulnerabilityID"`
}

type TrivyJson struct {
	Results []struct {
		Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
	} `json:"Results"`
}

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

func processTrivyJSON(trivy string, vulnInfo string) {

	// Read the first JSON file (contains Vulnerabilities)
	var firstFile TrivyJson
	err := readJSONFile(trivy, &firstFile)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Read the second JSON file (contains Vuln entries)
	var secondFile VulnInfo
	err = readJSONFile(vulnInfo, &secondFile)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Create a map to store the indexes of existing CVE-IDs in the second file
	existingVulnIndexMap := make(map[string]int)
	for i, vuln := range secondFile.Vuln {
		existingVulnIndexMap[vuln.CVEID] = i
	}

	// Loop through each vulnerability from the first file
	for _, result := range firstFile.Results {
		for _, vuln := range result.Vulnerabilities {
			if index, exists := existingVulnIndexMap[vuln.VulnerabilityID]; exists {
				// If the vulnerability exists, set Trivy to true
				secondFile.Vuln[index].Trivy = true
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
					CVEID: vuln.VulnerabilityID,
					GHSA:  "",    // Placeholder, as GHSA is not in the first file
					GOID:  "",    // Placeholder, as GO-ID is not in the first file
					OSV:   false, // Placeholder, as OSV is not in the first file
					Trivy: true,  // Trivy is set to true as requested
					Snyk:  false, // Placeholder, as Snyk is not in the first file
				}
				secondFile.Vuln = append(secondFile.Vuln, newVuln)
			}
		}
	}

	// Write the updated second file
	err = writeJSONFile(vulnInfo, &secondFile)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("The second JSON file has been updated successfully.")
}

package parse

import (
	"encoding/json"
	"fmt"
	"os"
)

func Parse(osvPath string, trivyPath string, snykPath string, target string) {
	// Path to the input JSON file
	//osvPath := "./parse/osv.json"
	//trivyPath := "./parse/trivy.json"
	// Path to the output JSON file
	var vulnInfos string
	if target == "" {
		vulnInfos = "./vulnInfos.json"
	} else {
		vulnInfos = target + ".json"
	}

	// Process the OSV JSON file
	outputData, err := processOSVJSON(osvPath)
	if err != nil {
		fmt.Printf("Error processing JSON: %v\n", err)
		return
	}
	// Save the OSV in VulnInfo struct to a new JSON file
	err = saveOSVOutputJSON(vulnInfos, outputData)
	if err != nil {
		fmt.Printf("Error saving output JSON: %v\n", err)
		return
	}

	// Process the Trivy JSON files
	processTrivyJSON(trivyPath, vulnInfos)

	// Process the Snyk JSON files
	processSnykJSON(snykPath, vulnInfos)

	// Calculate the counts of vulnerabilities
	calculateCounts(vulnInfos, target)
}

func calculateCounts(vulnInfo string, target string) {
	// Read the existing JSON file
	existingData, err := os.ReadFile(vulnInfo)
	if err != nil {
		fmt.Println("Error reading existing JSON file:", err)
		return
	}

	// Unmarshal the existing JSON into a map
	var existingJson map[string]interface{}
	err = json.Unmarshal(existingData, &existingJson)
	if err != nil {
		fmt.Println("Error unmarshalling existing JSON:", err)
		return
	}

	// Extract the "Vuln" field to calculate counts
	vulnData, ok := existingJson["Vuln"].([]interface{})
	if vulnData == nil {
		fmt.Println("Vuln is nil")
		return
	}
	if !ok {
		fmt.Println("Error: 'Vuln' field is not an array")
		return
	}

	// Initialize counters
	countOSV := 0
	countTrivy := 0
	countSnyk := 0
	totalEntries := len(vulnData)

	// Loop through each vulnerability and count true values
	for _, vuln := range vulnData {
		vulnMap, ok := vuln.(map[string]interface{})
		if !ok {
			fmt.Println("Error: failed to cast vulnerability to map")
			continue
		}
		if osv, ok := vulnMap["OSV"].(bool); ok && osv {
			countOSV++
		}
		if trivy, ok := vulnMap["Trivy"].(bool); ok && trivy {
			countTrivy++
		}
		if snyk, ok := vulnMap["Snyk"].(bool); ok && snyk {
			countSnyk++
		}
	}

	// Update the "Counts" field in the existing JSON structure
	if _, ok := existingJson["Counts"].(map[string]interface{}); !ok {
		existingJson["Counts"] = make(map[string]interface{})
	}
	counts := existingJson["Counts"].(map[string]interface{})
	counts["Target"] = target
	counts["TotalEntries"] = totalEntries
	counts["CountOSV"] = countOSV
	counts["CountTrivy"] = countTrivy
	counts["CountSnyk"] = countSnyk

	// Marshal the updated structure back to JSON
	finalJSON, err := json.MarshalIndent(existingJson, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling final JSON:", err)
		return
	}

	// Write the updated JSON back to the file
	err = os.WriteFile(vulnInfo, finalJSON, 0644)
	if err != nil {
		fmt.Println("Error writing updated JSON file:", err)
		return
	}
}

package parse

import (
	"fmt"
)

type VulnInfo struct {
	Vuln []struct {
		CVEID string `json:"CVE-ID"`
		GHSA  string `json:"GHSA"`
		GOID  string `json:"GO-ID"`
		OSV   bool   `json:"OSV"`
		Trivy bool   `json:"Trivy"`
		Snyk  bool   `json:"Snyk"`
	} `json:"Vuln"`
}

func Parse(osvPath string, trivyPath string, snykPath string) {
	// Path to the input JSON file
	//osvPath := "./parse/osv.json"
	//trivyPath := "./parse/trivy.json"
	// Path to the output JSON file
	vulnInfos := "./output.json"

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
}

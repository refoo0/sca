package parse

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/refoo0/sca/scan/modul"
	"github.com/refoo0/sca/scan/utils"
)

func Parse(osvPath string, trivyPath string, snykPath string, target string) error {
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

	var vulnInfoJson modul.VulnInfo
	// JSON aus der Struktur erzeugen
	jsonData, err := json.MarshalIndent(vulnInfoJson, "", "  ")
	if err != nil {
		fmt.Println("Fehler beim Erzeugen des JSON:", err)
		return err
	}

	err = os.WriteFile(vulnInfos, jsonData, 0644)
	if err != nil {
		fmt.Println("Fehler beim Schreiben der Datei:", err)
		return err
	}

	//Process the OSV JSON file
	err = processOSVJSON(osvPath, vulnInfos)
	if err != nil {
		fmt.Println(err)
		return fmt.Errorf("error processing OSV JSON: %v", err)
	}

	// Process the Trivy JSON files
	err = processTrivyJSON(trivyPath, vulnInfos)
	if err != nil {
		fmt.Println(err)
		return fmt.Errorf("error processing Trivy JSON: %v", err)
	}

	// Process the Snyk JSON files
	err = processSnykJSON(snykPath, vulnInfos)
	if err != nil {
		fmt.Println(err)
		return fmt.Errorf("error processing Snyk JSON: %v", err)
	}

	// Calculate the counts of vulnerabilities
	err = calculateCounts(vulnInfos, target)
	if err != nil {
		fmt.Println(err)
		return fmt.Errorf("error calculating counts: %v", err)
	}

	return nil

}

func calculateCounts(vulnInfo string, target string) error {

	// Read the existing JSON file
	existingData, err := os.ReadFile(vulnInfo)
	if err != nil {
		return fmt.Errorf("error reading existing JSON: %v", err)
	}

	//unmarshal the existing JSON into a struct
	var existingJso modul.VulnInfo
	err = json.Unmarshal(existingData, &existingJso)
	if err != nil {
		return fmt.Errorf("error unmarshalling existing JSON: %v", err)
	}

	// Extract the "Vuln" field to calculate counts
	vulnData := existingJso.Vuln

	totalEntries := len(vulnData)

	existingJso.Target = target

	existingJso.TotalEntries = totalEntries

	err = utils.WriteJSONFile(vulnInfo, existingJso)
	if err != nil {
		return fmt.Errorf("error writing JSON file: %v", err)
	}

	return nil
}

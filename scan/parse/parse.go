package parse

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/refoo0/sca/scan/modul"
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

	// Initialize counters
	countOSV := 0
	countTrivy := 0
	countSnyk := 0
	totalEntries := len(vulnData)

	// Loop through each vulnerability and count true values
	for _, vuln := range vulnData {
		if vuln.OSV {
			countOSV++
		}
		if vuln.Trivy {
			countTrivy++
		}
		if vuln.Snyk {
			countSnyk++
		}
	}

	existingJso.Counts.Target = target
	existingJso.Counts.TotalEntries = totalEntries

	if existingJso.Counts.CountOSV != countOSV {
		fmt.Printf("error: CountOSV mismatch: expected %v, got %v\n", existingJso.Counts.CountOSV, countOSV)
	}
	if existingJso.Counts.CountTrivy != countTrivy {
		fmt.Printf("error: CountTrivy mismatch: expected %v, got %v\n", existingJso.Counts.CountTrivy, countTrivy)
	}
	if existingJso.Counts.CountSnyk != countSnyk {
		fmt.Printf("error: CountSnyk mismatch: expected %v, got %v\n", existingJso.Counts.CountSnyk, countSnyk)
	}

	// Update the counts in the JSON
	onlyOSV := 0
	onlyTrivy := 0
	onlySnyk := 0
	OSVTrivy := 0
	OSVSnyk := 0
	TrivySnyk := 0
	allThree := 0

	vulnOnlyOSV := []modul.Vuln{}
	vulnOnlyTrivy := []modul.Vuln{}
	vulnOnlySnyk := []modul.Vuln{}
	vulnOSVTrivy := []modul.Vuln{}
	vulnOSVSnyk := []modul.Vuln{}
	vulnTrivySnyk := []modul.Vuln{}
	vulnAllThree := []modul.Vuln{}

	for _, vuln := range vulnData {
		if vuln.OSV && !vuln.Trivy && !vuln.Snyk {
			vulnOnlyOSV = append(vulnOnlyOSV, vuln)
			onlyOSV++
		}
		if !vuln.OSV && vuln.Trivy && !vuln.Snyk {
			vulnOnlyTrivy = append(vulnOnlyTrivy, vuln)
			onlyTrivy++
		}
		if !vuln.OSV && !vuln.Trivy && vuln.Snyk {
			vulnOnlySnyk = append(vulnOnlySnyk, vuln)
			onlySnyk++
		}
		if vuln.OSV && vuln.Trivy && !vuln.Snyk {
			vulnOSVTrivy = append(vulnOSVTrivy, vuln)
			OSVTrivy++
		}
		if vuln.OSV && !vuln.Trivy && vuln.Snyk {
			vulnOSVSnyk = append(vulnOSVSnyk, vuln)
			OSVSnyk++
		}
		if !vuln.OSV && vuln.Trivy && vuln.Snyk {
			vulnTrivySnyk = append(vulnTrivySnyk, vuln)
			TrivySnyk++
		}
		if vuln.OSV && vuln.Trivy && vuln.Snyk {
			vulnAllThree = append(vulnAllThree, vuln)
			allThree++
		}
	}

	existingJso.Counts.OnlyOSV = onlyOSV
	existingJso.Counts.OnlyTrivy = onlyTrivy
	existingJso.Counts.OnlySnyk = onlySnyk
	existingJso.Counts.OSVTrivy = OSVTrivy
	existingJso.Counts.OSVSnyk = OSVSnyk
	existingJso.Counts.TrivySnyk = TrivySnyk
	existingJso.Counts.AllThree = allThree

	existingJso.Counts.VulnOnlyOSV = vulnOnlyOSV
	existingJso.Counts.VulnOnlyTrivy = vulnOnlyTrivy
	existingJso.Counts.VulnOnlySnyk = vulnOnlySnyk
	existingJso.Counts.VulnOSVTrivy = vulnOSVTrivy
	existingJso.Counts.VulnOSVSnyk = vulnOSVSnyk
	existingJso.Counts.VulnTrivySnyk = vulnTrivySnyk
	existingJso.Counts.VulnAllThree = vulnAllThree

	err = writeJSONFile(vulnInfo, existingJso)
	if err != nil {
		return fmt.Errorf("error writing JSON file: %v", err)
	}

	return nil
}

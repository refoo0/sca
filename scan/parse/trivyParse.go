package parse

import (
	"fmt"
	"strings"

	"github.com/refoo0/sca/scan/modul"
)

type Vulnerability struct {
	VulnerabilityID string `json:"VulnerabilityID"`
}

type TrivyJson struct {
	Results []struct {
		Type            string          `json:"Type"`
		Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
	} `json:"Results"`
}

func processTrivyJSON(trivy string, vulnInfoPath string) error {

	// Read the first JSON file (contains Vulnerabilities)
	var trivyFile TrivyJson
	err := readJSONFile(trivy, &trivyFile)
	if err != nil {
		return err
	}

	// Create a map to store the vulnerability IDs and avoid duplicates
	vulnerabilityIDs := make(map[string]string)
	for _, result := range trivyFile.Results {
		typ := result.Type
		var t string
		if typ == "gomod" {
			t = "Go"
		} else if typ == "yarn" || typ == "npm" {
			t = "Npm"
		} else if typ == "pip" || typ == "poetry" {
			t = "Pypi"
		} else {
			return fmt.Errorf("unknown Type: %s", typ)
		}
		for _, vuln := range result.Vulnerabilities {
			id := vuln.VulnerabilityID + "//" + t
			vulnerabilityIDs[id] = t
		}
	}

	// Read the second JSON file (contains Vuln entries)
	var vulnInfo modul.VulnInfo
	err = readJSONFile(vulnInfoPath, &vulnInfo)
	if err != nil {
		return err
	}
	vulnInfo.Counts.CountTrivy = len(vulnerabilityIDs)
	existingVulns := vulnInfo.Vuln

	newVulns := []modul.Vuln{}
	// Loop through each vulnerability from the first file
	for vulnID := range vulnerabilityIDs {

		oldVulnID := vulnID
		var cveID, ghsaID, goID, id string

		newVuln := modul.Vuln{}
		newVuln.OthersID = map[string]string{}
		lowerID := strings.ToLower(vulnID)

		vulnID = strings.Split(vulnID, "//")[0]
		if strings.HasPrefix(lowerID, "cve") {
			cveID = vulnID
			newVuln.CVEID = cveID
		} else if strings.HasPrefix(lowerID, "ghsa") {
			ghsaID = vulnID
			newVuln.GHSA = ghsaID
		} else if strings.HasPrefix(lowerID, "go") {
			goID = vulnID
			newVuln.GOID = goID
		} else {
			id = vulnID
			newVuln.OthersID["Trivy-"+id] = id
		}
		newVuln.Trivy = true

		newVuln.System = vulnerabilityIDs[oldVulnID]

		newVulns = append(newVulns, newVuln)

	}

	// Update the existing vulnerabilities with the new vulnerabilities
	vulnInfo.Vuln = updateVulns(existingVulns, newVulns, "Trivy")

	// Write the updated second file
	err = writeJSONFile(vulnInfoPath, &vulnInfo)
	if err != nil {
		return err
	}

	return nil
}

package parse

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/refoo0/sca/scan/modul"
	"github.com/refoo0/sca/scan/utils"
)

type SnykJSON struct {
	Vulnerabilities []struct {
		SnykID      string              `json:"id"`
		Identifiers map[string][]string `json:"identifiers"`
	} `json:"vulnerabilities"`
	PackageManager string `json:"packageManager"`
}

type SnykJSONList []SnykJSON

// processSnykJSON lädt die JSON-Datei vom angegebenen Pfad und aktualisiert die VulnInfo-Datei
func processSnykJSON(snykPath string, vulnInfoPath string) error {
	var snykList SnykJSONList
	err := readJSONFileSnyk(snykPath, &snykList)
	if err != nil {
		return err
	}

	vulnsGo := make(map[string]modul.Vuln)
	vulnsNpm := make(map[string]modul.Vuln)
	vulnsPypi := make(map[string]modul.Vuln)
	vulnsElse := make(map[string]modul.Vuln)

	existVuln := make(map[string]bool)

	for _, snyk := range snykList {
		typ := snyk.PackageManager
		var t string
		if typ == "gomodules" {
			t = "Go"
		} else if typ == "npm" || typ == "yarn" {
			t = "Npm"
		} else if typ == "poetry" {
			t = "Pypi"
		} else {
			return fmt.Errorf("unknown PackageManager: %s", typ)
		}

		for _, vuln := range snyk.Vulnerabilities {

			if !existVuln[vuln.SnykID] {

				existVuln[vuln.SnykID] = true

				cveIDS := vuln.Identifiers["CVE"]
				ghsaIDS := vuln.Identifiers["GHSA"]

				cveIDsGhsaIDs := make(map[string][]string)

				var uniqueKeys []string

				for _, cveID := range cveIDS {
					uniqueKeys = append(uniqueKeys, cveID)
					cveIDsGhsaIDs[cveID] = ghsaIDS
				}

				if len(uniqueKeys) == 0 {
					uniqueKeys = append(uniqueKeys, ghsaIDS...)
				}

				if len(uniqueKeys) == 0 {
					uniqueKeys = append(uniqueKeys, vuln.SnykID)
				}

				for _, uniqueKey := range uniqueKeys {
					newVuln := modul.Vuln{
						ID:      uniqueKey,
						GhsaIDs: cveIDsGhsaIDs[uniqueKey],
						Scanner: modul.Scanner{
							Snyk: true,
						},
						System: t,
					}

					if t == "Go" {
						vulnsGo[uniqueKey] = newVuln

					} else if t == "Npm" {
						vulnsNpm[uniqueKey] = newVuln
					} else if t == "Pypi" {
						vulnsPypi[uniqueKey] = newVuln
					} else {
						vulnsElse[uniqueKey] = newVuln
					}
				}

			}

		}

	}

	// Read the second JSON file (contains Vuln entries)
	var vulnInfo modul.VulnInfo
	err = utils.ReadJSONFile(vulnInfoPath, &vulnInfo)
	if err != nil {
		return err
	}
	vulnInfo.CountSnyk = len(vulnsGo) + len(vulnsNpm) + len(vulnsPypi) + len(vulnsElse)
	existingVulns := vulnInfo.Vuln

	newVulns := []modul.Vuln{}
	for _, vuln := range vulnsGo {
		newVulns = append(newVulns, vuln)
	}

	for _, vuln := range vulnsNpm {
		newVulns = append(newVulns, vuln)
	}

	for _, vuln := range vulnsPypi {
		newVulns = append(newVulns, vuln)
	}

	for _, vuln := range vulnsElse {
		newVulns = append(newVulns, vuln)
	}

	vulnInfo.Vuln = utils.UpdateVulns(existingVulns, newVulns, "Snyk")

	err = utils.WriteJSONFile(vulnInfoPath, &vulnInfo)
	if err != nil {
		return err
	}

	return nil
}

/*
// VulnIDS beschreibt die Struktur von CVE, GHSA und GO IDs
type VulnIDS struct {
	CVEID string `json:"CVE-ID"`
	GHSA  string `json:"GHSA"`
	GOID  string `json:"GO-ID"`
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
*/

// readJSONFileSnyk liest eine JSON-Datei in die angegebene Struktur
func readJSONFileSnyk(path string, target interface{}) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %v", path, err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %v", path, err)
	}

	err = json.Unmarshal(data, target)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON from file %s: %v", path, err)
	}

	return nil

}

func (s *SnykJSONList) UnmarshalJSON(data []byte) error {
	// Try unmarshaling as an array
	var list []SnykJSON
	if err := json.Unmarshal(data, &list); err == nil {
		*s = list
		return nil
	}

	// If it's not an array, try unmarshaling as a single object
	var single SnykJSON
	if err := json.Unmarshal(data, &single); err == nil {
		*s = append(*s, single)
		return nil
	}

	// Return an error if neither works
	return fmt.Errorf("invalid JSON format for SnykJSONList")
}

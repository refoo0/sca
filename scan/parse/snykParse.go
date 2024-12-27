package parse

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/refoo0/sca/scan/modul"
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

	vulnSynk := make(map[string]modul.Vuln)
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
			id := vuln.SnykID
			if _, exists := vulnSynk[id]; !exists {
				existVuln := vulnSynk[id]

				existVuln.System = t

				existVuln.Snyk = true
				existVuln.SnykID = id
				existVuln.OthersID = make(map[string]string)

				if identifiers, ok := vuln.Identifiers["CVE"]; ok && len(identifiers) > 0 {

					existVuln.CVEID = identifiers[0]
					if len(identifiers) > 1 {
						for i := 1; i < len(identifiers)-1; i++ {
							existVuln.OthersID[fmt.Sprint("Snyk-CVE-", i)] = identifiers[i]
						}
					}
				}

				if identifiers, ok := vuln.Identifiers["GHSA"]; ok && len(identifiers) > 0 {
					existVuln.GHSA = identifiers[0]

					if len(identifiers) > 1 {
						for i := 1; i < len(identifiers)-1; i++ {
							existVuln.OthersID[fmt.Sprint("Snyk-GHSA-", i)] = identifiers[i]
						}
					}

				}

				if identifiers, ok := vuln.Identifiers["GO"]; ok && len(identifiers) > 0 {
					existVuln.GOID = identifiers[0]
					if len(identifiers) > 1 {
						for i := 1; i < len(identifiers)-1; i++ {
							existVuln.OthersID[fmt.Sprint("Snyk-GO-", i)] = identifiers[i]
						}
					}
				}
				vulnSynk[id] = existVuln

			}

		}

	}

	// Read the second JSON file (contains Vuln entries)
	var vulnInfo modul.VulnInfo
	err = readJSONFile(vulnInfoPath, &vulnInfo)
	if err != nil {
		return err
	}
	vulnInfo.Counts.CountSnyk = len(vulnSynk)
	existingVulns := vulnInfo.Vuln

	newVulns := []modul.Vuln{}
	for id, vuln := range vulnSynk {
		vuln.SnykID = id
		vuln.Snyk = true
		vuln.System = vulnSynk[id].System

		newVulns = append(newVulns, vuln)
	}

	vulnInfo.Vuln = updateVulns(existingVulns, newVulns, "Snyk")

	err = writeJSONFile(vulnInfoPath, &vulnInfo)
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

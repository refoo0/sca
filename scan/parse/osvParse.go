package parse

import (
	"fmt"

	"github.com/refoo0/sca/scan/modul"
	"github.com/refoo0/sca/scan/utils"
)

type OSVJSON struct {
	Results []struct {
		Packages []struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
			Vulnerabilities []struct {
				ID       string   `json:"id"`
				Aliases  []string `json:"aliases"`
				Affected []struct {
					Package struct {
						Ecosystem string `json:"ecosystem"`
						Name      string `json:"name"`
					} `json:"package"`
				} `json:"affected"`
			} `json:"vulnerabilities"`

			Groups []struct {
				IDs     []string `json:"ids"`
				Aliases []string `json:"aliases"`
			} `json:"groups"`
		} `json:"packages"`
	} `json:"results"`
}

// processJSON parses the input JSON file and maps CVE-ID, GHSA, and GO-ID into the required structure
func processOSVJSON(osvPath string, vulnInfoPath string) error {
	// read the JSON file
	var osvJson OSVJSON
	err := utils.ReadJSONFile(osvPath, &osvJson)
	if err != nil {
		return err
	}

	vulnsGo := make(map[string]modul.Vuln)
	vulnsNpm := make(map[string]modul.Vuln)
	vulnsPypi := make(map[string]modul.Vuln)
	vulnsElse := make(map[string]modul.Vuln)

	for _, result := range osvJson.Results {
		for _, pkg := range result.Packages {

			typ := pkg.Package.Ecosystem
			var t string
			if typ == "Go" {
				t = "Go"
			} else if typ == "npm" {
				t = "Npm"
			} else if typ == "PyPI" {
				t = "Pypi"
			} else {
				return fmt.Errorf("unknown ecosystem: %s", typ)
			}

			for _, vuln := range pkg.Vulnerabilities {
				var ids []string
				ids = append(ids, vuln.ID)
				ids = append(ids, vuln.Aliases...)

				var cveIDs, ghsaIDs, goIDs, uniqueKeys []string

				// Identify CVE-ID, GHSA, and GO-ID from the ids
				cveIDsGhsaIDs := make(map[string][]string)

				othersIDS := []string{}

				for _, id := range ids {
					if len(id) > 3 && id[:4] == "CVE-" {
						cveIDs = append(cveIDs, id)
					} else if len(id) > 4 && id[:4] == "GHSA" {
						ghsaIDs = append(ghsaIDs, id)
						for _, cveID := range cveIDs {
							cveIDsGhsaIDs[cveID] = ghsaIDs
						}
					} else if len(id) > 3 && id[:3] == "GO-" {
						goIDs = append(goIDs, id)
					} else {
						othersIDS = append(othersIDS, id)
					}
				}

				uniqueKeys = append(uniqueKeys, cveIDs...)
				if len(uniqueKeys) == 0 {
					uniqueKeys = append(uniqueKeys, ghsaIDs...)
				}
				if len(uniqueKeys) == 0 {
					uniqueKeys = append(uniqueKeys, goIDs...)
				}

				if len(uniqueKeys) == 0 {
					if len(othersIDS) > 0 {
						uniqueKeys = append(uniqueKeys, othersIDS[0])
						othersIDS = othersIDS[1:]
					}
				}

				for _, uniqueKey := range uniqueKeys {

					newVuln := modul.Vuln{
						ID:        uniqueKey,
						GhsaIDs:   cveIDsGhsaIDs[uniqueKey],
						OthersIDS: othersIDS,
						Scanner: modul.Scanner{
							OSV: true,
						},
						System: t,
					}

					if t == "Go" {
						for _, affected := range vuln.Affected {
							if affected.Package.Ecosystem == "Go" {
								if affected.Package.Name == "stdlib" {
									newVuln.StandrdLibOSV = true
								}
							}
						}
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
	vulnInfo.CountOSV = len(vulnsGo) + len(vulnsNpm) + len(vulnsPypi) + len(vulnsElse)
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

	// Update the existing vulnerabilities with the new ones
	vulnInfo.Vuln = utils.UpdateVulns(existingVulns, newVulns, "OSV")

	// Write the updated second file
	err = utils.WriteJSONFile(vulnInfoPath, &vulnInfo)
	if err != nil {
		return err
	}

	return nil

}

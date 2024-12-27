package parse

import (
	"fmt"
	"strings"

	"github.com/refoo0/sca/scan/modul"
)

type OSVJSON struct {
	Results []struct {
		Packages []struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
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
	err := readJSONFile(osvPath, &osvJson)
	if err != nil {
		return err
	}

	osvVulnsGo := make(map[string]modul.Vuln)
	osvVulnsNpm := make(map[string]modul.Vuln)
	osvVulnsPypi := make(map[string]modul.Vuln)
	osvVulnsElse := make(map[string]modul.Vuln)

	// Extract the data for CVE-ID, GHSA, and GO-ID
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
			} else if typ == "Maven" || typ == "crates.io" || typ == "NuGet" {

				t = "else"
			} else {
				return fmt.Errorf("unknown ecosystem: %s", typ)
			}

			for _, group := range pkg.Groups {

				var cveIDs, ghsaIDs, goIDs, uniqueKeys []string

				// Identify CVE-ID, GHSA, and GO-ID from the aliases
				for _, alias := range group.Aliases {
					if len(alias) > 3 && alias[:4] == "CVE-" {
						cveIDs = append(cveIDs, alias)
					} else if len(alias) > 4 && alias[:4] == "GHSA" {
						ghsaIDs = append(ghsaIDs, alias)
					} else if len(alias) > 3 && alias[:3] == "GO-" {
						goIDs = append(goIDs, alias)
					}
				}
				var cveID, ghsaID, goID string
				if len(cveIDs) != 0 {
					for _, cveID := range cveIDs {
						if len(ghsaIDs) != 0 {
							for _, ghsaID := range ghsaIDs {
								if len(goIDs) != 0 {
									for _, goID := range goIDs {
										uniqueKeys = append(uniqueKeys, "CVEID:"+cveID+";"+"GHSA:"+ghsaID+";"+"GOID:"+goID)
									}
								} else {
									uniqueKeys = append(uniqueKeys, "CVEID:"+cveID+";"+"GHSA:"+ghsaID+";"+"GOID:"+goID)
								}
							}
						} else {
							if len(goIDs) != 0 {
								for _, goID := range goIDs {
									uniqueKeys = append(uniqueKeys, "CVEID:"+cveID+";"+"GHSA:"+ghsaID+";"+"GOID:"+goID)
								}
							} else {
								uniqueKeys = append(uniqueKeys, "CVEID:"+cveID+";"+"GHSA:"+ghsaID+";"+"GOID:"+goID)
							}
						}
					}
				} else if len(ghsaIDs) != 0 {
					for _, ghsaID := range ghsaIDs {
						if len(goIDs) != 0 {
							for _, goID := range goIDs {
								uniqueKeys = append(uniqueKeys, "CVEID:"+cveID+";"+"GHSA:"+ghsaID+";"+"GOID:"+goID)
							}
						} else {
							uniqueKeys = append(uniqueKeys, "CVEID:"+cveID+";"+"GHSA:"+ghsaID+";"+"GOID:"+goID)
						}
					}
				} else {
					if len(goIDs) != 0 {
						for _, goID := range goIDs {
							uniqueKeys = append(uniqueKeys, "CVEID:"+cveID+";"+"GHSA:"+ghsaID+";"+"GOID:"+goID)
						}
					}
				}

				// Use a unique key for each combination of CVE-ID, GHSA, and GO-ID to avoid duplicates

				othersIDs := make(map[string]string)
				if len(uniqueKeys) == 0 {
					var uniqueKey string
					for _, alias := range group.Aliases {
						uniqueKey += alias
						othersIDs[fmt.Sprint("OSV-", alias)] = alias

					}
					uniqueKey = "Others:" + uniqueKey
					uniqueKeys = append(uniqueKeys, uniqueKey)
				}

				for _, uniqueKey := range uniqueKeys {
					cveID, ghsaID, goID := ExtractValues(uniqueKey)
					newVuln := modul.Vuln{
						CVEID:    cveID,
						GHSA:     ghsaID,
						GOID:     goID,
						OthersID: othersIDs,
						OSV:      true,
						System:   t,
					}

					if t == "Go" {
						osvVulnsGo[uniqueKey] = newVuln
					} else if t == "Npm" {
						osvVulnsNpm[uniqueKey] = newVuln
					} else if t == "Pypi" {
						osvVulnsPypi[uniqueKey] = newVuln
					} else {
						osvVulnsElse[uniqueKey] = newVuln
					}

				}
			}
		}
	}

	//check if the package is standard library
	for i, v := range osvVulnsGo {
		for _, result := range osvJson.Results {
			for _, pkg := range result.Packages {
				for _, vuln := range pkg.Vulnerabilities {
					sameID := false
					if vuln.ID == v.CVEID || vuln.ID == v.GHSA || vuln.ID == v.GOID {
						sameID = true
					} else {
						for _, alias := range vuln.Aliases {
							if alias == v.CVEID {
								sameID = true
							}
						}
					}
					if sameID {
						for _, affected := range vuln.Affected {
							if affected.Package.Ecosystem == "Go" {
								if affected.Package.Name == "stdlib" {
									v.StandrdLibOSV = true
								}
							}
							osvVulnsGo[i] = v

						}
					}
				}
			}
		}
	}

	// Read the second JSON file (contains Vuln entries)
	var vulnInfo modul.VulnInfo
	err = readJSONFile(vulnInfoPath, &vulnInfo)
	if err != nil {
		return err
	}
	vulnInfo.Counts.CountOSV = len(osvVulnsGo) + len(osvVulnsNpm) + len(osvVulnsPypi) + len(osvVulnsElse)
	existingVulns := vulnInfo.Vuln

	newVulns := []modul.Vuln{}
	for _, vuln := range osvVulnsGo {
		newVulns = append(newVulns, vuln)
	}

	for _, vuln := range osvVulnsNpm {
		newVulns = append(newVulns, vuln)
	}

	for _, vuln := range osvVulnsPypi {
		newVulns = append(newVulns, vuln)
	}

	for _, vuln := range osvVulnsElse {
		newVulns = append(newVulns, vuln)
	}

	// Update the existing vulnerabilities with the new ones
	vulnInfo.Vuln = updateVulns(existingVulns, newVulns, "OSV")

	// Write the updated second file
	err = writeJSONFile(vulnInfoPath, &vulnInfo)
	if err != nil {
		return err
	}

	return nil

}

func ExtractValues(input string) (string, string, string) {
	var cveID, ghsa, goID string

	// Zerlegen des Eingabestrings in Teile, getrennt durch Semikolon
	parts := strings.Split(input, ";")
	for _, part := range parts {
		// Trimmen von Leerzeichen um die Teile sauber zu verarbeiten
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CVEID:") {
			cveID = strings.TrimSpace(strings.TrimPrefix(part, "CVEID:"))
		} else if strings.HasPrefix(part, "GHSA:") {
			ghsa = strings.TrimSpace(strings.TrimPrefix(part, "GHSA:"))
		} else if strings.HasPrefix(part, "GOID:") {
			goID = strings.TrimSpace(strings.TrimPrefix(part, "GOID:"))
		}
	}

	return cveID, ghsa, goID
}

package parse

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/refoo0/sca/scan/modul"
)

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

func updateVulns(existingVulns []modul.Vuln, newVulns []modul.Vuln, scanType string) []modul.Vuln {

	existingCVEs := make(map[string]bool)
	existingGHSAs := make(map[string]bool)
	existingGOs := make(map[string]bool)

	for _, vuln := range existingVulns {

		if vuln.CVEID != "" {
			existingCVEs[vuln.CVEID+"//"+vuln.System] = true
		}
		if vuln.GHSA != "" {
			existingGHSAs[vuln.GHSA+"//"+vuln.System] = true
		}
		if vuln.GOID != "" {
			existingGOs[vuln.GOID+"//"+vuln.System] = true
		}
	}

	for _, vuln := range newVulns {

		if vuln.CVEID != "" {
			if !existingCVEs[vuln.CVEID+"//"+vuln.System] {
				existingVulns = append(existingVulns, vuln)

			} else {

				for i, vul := range existingVulns {

					if vul.CVEID == vuln.CVEID {
						if vul.System == vuln.System {
							existingVulns[i].SetScanType(scanType, vuln.SnykID)

							for k, v := range vuln.OthersID {
								existingVulns[i].OthersID[k] = v
							}
						}

						//|| existingVulns[i].CVEID == "CVE-2022-24785"

					}
					/*
						if existingVulns[i].CVEID == "CVE-2022-25901" && vuln.CVEID == "CVE-2022-25901" {
							fmt.Println("!!", existingVulns[i].OSV)
							fmt.Println("scanType", scanType, "system", vuln.System, vul.System)
						}
					*/

				}
			}
			continue
		}
		if vuln.GHSA != "" {
			if !existingGHSAs[vuln.GHSA+"//"+vuln.System] {
				existingVulns = append(existingVulns, vuln)
			} else {
				for i, vul := range existingVulns {
					if vul.GHSA == vuln.GHSA {
						if vul.System == vuln.System {
							existingVulns[i].SetScanType(scanType, vuln.SnykID)
							for k, v := range vuln.OthersID {
								existingVulns[i].OthersID[k] = v
							}
						}

					}
				}
			}
			continue
		}
		if vuln.GOID != "" {
			if !existingGOs[vuln.GOID+"//"+vuln.System] {
				existingVulns = append(existingVulns, vuln)
			} else {
				for i, vul := range existingVulns {
					if vul.GOID == vuln.GOID {
						if vul.System == vuln.System {
							existingVulns[i].SetScanType(scanType, vuln.SnykID)
							for k, v := range vuln.OthersID {
								existingVulns[i].OthersID[k] = v
							}
						}

					}
				}
			}
			continue
		}
		if vuln.OthersID != nil {
			existingVulns = append(existingVulns, vuln)
		}

	}

	return existingVulns

}

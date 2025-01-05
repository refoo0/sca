package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/refoo0/sca/scan/modul"
)

// Funktion, um die Datei zu lesen und zu verarbeiten
func processJSONFile(filePath string, outputFilePath string) error {
	// Datei einlesen
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("Error by reading file: " + err.Error())
	}

	// JSON-Daten in die Struktur unmarshallen
	var inputData modul.VulnInfo
	err = json.Unmarshal(fileData, &inputData)
	if err != nil {
		return fmt.Errorf("Error by unmarshalling JSON: " + err.Error())
	}

	// Ziel-Name (Target) aus der JSON-Datei extrahieren
	project := inputData.Target

	var outputData modul.OutputFile
	if _, err := os.Stat(outputFilePath); err == nil {
		// Datei existiert, einlesen
		existingFileData, err := os.ReadFile(outputFilePath)
		if err != nil {
			return fmt.Errorf("Error by reading existing output file: " + err.Error())
		}
		err = json.Unmarshal(existingFileData, &outputData)
		if err != nil {
			return fmt.Errorf("Error by unmarshalling existing output file: " + err.Error())
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("Error checking if output file exists: " + err.Error())
	}

	// Sicherstellen, dass ProjectsVulns initialisiert ist
	if outputData.ProjectsVulns == nil {
		outputData.ProjectsVulns = make(map[string]modul.Counts)
	}

	goCount := modul.Counts{}
	npmCount := modul.Counts{}
	pythonCount := modul.Counts{}

	count := modul.Counts{}

	for _, vuln := range inputData.Vuln {
		var osv, snyk, trivy bool
		osv = vuln.Scanner.OSV
		snyk = vuln.Scanner.Snyk
		trivy = vuln.Scanner.Trivy

		id := vuln.ID

		system := vuln.System

		stdlib := vuln.StandrdLibOSV

		if osv && snyk && trivy {
			count, goCount, npmCount, pythonCount, err = updateCount(id, system, stdlib, osv, snyk, trivy, count, goCount, npmCount, pythonCount)
			if err != nil {
				return fmt.Errorf("Error updating count: " + err.Error())
			}
		} else if osv && snyk && !trivy {
			count, goCount, npmCount, pythonCount, err = updateCount(id, system, stdlib, osv, snyk, trivy, count, goCount, npmCount, pythonCount)
			if err != nil {
				return fmt.Errorf("Error updating count: " + err.Error())
			}
		} else if osv && !snyk && trivy {
			count, goCount, npmCount, pythonCount, err = updateCount(id, system, stdlib, osv, snyk, trivy, count, goCount, npmCount, pythonCount)
			if err != nil {
				return fmt.Errorf("Error updating count: " + err.Error())
			}
		} else if !osv && snyk && trivy {
			count, goCount, npmCount, pythonCount, err = updateCount(id, system, stdlib, osv, snyk, trivy, count, goCount, npmCount, pythonCount)
			if err != nil {
				return fmt.Errorf("Error updating count: " + err.Error())
			}
		} else if osv && !snyk && !trivy {
			count, goCount, npmCount, pythonCount, err = updateCount(id, system, stdlib, osv, snyk, trivy, count, goCount, npmCount, pythonCount)
			if err != nil {
				return fmt.Errorf("Error updating count: " + err.Error())
			}
		} else if !osv && snyk && !trivy {
			count, goCount, npmCount, pythonCount, err = updateCount(id, system, stdlib, osv, snyk, trivy, count, goCount, npmCount, pythonCount)
			if err != nil {
				return fmt.Errorf("Error updating count: " + err.Error())
			}
		} else if !osv && !snyk && trivy {
			count, goCount, npmCount, pythonCount, err = updateCount(id, system, stdlib, osv, snyk, trivy, count, goCount, npmCount, pythonCount)
			if err != nil {
				return fmt.Errorf("Error updating count: " + err.Error())
			}
		}

	}

	outputData.AllVulns = updateCountsModul(outputData.AllVulns, count)

	outputData.ProjectsVulns[project] = count

	if outputData.SystemsVulns == nil {
		outputData.SystemsVulns = make(map[string]modul.Counts)
	}
	outputData.SystemsVulns["Go"] = updateCountsModul(outputData.SystemsVulns["Go"], goCount)
	outputData.SystemsVulns["Npm"] = updateCountsModul(outputData.SystemsVulns["Npm"], npmCount)
	outputData.SystemsVulns["Pypi"] = updateCountsModul(outputData.SystemsVulns["Pypi"], pythonCount)

	err = WriteJSONFile(outputFilePath, outputData)
	if err != nil {
		return fmt.Errorf("Error by writing output file: " + err.Error())
	}

	fmt.Printf("Erfolgreich Ausgabedatei aktualisiert: %s\n", outputFilePath)
	return nil
}

// Funktion, um die Funktion processJSONFile für jede JSON-Datei in einem Ordner auszuführen
func Generate(inputDirPath, outputFilePath string) {
	// Überprüfen, ob der angegebene Pfad ein Verzeichnis ist
	files, err := os.ReadDir(inputDirPath)
	if err != nil {
		fmt.Printf("Fehler beim Lesen des Verzeichnisses %s: %v\n", inputDirPath, err)
		return
	}

	// Iteriere durch alle Dateien im Verzeichnis
	for _, file := range files {
		// Überprüfen, ob es sich um eine JSON-Datei handelt (mit .json-Endung)
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") {
			// Erstelle den vollständigen Pfad zur Datei
			inputFilePath := fmt.Sprintf("%s/%s", inputDirPath, file.Name())
			fmt.Printf("Verarbeite Datei: %s\n", inputFilePath)

			// Prozessiere die JSON-Datei
			err := processJSONFile(inputFilePath, outputFilePath)
			if err != nil {
				fmt.Printf("Fehler beim Verarbeiten der Datei %s: %v\n", inputFilePath, err)
			}
		}
	}
}

func updateCount(id, system string, stdlib, osv, snyk, trivy bool, count, goCount, npmCount, pythonCount modul.Counts) (modul.Counts, modul.Counts, modul.Counts, modul.Counts, error) {

	idPräfix := id[:4]

	if osv && snyk && trivy {
		count.Sum++

		count.All++

		count.CountOSV++
		count.CountSnyk++
		count.CountTrivy++

		count.IDsAll = append(count.IDsAll, id)

		if idPräfix == "CVE-" {
			count.CVEIDsCount++

			count.CVEIDsCountOSV++
			count.CVEIDsCountSnyk++
			count.CVEIDsCountTrivy++
		} else if idPräfix == "GHSA" {
			count.GHSAIDsCount++

			count.GHSAIDsCountOSV++
			count.GhsaIDsCountSnyk++
			count.GhsaIDsCountTrivy++
		} else {
			count.OtherIDsCount++

			count.OtherIDsCountOSV++
			count.OtherIDsCountSnyk++
			count.OtherIDsCountTrivy++
		}

		if system == "Go" {
			goCount.Sum++

			goCount.All++

			goCount.CountOSV++
			goCount.CountSnyk++
			goCount.CountTrivy++

			goCount.IDsAll = append(goCount.IDsAll, id)

			if idPräfix == "CVE-" {
				goCount.CVEIDsCount++

				goCount.CVEIDsCountOSV++
				goCount.CVEIDsCountSnyk++
				goCount.CVEIDsCountTrivy++
			} else if idPräfix == "GHSA" {
				goCount.GHSAIDsCount++

				goCount.GHSAIDsCountOSV++
				goCount.GhsaIDsCountSnyk++
				goCount.GhsaIDsCountTrivy++
			} else {
				goCount.OtherIDsCount++

				goCount.OtherIDsCountOSV++
				goCount.OtherIDsCountSnyk++
				goCount.OtherIDsCountTrivy++
			}

		} else if system == "Npm" {
			npmCount.Sum++

			npmCount.All++

			npmCount.CountOSV++
			npmCount.CountSnyk++
			npmCount.CountTrivy++

			npmCount.IDsAll = append(npmCount.IDsAll, id)

			if idPräfix == "CVE-" {
				npmCount.CVEIDsCount++

				npmCount.CVEIDsCountOSV++
				npmCount.CVEIDsCountSnyk++
				npmCount.CVEIDsCountTrivy++
			} else if idPräfix == "GHSA" {
				npmCount.GHSAIDsCount++

				npmCount.GHSAIDsCountOSV++
				npmCount.GhsaIDsCountSnyk++
				npmCount.GhsaIDsCountTrivy++
			} else {
				npmCount.OtherIDsCount++

				npmCount.OtherIDsCountOSV++
				npmCount.OtherIDsCountSnyk++
				npmCount.OtherIDsCountTrivy++
			}

		} else if system == "Pypi" {
			pythonCount.Sum++

			pythonCount.All++

			pythonCount.CountOSV++
			pythonCount.CountSnyk++
			pythonCount.CountTrivy++

			pythonCount.IDsAll = append(pythonCount.IDsAll, id)

			if idPräfix == "CVE-" {
				pythonCount.CVEIDsCount++

				pythonCount.CVEIDsCountOSV++
				pythonCount.CVEIDsCountSnyk++
				pythonCount.CVEIDsCountTrivy++
			} else if idPräfix == "GHSA" {
				pythonCount.GHSAIDsCount++

				pythonCount.GHSAIDsCountOSV++
				pythonCount.GhsaIDsCountSnyk++
				pythonCount.GhsaIDsCountTrivy++
			} else {
				pythonCount.OtherIDsCount++

				pythonCount.OtherIDsCountOSV++
				pythonCount.OtherIDsCountSnyk++
				pythonCount.OtherIDsCountTrivy++
			}
		} else {
			return count, goCount, npmCount, pythonCount, fmt.Errorf("system not supported")
		}

	} else if osv && snyk && !trivy {
		count.Sum++

		count.OSV_Snyk++

		count.CountOSV++
		count.CountSnyk++

		count.IDsOSV_Snyk = append(count.IDsOSV_Snyk, id)

		if idPräfix == "CVE-" {
			count.CVEIDsCount++

			count.CVEIDsCountOSV++
			count.CVEIDsCountSnyk++
		} else if idPräfix == "GHSA" {
			count.GHSAIDsCount++

			count.GHSAIDsCountOSV++
			count.GhsaIDsCountSnyk++

		} else {
			count.OtherIDsCount++

			count.OtherIDsCountOSV++
			count.OtherIDsCountSnyk++

		}

		if system == "Go" {
			goCount.Sum++

			goCount.OSV_Snyk++

			goCount.CountOSV++
			goCount.CountSnyk++

			goCount.IDsOSV_Snyk = append(goCount.IDsOSV_Snyk, id)

			if idPräfix == "CVE-" {
				goCount.CVEIDsCount++

				goCount.CVEIDsCountOSV++
				goCount.CVEIDsCountSnyk++
			} else if idPräfix == "GHSA" {
				goCount.GHSAIDsCount++

				goCount.GHSAIDsCountOSV++
				goCount.GhsaIDsCountSnyk++

			} else {
				goCount.OtherIDsCount++

				goCount.OtherIDsCountOSV++
				goCount.OtherIDsCountSnyk++
			}

		} else if system == "Npm" {
			npmCount.Sum++

			npmCount.OSV_Snyk++

			npmCount.CountOSV++
			npmCount.CountSnyk++

			npmCount.IDsOSV_Snyk = append(npmCount.IDsOSV_Snyk, id)

			if idPräfix == "CVE-" {
				npmCount.CVEIDsCount++

				npmCount.CVEIDsCountOSV++
				npmCount.CVEIDsCountSnyk++
			} else if idPräfix == "GHSA" {
				npmCount.GHSAIDsCount++

				npmCount.GHSAIDsCountOSV++
				npmCount.GhsaIDsCountSnyk++

			} else {
				npmCount.OtherIDsCount++

				npmCount.OtherIDsCountOSV++
				npmCount.OtherIDsCountSnyk++
			}
		} else if system == "Pypi" {
			pythonCount.Sum++

			pythonCount.OSV_Snyk++

			pythonCount.CountOSV++
			pythonCount.CountSnyk++

			pythonCount.IDsOSV_Snyk = append(pythonCount.IDsOSV_Snyk, id)

			if idPräfix == "CVE-" {
				pythonCount.CVEIDsCount++

				pythonCount.CVEIDsCountOSV++
				pythonCount.CVEIDsCountSnyk++
			} else if idPräfix == "GHSA" {
				pythonCount.GHSAIDsCount++

				pythonCount.GHSAIDsCountOSV++
				pythonCount.GhsaIDsCountSnyk++

			} else {
				pythonCount.OtherIDsCount++

				pythonCount.OtherIDsCountOSV++
				pythonCount.OtherIDsCountSnyk++
			}
		} else {
			return count, goCount, npmCount, pythonCount, fmt.Errorf("system not supported")
		}
	} else if osv && trivy && !snyk {
		count.Sum++

		count.OSV_Trivy++

		count.CountOSV++
		count.CountTrivy++

		count.IDsOSV_Trivy = append(count.IDsOSV_Trivy, id)

		if idPräfix == "CVE-" {
			count.CVEIDsCount++

			count.CVEIDsCountOSV++
			count.CVEIDsCountTrivy++
		} else if idPräfix == "GHSA" {
			count.GHSAIDsCount++

			count.GHSAIDsCountOSV++
			count.GhsaIDsCountTrivy++
		} else {

			count.OtherIDsCount++

			count.OtherIDsCountOSV++
			count.OtherIDsCountTrivy++
		}

		if system == "Go" {
			goCount.Sum++

			goCount.OSV_Trivy++

			goCount.CountOSV++
			goCount.CountTrivy++

			goCount.IDsOSV_Trivy = append(goCount.IDsOSV_Trivy, id)

			if idPräfix == "CVE-" {
				goCount.CVEIDsCount++

				goCount.CVEIDsCountOSV++
				goCount.CVEIDsCountTrivy++
			} else if idPräfix == "GHSA" {
				goCount.GHSAIDsCount++

				goCount.GHSAIDsCountOSV++
				goCount.GhsaIDsCountTrivy++
			} else {
				goCount.OtherIDsCount++

				goCount.OtherIDsCountOSV++
				goCount.OtherIDsCountTrivy++
			}

		} else if system == "Npm" {
			npmCount.Sum++

			npmCount.OSV_Trivy++

			npmCount.CountOSV++
			npmCount.CountTrivy++

			npmCount.IDsOSV_Trivy = append(npmCount.IDsOSV_Trivy, id)

			if idPräfix == "CVE-" {
				npmCount.CVEIDsCount++

				npmCount.CVEIDsCountOSV++
				npmCount.CVEIDsCountTrivy++
			} else if idPräfix == "GHSA" {
				npmCount.GHSAIDsCount++

				npmCount.GHSAIDsCountOSV++
				npmCount.GhsaIDsCountTrivy++
			} else {
				npmCount.OtherIDsCount++

				npmCount.OtherIDsCountOSV++
				npmCount.OtherIDsCountTrivy++
			}
		} else if system == "Pypi" {
			pythonCount.Sum++

			pythonCount.OSV_Trivy++

			pythonCount.CountOSV++
			pythonCount.CountTrivy++

			pythonCount.IDsOSV_Trivy = append(pythonCount.IDsOSV_Trivy, id)

			if idPräfix == "CVE-" {
				pythonCount.CVEIDsCount++

				pythonCount.CVEIDsCountOSV++
				pythonCount.CVEIDsCountTrivy++
			} else if idPräfix == "GHSA" {
				pythonCount.GHSAIDsCount++

				pythonCount.GHSAIDsCountOSV++
				pythonCount.GhsaIDsCountTrivy++
			} else {
				pythonCount.OtherIDsCount++

				pythonCount.OtherIDsCountOSV++
				pythonCount.OtherIDsCountTrivy++
			}
		} else {
			return count, goCount, npmCount, pythonCount, fmt.Errorf("system not supported")
		}
	} else if snyk && trivy && !osv {
		count.Sum++

		count.Snyk_Trivy++

		count.CountSnyk++
		count.CountTrivy++

		count.IDsSnyk_Trivy = append(count.IDsSnyk_Trivy, id)

		if system == "Go" {
			goCount.Sum++

			goCount.Snyk_Trivy++

			goCount.CountSnyk++
			goCount.CountTrivy++

			goCount.IDsSnyk_Trivy = append(goCount.IDsSnyk_Trivy, id)

			if idPräfix == "CVE-" {
				goCount.CVEIDsCount++

				goCount.CVEIDsCountSnyk++
				goCount.CVEIDsCountTrivy++
			} else if idPräfix == "GHSA" {
				goCount.GHSAIDsCount++

				goCount.GhsaIDsCountSnyk++
				goCount.GhsaIDsCountTrivy++
			} else {
				goCount.OtherIDsCount++

				goCount.OtherIDsCountSnyk++
				goCount.OtherIDsCountTrivy++
			}

		} else if system == "Npm" {
			npmCount.Sum++

			npmCount.Snyk_Trivy++

			npmCount.CountSnyk++
			npmCount.CountTrivy++

			npmCount.IDsSnyk_Trivy = append(npmCount.IDsSnyk_Trivy, id)

			if idPräfix == "CVE-" {
				npmCount.CVEIDsCount++

				npmCount.CVEIDsCountSnyk++
				npmCount.CVEIDsCountTrivy++
			} else if idPräfix == "GHSA" {
				npmCount.GHSAIDsCount++

				npmCount.GhsaIDsCountSnyk++
				npmCount.GhsaIDsCountTrivy++
			} else {
				npmCount.OtherIDsCount++

				npmCount.OtherIDsCountSnyk++
				npmCount.OtherIDsCountTrivy++
			}
		} else if system == "Pypi" {
			pythonCount.Sum++

			pythonCount.Snyk_Trivy++

			pythonCount.CountSnyk++
			pythonCount.CountTrivy++

			pythonCount.IDsSnyk_Trivy = append(pythonCount.IDsSnyk_Trivy, id)

			if idPräfix == "CVE-" {
				pythonCount.CVEIDsCount++

				pythonCount.CVEIDsCountSnyk++
				pythonCount.CVEIDsCountTrivy++
			} else if idPräfix == "GHSA" {
				pythonCount.GHSAIDsCount++

				pythonCount.GhsaIDsCountSnyk++
				pythonCount.GhsaIDsCountTrivy++
			} else {
				pythonCount.OtherIDsCount++

				pythonCount.OtherIDsCountSnyk++
				pythonCount.OtherIDsCountTrivy++
			}
		} else {
			return count, goCount, npmCount, pythonCount, fmt.Errorf("system not supported")
		}
	} else if osv && !snyk && !trivy {
		count.Sum++

		count.OnlyOSV++

		count.CountOSV++

		count.IDsOnlyOSV = append(count.IDsOnlyOSV, id)

		if idPräfix == "CVE-" {
			count.CVEIDsCount++

			count.CVEIDsCountOSV++
		} else if idPräfix == "GHSA" {
			count.GHSAIDsCount++

			count.GHSAIDsCountOSV++
		} else {
			count.OtherIDsCount++

			count.OtherIDsCountOSV++
		}

		if system == "Go" {
			if stdlib {
				goCount.StdLibOSVOnly++
			} else {
				goCount.IDsOnlyOSVNotStdLib = append(goCount.IDsOnlyOSVNotStdLib, id)
			}

			goCount.Sum++

			goCount.CountOSV++

			goCount.OnlyOSV++

			goCount.IDsOnlyOSV = append(goCount.IDsOnlyOSV, id)

			if idPräfix == "CVE-" {
				goCount.CVEIDsCount++

				goCount.CVEIDsCountOSV++
			} else if idPräfix == "GHSA" {
				goCount.GHSAIDsCount++

				goCount.GHSAIDsCountOSV++
			} else {
				goCount.OtherIDsCount++

				goCount.OtherIDsCountOSV++
			}

		} else if system == "Npm" {
			npmCount.Sum++

			npmCount.CountOSV++

			npmCount.OnlyOSV++

			npmCount.IDsOnlyOSV = append(npmCount.IDsOnlyOSV, id)

			if idPräfix == "CVE-" {
				npmCount.CVEIDsCount++

				npmCount.CVEIDsCountOSV++
			} else if idPräfix == "GHSA" {
				npmCount.GHSAIDsCount++

				npmCount.GHSAIDsCountOSV++
			} else {
				npmCount.OtherIDsCount++

				npmCount.OtherIDsCountOSV++
			}
		} else if system == "Pypi" {
			pythonCount.Sum++

			pythonCount.CountOSV++

			pythonCount.OnlyOSV++

			pythonCount.IDsOnlyOSV = append(pythonCount.IDsOnlyOSV, id)

			if idPräfix == "CVE-" {
				pythonCount.CVEIDsCount++

				pythonCount.CVEIDsCountOSV++
			} else if idPräfix == "GHSA" {
				pythonCount.GHSAIDsCount++

				pythonCount.GHSAIDsCountOSV++
			} else {
				pythonCount.OtherIDsCount++

				pythonCount.OtherIDsCountOSV++
			}
		} else {
			return count, goCount, npmCount, pythonCount, fmt.Errorf("system not supported")
		}
	} else if snyk && !osv && !trivy {
		count.Sum++

		count.OnlySnyk++

		count.CountSnyk++

		count.IDsOnlySnyk = append(count.IDsOnlySnyk, id)

		if idPräfix == "CVE-" {
			count.CVEIDsCount++

			count.CVEIDsCountSnyk++
		} else if idPräfix == "GHSA" {
			count.GHSAIDsCount++

			count.GhsaIDsCountSnyk++

		} else {
			count.OtherIDsCount++

			count.OtherIDsCountSnyk++
		}

		if system == "Go" {
			goCount.Sum++

			goCount.CountSnyk++

			goCount.OnlySnyk++

			goCount.IDsOnlySnyk = append(goCount.IDsOnlySnyk, id)

			if idPräfix == "CVE-" {
				goCount.CVEIDsCount++

				goCount.CVEIDsCountSnyk++
			} else if idPräfix == "GHSA" {
				goCount.GHSAIDsCount++

				goCount.GhsaIDsCountSnyk++

			} else {
				goCount.OtherIDsCount++

				goCount.OtherIDsCountSnyk++
			}

		} else if system == "Npm" {
			npmCount.Sum++

			npmCount.CountSnyk++

			npmCount.OnlySnyk++

			npmCount.IDsOnlySnyk = append(npmCount.IDsOnlySnyk, id)

			if idPräfix == "CVE-" {
				npmCount.CVEIDsCount++

				npmCount.CVEIDsCountSnyk++
			} else if idPräfix == "GHSA" {
				npmCount.GHSAIDsCount++

				npmCount.GhsaIDsCountSnyk++

			} else {
				npmCount.OtherIDsCount++

				npmCount.OtherIDsCountSnyk++
			}
		} else if system == "Pypi" {
			pythonCount.Sum++

			pythonCount.CountSnyk++

			pythonCount.OnlySnyk++

			pythonCount.IDsOnlySnyk = append(pythonCount.IDsOnlySnyk, id)

			if idPräfix == "CVE-" {
				pythonCount.CVEIDsCount++

				pythonCount.CVEIDsCountSnyk++
			} else if idPräfix == "GHSA" {
				pythonCount.GHSAIDsCount++

				pythonCount.GhsaIDsCountSnyk++
			} else {
				pythonCount.OtherIDsCount++

				pythonCount.OtherIDsCountSnyk++
			}

		} else {
			return count, goCount, npmCount, pythonCount, fmt.Errorf("system not supported")
		}
	} else if trivy && !osv && !snyk {
		count.Sum++

		count.OnlyTrivy++

		count.CountTrivy++

		count.IDsOnlyTrivy = append(count.IDsOnlyTrivy, id)

		if idPräfix == "CVE-" {
			count.CVEIDsCount++

			count.CVEIDsCountTrivy++
		} else if idPräfix == "GHSA" {
			count.GHSAIDsCount++

			count.GhsaIDsCountTrivy++
		} else {
			count.OtherIDsCount++

			count.OtherIDsCountTrivy++
		}

		if system == "Go" {
			goCount.Sum++

			goCount.CountTrivy++

			goCount.OnlyTrivy++

			goCount.IDsOnlyTrivy = append(goCount.IDsOnlyTrivy, id)

			if idPräfix == "CVE-" {
				goCount.CVEIDsCount++

				goCount.CVEIDsCountTrivy++
			} else if idPräfix == "GHSA" {
				goCount.GHSAIDsCount++

				goCount.GhsaIDsCountTrivy++
			} else {
				goCount.OtherIDsCount++

				goCount.OtherIDsCountTrivy++
			}

		} else if system == "Npm" {
			npmCount.Sum++

			npmCount.CountTrivy++

			npmCount.OnlyTrivy++

			npmCount.IDsOnlyTrivy = append(npmCount.IDsOnlyTrivy, id)

			if idPräfix == "CVE-" {
				npmCount.CVEIDsCount++

				npmCount.CVEIDsCountTrivy++
			} else if idPräfix == "GHSA" {
				npmCount.GHSAIDsCount++

				npmCount.GhsaIDsCountTrivy++
			} else {
				npmCount.OtherIDsCount++

				npmCount.OtherIDsCountTrivy++
			}
		} else if system == "Pypi" {
			pythonCount.Sum++

			pythonCount.CountTrivy++

			pythonCount.OnlyTrivy++

			pythonCount.IDsOnlyTrivy = append(pythonCount.IDsOnlyTrivy, id)

			if idPräfix == "CVE-" {
				pythonCount.CVEIDsCount++

				pythonCount.CVEIDsCountTrivy++
			} else if idPräfix == "GHSA" {
				pythonCount.GHSAIDsCount++

				pythonCount.GhsaIDsCountTrivy++
			} else {
				pythonCount.OtherIDsCount++

				pythonCount.OtherIDsCountTrivy++
			}
		} else {
			return count, goCount, npmCount, pythonCount, fmt.Errorf("system not supported")
		}
	}

	return count, goCount, npmCount, pythonCount, nil
}

func updateCountsModul(existing modul.Counts, new modul.Counts) modul.Counts {

	existing.CountOSV += new.CountOSV
	existing.CountSnyk += new.CountSnyk
	existing.CountTrivy += new.CountTrivy

	existing.Sum += new.Sum

	existing.OnlyOSV += new.OnlyOSV
	existing.OnlySnyk += new.OnlySnyk
	existing.OnlyTrivy += new.OnlyTrivy
	existing.OSV_Snyk += new.OSV_Snyk
	existing.OSV_Trivy += new.OSV_Trivy
	existing.Snyk_Trivy += new.Snyk_Trivy

	existing.All += new.All

	existing.IDsOnlyOSV = append(existing.IDsOnlyOSV, new.IDsOnlyOSV...)
	existing.IDsOnlySnyk = append(existing.IDsOnlySnyk, new.IDsOnlySnyk...)
	existing.IDsOnlyTrivy = append(existing.IDsOnlyTrivy, new.IDsOnlyTrivy...)
	existing.IDsOSV_Snyk = append(existing.IDsOSV_Snyk, new.IDsOSV_Snyk...)
	existing.IDsOSV_Trivy = append(existing.IDsOSV_Trivy, new.IDsOSV_Trivy...)
	existing.IDsSnyk_Trivy = append(existing.IDsSnyk_Trivy, new.IDsSnyk_Trivy...)
	existing.IDsAll = append(existing.IDsAll, new.IDsAll...)

	existing.CVEIDsCount += new.CVEIDsCount
	existing.GHSAIDsCount += new.GHSAIDsCount
	existing.OtherIDsCount += new.OtherIDsCount

	existing.CVEIDsCountOSV += new.CVEIDsCountOSV
	existing.CVEIDsCountSnyk += new.CVEIDsCountSnyk
	existing.CVEIDsCountTrivy += new.CVEIDsCountTrivy

	existing.GHSAIDsCountOSV += new.GHSAIDsCountOSV
	existing.GhsaIDsCountSnyk += new.GhsaIDsCountSnyk
	existing.GhsaIDsCountTrivy += new.GhsaIDsCountTrivy

	existing.OtherIDsCountOSV += new.OtherIDsCountOSV
	existing.OtherIDsCountSnyk += new.OtherIDsCountSnyk
	existing.OtherIDsCountTrivy += new.OtherIDsCountTrivy

	existing.StdLibOSVOnly += new.StdLibOSVOnly
	existing.IDsOnlyOSVNotStdLib = append(existing.IDsOnlyOSVNotStdLib, new.IDsOnlyOSVNotStdLib...)

	return existing
}

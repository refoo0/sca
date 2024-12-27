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
			count, goCount, npmCount, pythonCount = updateAllCounts(id, system, stdlib, osv, snyk, trivy, count, goCount, npmCount, pythonCount)

		} else if osv && snyk && !trivy {
			count, goCount, npmCount, pythonCount = updateAllCounts(id, system, stdlib, osv, snyk, trivy, count, goCount, npmCount, pythonCount)

		} else if osv && !snyk && trivy {
			count, goCount, npmCount, pythonCount = updateAllCounts(id, system, stdlib, osv, snyk, trivy, count, goCount, npmCount, pythonCount)

		} else if !osv && snyk && trivy {
			count, goCount, npmCount, pythonCount = updateAllCounts(id, system, stdlib, osv, snyk, trivy, count, goCount, npmCount, pythonCount)

		} else if osv && !snyk && !trivy {
			count, goCount, npmCount, pythonCount = updateAllCounts(id, system, stdlib, osv, snyk, trivy, count, goCount, npmCount, pythonCount)

		} else if !osv && snyk && !trivy {
			count, goCount, npmCount, pythonCount = updateAllCounts(id, system, stdlib, osv, snyk, trivy, count, goCount, npmCount, pythonCount)

		} else if !osv && !snyk && trivy {
			count, goCount, npmCount, pythonCount = updateAllCounts(id, system, stdlib, osv, snyk, trivy, count, goCount, npmCount, pythonCount)

		}

		if id[:4] == "CVE-" {
			count.CVEIDsCount++
			if system == "Go" {
				goCount.CVEIDsCount++
			} else if system == "Npm" {
				npmCount.CVEIDsCount++
			} else if system == "Pypi" {
				pythonCount.CVEIDsCount++
			}
		} else if id[:4] == "GHSA" {
			count.GHSAIDsCount++
			if system == "Go" {
				goCount.GHSAIDsCount++
			} else if system == "Npm" {
				npmCount.GHSAIDsCount++
			} else if system == "Pypi" {
				pythonCount.GHSAIDsCount++
			}

		} else {
			count.OtherIDsCount++
			if system == "Go" {
				goCount.OtherIDsCount++
			} else if system == "Npm" {
				npmCount.OtherIDsCount++
			} else if system == "Pypi" {
				pythonCount.OtherIDsCount++
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

func updateAllCounts(id, system string, stdlib, osv, snyk, trivy bool, count, goCount, npmCount, pythonCount modul.Counts) (modul.Counts, modul.Counts, modul.Counts, modul.Counts) {

	co := updateCount(id, "", stdlib, osv, snyk, trivy, count)

	var goCo, npmCo, pythonCo modul.Counts
	if system == "Go" {
		goCo = updateCount(id, system, stdlib, osv, snyk, trivy, goCount)
	}
	if system == "Npm" {
		npmCo = updateCount(id, system, stdlib, osv, snyk, trivy, npmCount)
	}
	if system == "Pypi" {
		pythonCo = updateCount(id, system, stdlib, osv, snyk, trivy, pythonCount)
	}

	return co, goCo, npmCo, pythonCo
}

func updateCount(id, system string, stdlib, osv, snyk, trivy bool, count modul.Counts) modul.Counts {

	if osv && snyk && trivy {
		count.Sum++

		count.All++

		count.CountOSV++
		count.CountSnyk++
		count.CountTrivy++

		count.IDsAll = append(count.IDsAll, id)

		if system == "Go" {
			count.IDsAll = append(count.IDsAll, id)
		} else if system == "Npm" {
			count.IDsAll = append(count.IDsAll, id)
		} else if system == "Pypi" {
			count.IDsAll = append(count.IDsAll, id)
		} else {
			count.IDsAll = append(count.IDsAll, id)
		}

	} else if osv && snyk && !trivy {
		count.Sum++

		count.OSV_Snyk++

		count.CountOSV++
		count.CountSnyk++

		count.IDsOSV_Snyk = append(count.IDsOSV_Snyk, id)

		if system == "Go" {
			count.IDsOSV_Snyk = append(count.IDsOSV_Snyk, id)

		} else if system == "Npm" {
			count.IDsOSV_Snyk = append(count.IDsOSV_Snyk, id)
		} else if system == "Pypi" {
			count.IDsOSV_Snyk = append(count.IDsOSV_Snyk, id)
		} else {
			count.IDsOSV_Snyk = append(count.IDsOSV_Snyk, id)
		}
	} else if osv && trivy && !snyk {
		count.Sum++

		count.OSV_Trivy++

		count.CountOSV++
		count.CountTrivy++

		count.IDsOSV_Trivy = append(count.IDsOSV_Trivy, id)

		if system == "Go" {
			count.IDsOSV_Trivy = append(count.IDsOSV_Trivy, id)

		} else if system == "Npm" {
			count.IDsOSV_Trivy = append(count.IDsOSV_Trivy, id)
		} else if system == "Pypi" {
			count.IDsOSV_Trivy = append(count.IDsOSV_Trivy, id)
		} else {
			count.IDsOSV_Trivy = append(count.IDsOSV_Trivy, id)
		}
	} else if snyk && trivy && !osv {
		count.Sum++

		count.Snyk_Trivy++

		count.CountSnyk++
		count.CountTrivy++

		count.IDsSnyk_Trivy = append(count.IDsSnyk_Trivy, id)

		if system == "Go" {
			count.IDsSnyk_Trivy = append(count.IDsSnyk_Trivy, id)

		} else if system == "Npm" {
			count.IDsSnyk_Trivy = append(count.IDsSnyk_Trivy, id)
		} else if system == "Pypi" {
			count.IDsSnyk_Trivy = append(count.IDsSnyk_Trivy, id)
		} else {
			count.IDsSnyk_Trivy = append(count.IDsSnyk_Trivy, id)
		}
	} else if osv && !snyk && !trivy {
		count.Sum++

		count.OnlyOSV++

		count.CountOSV++

		count.IDsOnlyOSV = append(count.IDsOnlyOSV, id)

		if system == "Go" {
			count.IDsOnlyOSV = append(count.IDsOnlyOSV, id)

			if stdlib {
				count.StdLibOSVOnly++
			}

		} else if system == "Npm" {
			count.IDsOnlyOSV = append(count.IDsOnlyOSV, id)
		} else if system == "Pypi" {
			count.IDsOnlyOSV = append(count.IDsOnlyOSV, id)
		} else {
			count.IDsOnlyOSV = append(count.IDsOnlyOSV, id)
		}
	} else if snyk && !osv && !trivy {
		count.Sum++

		count.OnlySnyk++

		count.CountSnyk++

		count.IDsOnlySnyk = append(count.IDsOnlySnyk, id)

		if system == "Go" {
			count.IDsOnlySnyk = append(count.IDsOnlySnyk, id)

		} else if system == "Npm" {
			count.IDsOnlySnyk = append(count.IDsOnlySnyk, id)
		} else if system == "Pypi" {
			count.IDsOnlySnyk = append(count.IDsOnlySnyk, id)
		} else {
			count.IDsOnlySnyk = append(count.IDsOnlySnyk, id)
		}
	} else if trivy && !osv && !snyk {
		count.Sum++

		count.OnlyTrivy++

		count.CountTrivy++

		count.IDsOnlyTrivy = append(count.IDsOnlyTrivy, id)

		if system == "Go" {
			count.IDsOnlyTrivy = append(count.IDsOnlyTrivy, id)

		} else if system == "Npm" {
			count.IDsOnlyTrivy = append(count.IDsOnlyTrivy, id)
		} else if system == "Pypi" {
			count.IDsOnlyTrivy = append(count.IDsOnlyTrivy, id)
		} else {
			count.IDsOnlyTrivy = append(count.IDsOnlyTrivy, id)
		}
	}

	return count
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

	existing.StdLibOSVOnly += new.StdLibOSVOnly

	return existing
}

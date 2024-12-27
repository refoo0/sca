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
	elseCount := modul.Counts{}

	count := modul.Counts{}

	for _, vuln := range inputData.Vuln {
		var osv, snyk, trivy bool
		osv = vuln.Scanner.OSV
		snyk = vuln.Scanner.Snyk
		trivy = vuln.Scanner.Trivy

		id := vuln.ID

		if osv && snyk && trivy {
			count, goCount, npmCount, pythonCount, elseCount = updateAllCounts(id, osv, snyk, trivy, count, goCount, npmCount, pythonCount, elseCount)

		} else if osv && snyk && !trivy {
			count, goCount, npmCount, pythonCount, elseCount = updateAllCounts(id, osv, snyk, trivy, count, goCount, npmCount, pythonCount, elseCount)

		} else if osv && !snyk && trivy {
			count, goCount, npmCount, pythonCount, elseCount = updateAllCounts(id, osv, snyk, trivy, count, goCount, npmCount, pythonCount, elseCount)

		} else if !osv && snyk && trivy {
			count, goCount, npmCount, pythonCount, elseCount = updateAllCounts(id, osv, snyk, trivy, count, goCount, npmCount, pythonCount, elseCount)

		} else if osv && !snyk && !trivy {
			count, goCount, npmCount, pythonCount, elseCount = updateAllCounts(id, osv, snyk, trivy, count, goCount, npmCount, pythonCount, elseCount)

		} else if !osv && snyk && !trivy {
			count, goCount, npmCount, pythonCount, elseCount = updateAllCounts(id, osv, snyk, trivy, count, goCount, npmCount, pythonCount, elseCount)

		} else if !osv && !snyk && trivy {
			count, goCount, npmCount, pythonCount, elseCount = updateAllCounts(id, osv, snyk, trivy, count, goCount, npmCount, pythonCount, elseCount)

		}

		if id[:4] == "CVE-" {
			count.CVEIDsCount++
		} else if id[:4] == "GHSA" {
			count.GHSAIDsCount++
		} else {
			count.OtherIDsCount++
		}
	}

	outputData.AllVulns = updateCountsModul(outputData.AllVulns, count)

	outputData.ProjectsVulns[project] = count

	outputData.SystemsVulns = make(map[string]modul.Counts)
	outputData.SystemsVulns["Go"] = updateCountsModul(outputData.SystemsVulns["Go"], goCount)
	outputData.SystemsVulns["Npm"] = updateCountsModul(outputData.SystemsVulns["Npm"], npmCount)
	outputData.SystemsVulns["Pypi"] = updateCountsModul(outputData.SystemsVulns["Pypi"], pythonCount)
	outputData.SystemsVulns["Others"] = updateCountsModul(outputData.SystemsVulns["Others"], elseCount)

	// Überprüfen, ob die Ausgabedatei existiert
	if _, err := os.Stat(outputFilePath); err == nil {
		// Datei existiert, also einlesen
		existingFileData, err := os.ReadFile(outputFilePath)
		if err != nil {
			return fmt.Errorf("Error by reading existing output file: " + err.Error())
		}

		// Unmarshal der bestehenden Ausgabedaten
		err = json.Unmarshal(existingFileData, &outputData)
		if err != nil {
			return fmt.Errorf("Error by unmarshalling existing output file: " + err.Error())
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("Error checking if output file exists: " + err.Error())
	}

	// JSON-Daten in die Datei schreiben
	fileContent, err := json.MarshalIndent(outputData, "", "  ")
	if err != nil {
		return fmt.Errorf("Error by marshalling JSON: " + err.Error())
	}

	err = os.WriteFile(outputFilePath, fileContent, 0644)
	if err != nil {
		return fmt.Errorf("Error by writing file: " + err.Error())
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

func updateAllCounts(id string, osv, snyk, trivy bool, count, goCount, npmCount, pythonCount, elseCount modul.Counts) (modul.Counts, modul.Counts, modul.Counts, modul.Counts, modul.Counts) {
	co := updateCount(id, osv, snyk, trivy, count)
	goCo := updateCount(id, osv, snyk, trivy, goCount)
	npmCo := updateCount(id, osv, snyk, trivy, npmCount)
	pythonCo := updateCount(id, osv, snyk, trivy, pythonCount)
	elseCo := updateCount(id, osv, snyk, trivy, elseCount)

	return co, goCo, npmCo, pythonCo, elseCo
}

func updateCount(id string, osv bool, snyk bool, trivy bool, count modul.Counts) modul.Counts {
	if osv && snyk && trivy {
		count.Sum++

		count.All++

		count.CountOSV++
		count.CountSnyk++
		count.CountTrivy++

		count.IDsAll = append(count.IDsAll, id)
	} else if osv && snyk && !trivy {
		count.Sum++

		count.OSV_Snyk++

		count.CountOSV++
		count.CountSnyk++

		count.IDsOSV_Snyk = append(count.IDsOSV_Snyk, id)
	} else if osv && trivy && !snyk {
		count.Sum++

		count.OSV_Trivy++

		count.CountOSV++
		count.CountTrivy++

		count.IDsOSV_Trivy = append(count.IDsOSV_Trivy, id)
	} else if snyk && trivy && !osv {
		count.Sum++

		count.Snyk_Trivy++

		count.CountSnyk++
		count.CountTrivy++

		count.IDsSnyk_Trivy = append(count.IDsSnyk_Trivy, id)
	} else if osv && !snyk && !trivy {
		count.Sum++

		count.OnlyOSV++

		count.CountOSV++

		count.IDsOnlyOSV = append(count.IDsOnlyOSV, id)
	} else if snyk && !osv && !trivy {
		count.Sum++

		count.OnlySnyk++

		count.CountSnyk++

		count.IDsOnlySnyk = append(count.IDsOnlySnyk, id)
	} else if trivy && !osv && !snyk {
		count.Sum++

		count.OnlyTrivy++

		count.CountTrivy++

		count.IDsOnlyTrivy = append(count.IDsOnlyTrivy, id)
	}

	return count
}

func updateCountsModul(existing modul.Counts, new modul.Counts) modul.Counts {
	existing.Sum += new.Sum
	existing.All += new.All
	existing.CountOSV += new.CountOSV
	existing.CountSnyk += new.CountSnyk
	existing.CountTrivy += new.CountTrivy
	existing.OnlyOSV += new.OnlyOSV
	existing.OnlySnyk += new.OnlySnyk
	existing.OnlyTrivy += new.OnlyTrivy
	existing.OSV_Snyk += new.OSV_Snyk
	existing.OSV_Trivy += new.OSV_Trivy
	existing.Snyk_Trivy += new.Snyk_Trivy

	return existing
}

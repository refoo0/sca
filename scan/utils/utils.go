package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/refoo0/sca/scan/modul"
)

/*
// Structs für die JSON-Datei
type Counts struct {
	CountOSV     int    `json:"CountOSV"`
	CountSnyk    int    `json:"CountSnyk"`
	CountTrivy   int    `json:"CountTrivy"`
	Target       string `json:"Target"`
	TotalEntries int    `json:"TotalEntries"`
}
*/

type MiniCounts struct {
	All              int `json:"All"`
	CVEIDsCount      int `json:"CVEIDsCount"`
	CVEIDsCountOSV   int `json:"CVEIDsCountOSV"`
	CVEIDsCountSnyk  int `json:"CVEIDsCountSnyk"`
	CVEIDsCountTrivy int `json:"CVEIDsCountTrivy"`

	GOIDsCount      int `json:"GOIDsCount"`
	GOIDsCountOSV   int `json:"GOIDsCountOSV"`
	GOIDsCountSnyk  int `json:"GOIDsCountSnyk"`
	GOIDsCountTrivy int `json:"GOIDsCountTrivy"`

	GHSAsCount      int `json:"GHSAsCount"`
	GHSAsCountOSV   int `json:"GHSAsCountOSV"`
	GHSAsCountSnyk  int `json:"GHSAsCountSnyk"`
	GHSAsCountTrivy int `json:"GHSAsCountTrivy"`

	SnykIDsCount      int `json:"SnykIDsCount"`
	SnykIDsCountOSV   int `json:"SnykIDsCountOSV"`
	SnykIDsCountSnyk  int `json:"SnykIDsCountSnyk"`
	SnykIDsCountTrivy int `json:"SnykIDsCountTrivy"`

	OthersIDsCount      int `json:"OthersIDsCount"`
	OthersIDsCountOSV   int `json:"OthersIDsCountOSV"`
	OthersIDsCountSnyk  int `json:"OthersIDsCountSnyk"`
	OthersIDsCountTrivy int `json:"OthersIDsCountTrivy"`

	GoOnlyOSV    int `json:"GoOnlyOSV"`
	GoOnlySnyk   int `json:"GoOnlySnyk"`
	GoOnlyTrivy  int `json:"GoOnlyTrivy"`
	GoOSV_Snyk   int `json:"GoOSV_Snyk"`
	GoOSV_Trivy  int `json:"GoOSV_Trivy"`
	GoSnyk_Trivy int `json:"GoSnyk_Trivy"`
	GoAll        int `json:"GoAll"`

	GoOSV_TrivyIDs []string `json:"GoOSV_TrivyIDs"`
}

type Vulnerability struct {
	CVEID string `json:"CVE-ID"`
	GHSA  string `json:"GHSA"`
	GOID  string `json:"GO-ID"`
	OSV   bool   `json:"OSV"`
	Snyk  bool   `json:"Snyk"`
	Trivy bool   `json:"Trivy"`
}

type VulnsIDs struct {
	CVEID    []string `json:"CVE-ID"`
	GHSA     []string `json:"GHSA"`
	GOID     []string `json:"GO-ID"`
	SnykID   []string `json:"Snyk-ID"`
	OthersID []string `json:"Others-ID"`
}

type Counts struct {
	Sum        int `json:"Sum"`
	OnlyOSV    int `json:"OnlyOSV"`
	OnlySnyk   int `json:"OnlySnyk"`
	OnlyTrivy  int `json:"OnlyTrivy"`
	OSV_Snyk   int `json:"OSV_Snyk"`
	OSV_Trivy  int `json:"OSV_Trivy"`
	Snyk_Trivy int `json:"Snyk_Trivy"`
	All        int `json:"All"`

	IDsOnlyOSV    VulnsIDs `json:"IDsOnlyOSV"`
	IDsOnlySnyk   VulnsIDs `json:"IDsOnlySnyk"`
	IDsOnlyTrivy  VulnsIDs `json:"IDsOnlyTrivy"`
	IDsOSV_Snyk   VulnsIDs `json:"IDsOSV_Snyk"`
	IDsOSV_Trivy  VulnsIDs `json:"IDsOSV_Trivy"`
	IDsSnyk_Trivy VulnsIDs `json:"IDsSnyk_Trivy"`
	IDsAll        VulnsIDs `json:"IDsAll"`

	OnlyOSVCVEs    int `json:"OnlyOSVCVEs"`
	OnlySnykCVEs   int `json:"OnlySnykCVEs"`
	OnlyTrivyCVEs  int `json:"OnlyTrivyCVEs"`
	OSV_SnykCVEs   int `json:"OSV_SnykCVEs"`
	OSV_TrivyCVEs  int `json:"OSV_TrivyCVEs"`
	Snyk_TrivyCVEs int `json:"Snyk_TrivyCVEs"`
	AllCVEs        int `json:"AllCVEs"`

	OnlyOSVGHSA    int `json:"OnlyOSVGHSA"`
	OnlySnykGHSA   int `json:"OnlySnykGHSA"`
	OnlyTrivyGHSA  int `json:"OnlyTrivyGHSA"`
	OSV_SnykGHSA   int `json:"OSV_SnykGHSA"`
	OSV_TrivyGHSA  int `json:"OSV_TrivyGHSA"`
	Snyk_TrivyGHSA int `json:"Snyk_TrivyGHSA"`
	AllGHSA        int `json:"AllGHSA"`

	CVEIDsCount    int `json:"CVEIDsCount"`
	GOIDsCount     int `json:"GOIDsCount"`
	GHSAsCount     int `json:"GHSAsCount"`
	SnykIDsCount   int `json:"SnykIDsCount"`
	OthersIDsCount int `json:"OthersIDsCount"`

	CVEIDsCountOSV   int `json:"CVEIDsCountOSV"`
	CVEIDsCountSnyk  int `json:"CVEIDsCountSnyk"`
	CVEIDsCountTrivy int `json:"CVEIDsCountTrivy"`

	GOIDsCountOSV   int `json:"GOIDsCountOSV"`
	GOIDsCountSnyk  int `json:"GOIDsCountSnyk"`
	GOIDsCountTrivy int `json:"GOIDsCountTrivy"`

	GHSAsCountOSV   int `json:"GHSAsCountOSV"`
	GHSAsCountSnyk  int `json:"GHSAsCountSnyk"`
	GHSAsCountTrivy int `json:"GHSAsCountTrivy"`

	SnykIDsCountOSV   int `json:"SnykIDsCountOSV"`
	SnykIDsCountSnyk  int `json:"SnykIDsCountSnyk"`
	SnykIDsCountTrivy int `json:"SnykIDsCountTrivy"`

	OthersIDsCountOSV   int `json:"OthersIDsCountOSV"`
	OthersIDsCountSnyk  int `json:"OthersIDsCountSnyk"`
	OthersIDsCountTrivy int `json:"OthersIDsCountTrivy"`
}

// Neue Struktur der Ausgabedatei
type OutputFile struct {
	Counts Counts `json:"Counts"`

	GoCounts     MiniCounts `json:"GoCounts"`
	NPMCounts    MiniCounts `json:"NPMCounts"`
	PythonCounts MiniCounts `json:"PythonCounts"`
	ElseCounts   MiniCounts `json:"ElseCounts"`

	ProjectsVulns map[string]ProjectVulns `json:"ProjectsVulns"`

	AllVulnsCVEs AllVulns `json:"AllVulnsCVEs"`
	AllVulnsGHSA AllVulns `json:"AllVulnsGHSA"`

	OnlyOSVAll       int      `json:"OnlyOSVAll"`
	OnlyOSVGO        int      `json:"OnlyOSVGO"`
	OnlyOSVRest      int      `json:"OnlyOSVRest"`
	OnlyOSVStdlib    int      `json:"OnlyOSVStdlib"`
	OnlyOSVNotStdlib int      `json:"OnlyOSVNotStdlib"`
	OnlyOsvNotStdlib []string `json:"OnlyOsvNotStdlib"`
}

type AllVulns struct {
	OnlyOSV    []string `json:"OnlyOSV"`
	OnlySnyk   []string `json:"OnlySnyk"`
	OnlyTrivy  []string `json:"OnlyTrivy"`
	OSV_Snyk   []string `json:"OSV_Snyk"`
	OSV_Trivy  []string `json:"OSV_Trivy"`
	Snyk_Trivy []string `json:"Snyk_Trivy"`
	All        []string `json:"All"`
}

type ProjectVulns struct {
	CVEIDs    map[string]Scanner `json:"CVEIDs"`
	GOIDs     map[string]Scanner `json:"GOIDs"`
	GHSAs     map[string]Scanner `json:"GHSAs"`
	SnykIDs   map[string]Scanner `json:"SnykIDs"`
	OthersIDs map[string]Scanner `json:"OthersIDs"`

	CVEIDsCount    int `json:"CVEIDsCount"`
	GOIDsCount     int `json:"GOIDsCount"`
	GHSAsCount     int `json:"GHSAsCount"`
	SnykIDsCount   int `json:"SnykIDsCount"`
	OthersIDsCount int `json:"OthersIDsCount"`
}

type Scanner struct {
	OSV   bool `json:"OSV"`
	Snyk  bool `json:"Snyk"`
	Trivy bool `json:"Trivy"`
}

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
	project := inputData.Counts.Target

	var outputData OutputFile
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
		outputData.ProjectsVulns = make(map[string]ProjectVulns)
	}

	// Sicherstellen, dass das Projekt initialisiert ist
	if _, exists := outputData.ProjectsVulns[project]; !exists {
		outputData.ProjectsVulns[project] = ProjectVulns{
			CVEIDs:    make(map[string]Scanner),
			GOIDs:     make(map[string]Scanner),
			GHSAs:     make(map[string]Scanner),
			SnykIDs:   make(map[string]Scanner),
			OthersIDs: make(map[string]Scanner),
		}
	}

	projectVulns := outputData.ProjectsVulns[project]

	goCount := MiniCounts{}
	npmCount := MiniCounts{}
	pythonCount := MiniCounts{}
	elseCount := MiniCounts{}

	cveIDCountsOSV := 0
	cveIDCountsSnyk := 0
	cveIDCountsTrivy := 0

	goidCountsOSV := 0
	goidCountsSnyk := 0
	goidCountsTrivy := 0

	ghsaCountsOSV := 0
	ghsaCountsSnyk := 0
	ghsaCountsTrivy := 0

	snykIDCountsOSV := 0
	snykIDCountsSnyk := 0
	snykIDCountsTrivy := 0

	othersIDCountsOSV := 0
	othersIDCountsSnyk := 0
	othersIDCountsTrivy := 0

	idsOnlyOSV := VulnsIDs{}
	idsOnlySnyk := VulnsIDs{}
	idsOnlyTrivy := VulnsIDs{}
	idsOSV_Snyk := VulnsIDs{}
	idsOSV_Trivy := VulnsIDs{}
	idsSnyk_Trivy := VulnsIDs{}
	idsAll := VulnsIDs{}

	onlyOSVAll := 0
	onlyOSVGO := 0
	onlyOSVRest := 0
	onlyOSVNotStdlibCount := 0
	onlyOSVStdlibCount := 0
	onlyOSVNotStdlib := []string{}

	// Iteriere über die Schwachstellen
	for _, vuln := range inputData.Vuln {

		if vuln.CVEID != "" {

			if vuln.OSV && vuln.Snyk && vuln.Trivy {

				outputData.ProjectsVulns[project].CVEIDs[vuln.CVEID+" ("+vuln.System+")"] = Scanner{
					OSV:   vuln.OSV,
					Snyk:  vuln.Snyk,
					Trivy: vuln.Trivy,
				}
				cveIDCountsOSV++
				cveIDCountsSnyk++
				cveIDCountsTrivy++

				idsAll.CVEID = append(idsAll.CVEID, vuln.CVEID)

				if vuln.System == "Go" {

					goCount.All++

					goCount.CVEIDsCount++

					goCount.CVEIDsCountOSV++
					goCount.CVEIDsCountSnyk++
					goCount.CVEIDsCountTrivy++

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.CVEIDsCount++

					npmCount.CVEIDsCountOSV++
					npmCount.CVEIDsCountSnyk++
					npmCount.CVEIDsCountTrivy++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.CVEIDsCount++

					pythonCount.CVEIDsCountOSV++
					pythonCount.CVEIDsCountSnyk++
					pythonCount.CVEIDsCountTrivy++

				} else {
					elseCount.All++

					elseCount.CVEIDsCount++

					elseCount.CVEIDsCountOSV++
					elseCount.CVEIDsCountSnyk++
					elseCount.CVEIDsCountTrivy++
				}

			} else if vuln.OSV && vuln.Snyk {

				outputData.ProjectsVulns[project].CVEIDs[vuln.CVEID+" ("+vuln.System+")"] = Scanner{
					OSV:  vuln.OSV,
					Snyk: vuln.Snyk,
				}
				cveIDCountsOSV++
				cveIDCountsSnyk++

				idsOSV_Snyk.CVEID = append(idsOSV_Snyk.CVEID, vuln.CVEID)

				if vuln.System == "Go" {
					goCount.All++

					goCount.CVEIDsCount++

					goCount.CVEIDsCountOSV++
					goCount.CVEIDsCountSnyk++

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.CVEIDsCount++

					npmCount.CVEIDsCountOSV++
					npmCount.CVEIDsCountSnyk++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.CVEIDsCount++

					pythonCount.CVEIDsCountOSV++
					pythonCount.CVEIDsCountSnyk++

				} else {
					elseCount.All++

					elseCount.CVEIDsCount++

					elseCount.CVEIDsCountOSV++
					elseCount.CVEIDsCountSnyk++
				}
			} else if vuln.OSV && vuln.Trivy && !vuln.Snyk {

				outputData.ProjectsVulns[project].CVEIDs[vuln.CVEID+" ("+vuln.System+")"] = Scanner{
					OSV:   vuln.OSV,
					Trivy: vuln.Trivy,
				}
				cveIDCountsOSV++
				cveIDCountsTrivy++

				idsOSV_Trivy.CVEID = append(idsOSV_Trivy.CVEID, vuln.CVEID)

				if vuln.System == "Go" {
					goCount.All++

					goCount.CVEIDsCount++

					goCount.CVEIDsCountOSV++
					goCount.CVEIDsCountTrivy++

					goCount.GoOSV_TrivyIDs = append(goCount.GoOSV_TrivyIDs, vuln.CVEID)

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.CVEIDsCount++

					npmCount.CVEIDsCountOSV++
					npmCount.CVEIDsCountTrivy++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.CVEIDsCount++

					pythonCount.CVEIDsCountOSV++
					pythonCount.CVEIDsCountTrivy++

				} else {
					elseCount.All++

					elseCount.CVEIDsCount++

					elseCount.CVEIDsCountOSV++
					elseCount.CVEIDsCountTrivy++
				}
			} else if vuln.Snyk && vuln.Trivy {

				outputData.ProjectsVulns[project].CVEIDs[vuln.CVEID+" ("+vuln.System+")"] = Scanner{
					Snyk:  vuln.Snyk,
					Trivy: vuln.Trivy,
				}
				cveIDCountsSnyk++
				cveIDCountsTrivy++

				idsSnyk_Trivy.CVEID = append(idsSnyk_Trivy.CVEID, vuln.CVEID)

				if vuln.System == "Go" {
					goCount.All++

					goCount.CVEIDsCount++

					goCount.CVEIDsCountSnyk++
					goCount.CVEIDsCountTrivy++

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.CVEIDsCount++

					npmCount.CVEIDsCountSnyk++
					npmCount.CVEIDsCountTrivy++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.CVEIDsCount++

					pythonCount.CVEIDsCountSnyk++
					pythonCount.CVEIDsCountTrivy++

				} else {
					elseCount.All++

					elseCount.CVEIDsCount++

					elseCount.CVEIDsCountSnyk++
					elseCount.CVEIDsCountTrivy++
				}
			} else if vuln.OSV {

				outputData.ProjectsVulns[project].CVEIDs[vuln.CVEID+" ("+vuln.System+")"] = Scanner{
					OSV: vuln.OSV,
				}
				cveIDCountsOSV++

				idsOnlyOSV.CVEID = append(idsOnlyOSV.CVEID, vuln.CVEID)

				if vuln.System == "Go" {
					goCount.All++

					goCount.CVEIDsCount++

					goCount.CVEIDsCountOSV++

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.CVEIDsCount++

					npmCount.CVEIDsCountOSV++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.CVEIDsCount++

					pythonCount.CVEIDsCountOSV++

				} else {
					elseCount.All++

					elseCount.CVEIDsCount++

					elseCount.CVEIDsCountOSV++
				}
			} else if vuln.Snyk {

				outputData.ProjectsVulns[project].CVEIDs[vuln.CVEID+" ("+vuln.System+")"] = Scanner{
					Snyk: vuln.Snyk,
				}
				cveIDCountsSnyk++

				idsOnlySnyk.CVEID = append(idsOnlySnyk.CVEID, vuln.CVEID)

				if vuln.System == "Go" {
					goCount.All++

					goCount.CVEIDsCount++

					goCount.CVEIDsCountSnyk++

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.CVEIDsCount++

					npmCount.CVEIDsCountSnyk++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.CVEIDsCount++

					pythonCount.CVEIDsCountSnyk++

				} else {
					elseCount.All++

					elseCount.CVEIDsCount++

					elseCount.CVEIDsCountSnyk++
				}
			} else if vuln.Trivy {

				outputData.ProjectsVulns[project].CVEIDs[vuln.CVEID+" ("+vuln.System+")"] = Scanner{
					Trivy: vuln.Trivy,
				}
				cveIDCountsTrivy++

				idsOnlyTrivy.CVEID = append(idsOnlyTrivy.CVEID, vuln.CVEID)

				if vuln.System == "Go" {
					goCount.All++

					goCount.CVEIDsCount++

					goCount.CVEIDsCountTrivy++

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.CVEIDsCount++

					npmCount.CVEIDsCountTrivy++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.CVEIDsCount++

					pythonCount.CVEIDsCountTrivy++

				} else {
					elseCount.All++

					elseCount.CVEIDsCount++

					elseCount.CVEIDsCountTrivy++
				}
			}

		} else if vuln.GOID != "" {

			if vuln.OSV && vuln.Snyk && vuln.Trivy {
				outputData.ProjectsVulns[project].GOIDs[vuln.GOID] = Scanner{
					OSV:   vuln.OSV,
					Snyk:  vuln.Snyk,
					Trivy: vuln.Trivy,
				}
				goidCountsOSV++
				goidCountsSnyk++
				goidCountsTrivy++

				idsAll.GOID = append(idsAll.GOID, vuln.GOID)

				if vuln.System == "Go" {
					goCount.All++

					goCount.GOIDsCount++

					goCount.GOIDsCountOSV++
					goCount.GOIDsCountSnyk++
					goCount.GOIDsCountTrivy++

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.GOIDsCount++

					npmCount.GOIDsCountOSV++
					npmCount.GOIDsCountSnyk++
					npmCount.GOIDsCountTrivy++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.GOIDsCount++

					pythonCount.GOIDsCountOSV++
					pythonCount.GOIDsCountSnyk++
					pythonCount.GOIDsCountTrivy++

				} else {
					elseCount.All++

					elseCount.GOIDsCount++

					elseCount.GOIDsCountOSV++
					elseCount.GOIDsCountSnyk++
					elseCount.GOIDsCountTrivy++
				}
			} else if vuln.OSV && vuln.Snyk {
				outputData.ProjectsVulns[project].GOIDs[vuln.GOID] = Scanner{
					OSV:  vuln.OSV,
					Snyk: vuln.Snyk,
				}
				goidCountsOSV++
				goidCountsSnyk++

				if vuln.System == "Go" {
					goCount.All++

					goCount.GOIDsCount++

					goCount.GOIDsCountOSV++
					goCount.GOIDsCountSnyk++

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.GOIDsCount++

					npmCount.GOIDsCountOSV++
					npmCount.GOIDsCountSnyk++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.GOIDsCount++

					pythonCount.GOIDsCountOSV++
					pythonCount.GOIDsCountSnyk++

				} else {
					elseCount.All++

					elseCount.GOIDsCount++

					elseCount.GOIDsCountOSV++
					elseCount.GOIDsCountSnyk++
				}
			} else if vuln.OSV && vuln.Trivy && !vuln.Snyk {
				outputData.ProjectsVulns[project].GOIDs[vuln.GOID] = Scanner{
					OSV:   vuln.OSV,
					Trivy: vuln.Trivy,
				}
				goidCountsOSV++
				goidCountsTrivy++

				idsOSV_Trivy.GOID = append(idsOSV_Trivy.GOID, vuln.GOID)

				if vuln.System == "Go" {
					goCount.All++

					goCount.GOIDsCount++

					goCount.GOIDsCountOSV++
					goCount.GOIDsCountTrivy++

					goCount.GoOSV_TrivyIDs = append(goCount.GoOSV_TrivyIDs, vuln.GOID)

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.GOIDsCount++

					npmCount.GOIDsCountOSV++
					npmCount.GOIDsCountTrivy++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.GOIDsCount++

					pythonCount.GOIDsCountOSV++
					pythonCount.GOIDsCountTrivy++

				} else {
					elseCount.All++

					elseCount.GOIDsCount++

					elseCount.GOIDsCountOSV++
					elseCount.GOIDsCount++
				}
			} else if vuln.Snyk && vuln.Trivy {
				outputData.ProjectsVulns[project].GOIDs[vuln.GOID] = Scanner{
					Snyk:  vuln.Snyk,
					Trivy: vuln.Trivy,
				}
				goidCountsSnyk++
				goidCountsTrivy++

				idsSnyk_Trivy.GOID = append(idsSnyk_Trivy.GOID, vuln.GOID)

				if vuln.System == "Go" {
					goCount.All++

					goCount.GOIDsCount++

					goCount.GOIDsCountSnyk++
					goCount.GOIDsCountTrivy++

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.GOIDsCount++

					npmCount.GOIDsCountSnyk++
					npmCount.GOIDsCountTrivy++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.GOIDsCount++

					pythonCount.GOIDsCountSnyk++
					pythonCount.GOIDsCountTrivy++

				} else {
					elseCount.All++

					elseCount.GOIDsCount++

					elseCount.GOIDsCountSnyk++
					elseCount.GOIDsCountTrivy++
				}
			} else if vuln.OSV {
				outputData.ProjectsVulns[project].GOIDs[vuln.GOID] = Scanner{
					OSV: vuln.OSV,
				}
				goidCountsOSV++

				idsOnlyOSV.GOID = append(idsOnlyOSV.GOID, vuln.GOID)

				if vuln.System == "Go" {
					goCount.All++

					goCount.GOIDsCount++

					goCount.GOIDsCountOSV++

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.GOIDsCount++

					npmCount.GOIDsCountOSV++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.GOIDsCount++

					pythonCount.GOIDsCountOSV++

				} else {
					elseCount.All++

					elseCount.GOIDsCount++

					elseCount.GOIDsCountOSV++
				}
			} else if vuln.Snyk {
				outputData.ProjectsVulns[project].GOIDs[vuln.GOID] = Scanner{
					Snyk: vuln.Snyk,
				}
				goidCountsSnyk++

				idsOnlySnyk.GOID = append(idsOnlySnyk.GOID, vuln.GOID)

				if vuln.System == "Go" {
					goCount.All++

					goCount.GOIDsCount++

					goCount.GOIDsCountSnyk++

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.GOIDsCount++

					npmCount.GOIDsCountSnyk++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.GOIDsCount++

					pythonCount.GOIDsCountSnyk++

				} else {
					elseCount.All++

					elseCount.GOIDsCount++

					elseCount.GOIDsCountSnyk++
				}
			} else if vuln.Trivy {
				outputData.ProjectsVulns[project].GOIDs[vuln.GOID] = Scanner{
					Trivy: vuln.Trivy,
				}
				goidCountsTrivy++

				idsOnlyTrivy.GOID = append(idsOnlyTrivy.GOID, vuln.GOID)

				if vuln.System == "Go" {
					goCount.All++

					goCount.GOIDsCount++

					goCount.GOIDsCountTrivy++

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.GOIDsCount++

					npmCount.GOIDsCountTrivy++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.GOIDsCount++

					pythonCount.GOIDsCountTrivy++

				} else {
					elseCount.All++

					elseCount.GOIDsCount++

					elseCount.GOIDsCountTrivy++
				}
			}
		} else if vuln.GHSA != "" {

			if vuln.OSV && vuln.Snyk && vuln.Trivy {
				outputData.ProjectsVulns[project].GHSAs[vuln.GHSA] = Scanner{
					OSV:   vuln.OSV,
					Snyk:  vuln.Snyk,
					Trivy: vuln.Trivy,
				}
				ghsaCountsOSV++
				ghsaCountsSnyk++
				ghsaCountsTrivy++

				idsAll.GHSA = append(idsAll.GHSA, vuln.GHSA)

				if vuln.System == "Go" {
					goCount.All++

					goCount.GHSAsCount++

					goCount.GHSAsCountOSV++
					goCount.GHSAsCountSnyk++
					goCount.GHSAsCountTrivy++

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.GHSAsCount++

					npmCount.GHSAsCountOSV++
					npmCount.GHSAsCountSnyk++
					npmCount.GHSAsCountTrivy++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.GHSAsCount++

					pythonCount.GHSAsCountOSV++
					pythonCount.GHSAsCountSnyk++
					pythonCount.GHSAsCountTrivy++

				} else {
					elseCount.All++

					elseCount.GHSAsCount++

					elseCount.GHSAsCountOSV++
					elseCount.GHSAsCountSnyk++
					elseCount.GHSAsCountTrivy++
				}
			} else if vuln.OSV && vuln.Snyk {
				outputData.ProjectsVulns[project].GHSAs[vuln.GHSA] = Scanner{
					OSV:  vuln.OSV,
					Snyk: vuln.Snyk,
				}
				ghsaCountsOSV++
				ghsaCountsSnyk++

				idsOSV_Snyk.GHSA = append(idsOSV_Snyk.GHSA, vuln.GHSA)

				if vuln.System == "Go" {
					goCount.All++

					goCount.GHSAsCount++

					goCount.GHSAsCountOSV++
					goCount.GHSAsCountSnyk++

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.GHSAsCount++

					npmCount.GHSAsCountOSV++
					npmCount.GHSAsCountSnyk++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.GHSAsCount++

					pythonCount.GHSAsCountOSV++
					pythonCount.GHSAsCountSnyk++

				} else {
					elseCount.All++

					elseCount.GHSAsCount++

					elseCount.GHSAsCountOSV++
					elseCount.GHSAsCountSnyk++
				}

			} else if vuln.OSV && vuln.Trivy && !vuln.Snyk {
				outputData.ProjectsVulns[project].GHSAs[vuln.GHSA] = Scanner{
					OSV:   vuln.OSV,
					Trivy: vuln.Trivy,
				}
				ghsaCountsOSV++
				ghsaCountsTrivy++

				idsOSV_Trivy.GHSA = append(idsOSV_Trivy.GHSA, vuln.GHSA)

				if vuln.System == "Go" {
					goCount.All++

					goCount.GHSAsCount++

					goCount.GHSAsCountOSV++
					goCount.GHSAsCountTrivy++

					goCount.GoOSV_TrivyIDs = append(goCount.GoOSV_TrivyIDs, vuln.GHSA)

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.GHSAsCount++

					npmCount.GHSAsCountOSV++
					npmCount.GHSAsCountTrivy++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.GHSAsCount++

					pythonCount.GHSAsCountOSV++
					pythonCount.GHSAsCountTrivy++

				} else {
					elseCount.All++

					elseCount.GHSAsCount++

					elseCount.GHSAsCountOSV++
					elseCount.GHSAsCountTrivy++
				}
			} else if vuln.Snyk && vuln.Trivy {
				outputData.ProjectsVulns[project].GHSAs[vuln.GHSA] = Scanner{
					Snyk:  vuln.Snyk,
					Trivy: vuln.Trivy,
				}
				ghsaCountsSnyk++
				ghsaCountsTrivy++

				idsSnyk_Trivy.GHSA = append(idsSnyk_Trivy.GHSA, vuln.GHSA)

				if vuln.System == "Go" {
					goCount.All++

					goCount.GHSAsCount++

					goCount.GHSAsCountSnyk++
					goCount.GHSAsCountTrivy++

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.GHSAsCount++

					npmCount.GHSAsCountSnyk++
					npmCount.GHSAsCountTrivy++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.GHSAsCount++

					pythonCount.GHSAsCountSnyk++
					pythonCount.GHSAsCountTrivy++

				} else {
					elseCount.All++

					elseCount.GHSAsCount++

					elseCount.GHSAsCountSnyk++
					elseCount.GHSAsCountTrivy++
				}
			} else if vuln.OSV {
				outputData.ProjectsVulns[project].GHSAs[vuln.GHSA] = Scanner{
					OSV: vuln.OSV,
				}
				ghsaCountsOSV++

				idsOnlyOSV.GHSA = append(idsOnlyOSV.GHSA, vuln.GHSA)

				if vuln.System == "Go" {
					goCount.All++

					goCount.GHSAsCount++

					goCount.GHSAsCountOSV++

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.GHSAsCount++

					npmCount.GHSAsCountOSV++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.GHSAsCount++

					pythonCount.GHSAsCountOSV++

				} else {
					elseCount.All++

					elseCount.GHSAsCount++

					elseCount.GHSAsCountOSV++
				}

			} else if vuln.Snyk {
				outputData.ProjectsVulns[project].GHSAs[vuln.GHSA] = Scanner{
					Snyk: vuln.Snyk,
				}
				ghsaCountsSnyk++

				idsOnlySnyk.GHSA = append(idsOnlySnyk.GHSA, vuln.GHSA)

				if vuln.System == "Go" {
					goCount.All++

					goCount.GHSAsCount++

					goCount.GHSAsCountSnyk++

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.GHSAsCount++

					npmCount.GHSAsCountSnyk++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.GHSAsCount++

					pythonCount.GHSAsCountSnyk++

				} else {
					elseCount.All++

					elseCount.GHSAsCount++

					elseCount.GHSAsCountSnyk++
				}
			} else if vuln.Trivy {
				outputData.ProjectsVulns[project].GHSAs[vuln.GHSA] = Scanner{
					Trivy: vuln.Trivy,
				}
				ghsaCountsTrivy++

				idsOnlyTrivy.GHSA = append(idsOnlyTrivy.GHSA, vuln.GHSA)

				if vuln.System == "Go" {
					goCount.All++

					goCount.GHSAsCount++

					goCount.GHSAsCountTrivy++

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.GHSAsCount++

					npmCount.GHSAsCountTrivy++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.GHSAsCount++

					pythonCount.GHSAsCountTrivy++

				} else {
					elseCount.All++

					elseCount.GHSAsCount++

					elseCount.GHSAsCountTrivy++
				}
			}
		} else if vuln.SnykID != "" {

			if vuln.OSV && vuln.Snyk && vuln.Trivy {
				outputData.ProjectsVulns[project].SnykIDs[vuln.SnykID] = Scanner{
					OSV:   vuln.OSV,
					Snyk:  vuln.Snyk,
					Trivy: vuln.Trivy,
				}
				snykIDCountsOSV++
				snykIDCountsSnyk++
				snykIDCountsTrivy++

				idsAll.SnykID = append(idsAll.SnykID, vuln.SnykID)

				if vuln.System == "Go" {
					goCount.All++

					goCount.SnykIDsCount++

					goCount.SnykIDsCountOSV++
					goCount.SnykIDsCountSnyk++
					goCount.SnykIDsCountTrivy++

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.SnykIDsCount++

					npmCount.SnykIDsCountOSV++
					npmCount.SnykIDsCountSnyk++
					npmCount.SnykIDsCountTrivy++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.SnykIDsCount++

					pythonCount.SnykIDsCountOSV++
					pythonCount.SnykIDsCountSnyk++
					pythonCount.SnykIDsCountTrivy++

				} else {
					elseCount.All++

					elseCount.SnykIDsCount++

					elseCount.SnykIDsCountOSV++
					elseCount.SnykIDsCountSnyk++
					elseCount.SnykIDsCountTrivy++
				}
			} else if vuln.OSV && vuln.Snyk {
				outputData.ProjectsVulns[project].SnykIDs[vuln.SnykID] = Scanner{
					OSV:  vuln.OSV,
					Snyk: vuln.Snyk,
				}
				snykIDCountsOSV++
				snykIDCountsSnyk++

				idsOSV_Snyk.SnykID = append(idsOSV_Snyk.SnykID, vuln.SnykID)

				if vuln.System == "Go" {
					goCount.All++

					goCount.SnykIDsCount++

					goCount.SnykIDsCountOSV++
					goCount.SnykIDsCountSnyk++

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.SnykIDsCount++

					npmCount.SnykIDsCountOSV++
					npmCount.SnykIDsCountSnyk++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.SnykIDsCount++

					pythonCount.SnykIDsCountOSV++
					pythonCount.SnykIDsCountSnyk++

				} else {
					elseCount.All++

					elseCount.SnykIDsCount++

					elseCount.SnykIDsCountOSV++
					elseCount.SnykIDsCountSnyk++
				}
			} else if vuln.OSV && vuln.Trivy && !vuln.Snyk {
				outputData.ProjectsVulns[project].SnykIDs[vuln.SnykID] = Scanner{
					OSV:   vuln.OSV,
					Trivy: vuln.Trivy,
				}
				snykIDCountsOSV++
				snykIDCountsTrivy++

				idsOSV_Trivy.SnykID = append(idsOSV_Trivy.SnykID, vuln.SnykID)

				if vuln.System == "Go" {
					goCount.All++

					goCount.SnykIDsCount++

					goCount.SnykIDsCountOSV++
					goCount.SnykIDsCountTrivy++

					goCount.GoOSV_TrivyIDs = append(goCount.GoOSV_TrivyIDs, vuln.SnykID)

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.SnykIDsCount++

					npmCount.SnykIDsCountOSV++
					npmCount.SnykIDsCountTrivy++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.SnykIDsCount++

					pythonCount.SnykIDsCountOSV++
					pythonCount.SnykIDsCountTrivy++

				} else {
					elseCount.All++

					elseCount.SnykIDsCount++

					elseCount.SnykIDsCountOSV++
					elseCount.SnykIDsCountTrivy++
				}
			} else if vuln.Snyk && vuln.Trivy {
				outputData.ProjectsVulns[project].SnykIDs[vuln.SnykID] = Scanner{
					Snyk:  vuln.Snyk,
					Trivy: vuln.Trivy,
				}
				snykIDCountsSnyk++
				snykIDCountsTrivy++

				idsSnyk_Trivy.SnykID = append(idsSnyk_Trivy.SnykID, vuln.SnykID)

				if vuln.System == "Go" {
					goCount.All++

					goCount.SnykIDsCount++

					goCount.SnykIDsCountSnyk++
					goCount.SnykIDsCountTrivy++

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.SnykIDsCount++

					npmCount.SnykIDsCountSnyk++
					npmCount.SnykIDsCountTrivy++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.SnykIDsCount++

					pythonCount.SnykIDsCountSnyk++
					pythonCount.SnykIDsCountTrivy++

				} else {
					elseCount.All++

					elseCount.SnykIDsCount++

					elseCount.SnykIDsCountSnyk++
					elseCount.SnykIDsCountTrivy++
				}
			} else if vuln.OSV {
				outputData.ProjectsVulns[project].SnykIDs[vuln.SnykID] = Scanner{
					OSV: vuln.OSV,
				}
				snykIDCountsOSV++

				idsOnlyOSV.SnykID = append(idsOnlyOSV.SnykID, vuln.SnykID)

				if vuln.System == "Go" {
					goCount.All++

					goCount.SnykIDsCount++

					goCount.SnykIDsCountOSV++

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.SnykIDsCount++

					npmCount.SnykIDsCountOSV++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.SnykIDsCount++

					pythonCount.SnykIDsCountOSV++

				} else {
					elseCount.All++

					elseCount.SnykIDsCount++

					elseCount.SnykIDsCountOSV++
				}
			} else if vuln.Snyk {
				outputData.ProjectsVulns[project].SnykIDs[vuln.SnykID] = Scanner{
					Snyk: vuln.Snyk,
				}
				snykIDCountsSnyk++

				idsOnlySnyk.SnykID = append(idsOnlySnyk.SnykID, vuln.SnykID)

				if vuln.System == "Go" {
					goCount.All++

					goCount.SnykIDsCount++

					goCount.SnykIDsCountSnyk++

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.SnykIDsCount++

					npmCount.SnykIDsCountSnyk++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.SnykIDsCount++

					pythonCount.SnykIDsCountSnyk++

				} else {
					elseCount.All++

					elseCount.SnykIDsCount++

					elseCount.SnykIDsCountSnyk++
				}
			} else if vuln.Trivy {
				outputData.ProjectsVulns[project].SnykIDs[vuln.SnykID] = Scanner{
					Trivy: vuln.Trivy,
				}
				snykIDCountsTrivy++

				idsOnlyTrivy.SnykID = append(idsOnlyTrivy.SnykID, vuln.SnykID)

				if vuln.System == "Go" {
					goCount.All++

					goCount.SnykIDsCount++

					goCount.SnykIDsCountTrivy++

				} else if vuln.System == "Npm" {
					npmCount.All++

					npmCount.SnykIDsCount++

					npmCount.SnykIDsCountTrivy++

				} else if vuln.System == "Pypi" {
					pythonCount.All++

					pythonCount.SnykIDsCount++

					pythonCount.SnykIDsCountTrivy++

				} else {
					elseCount.All++

					elseCount.SnykIDsCount++

					elseCount.SnykIDsCountTrivy++
				}
			}

		} else if vuln.OthersID != nil {

			for id := range vuln.OthersID {
				if vuln.OSV && vuln.Snyk && vuln.Trivy {
					outputData.ProjectsVulns[project].OthersIDs[vuln.OthersID[id]] = Scanner{
						OSV:   vuln.OSV,
						Snyk:  vuln.Snyk,
						Trivy: vuln.Trivy,
					}
					othersIDCountsOSV++
					othersIDCountsSnyk++
					othersIDCountsTrivy++

					idsAll.OthersID = append(idsAll.OthersID, vuln.OthersID[id])

					if vuln.System == "Go" {
						goCount.All++

						goCount.OthersIDsCount++

						goCount.OthersIDsCountOSV++
						goCount.OthersIDsCountSnyk++
						goCount.OthersIDsCountTrivy++

					} else if vuln.System == "Npm" {
						npmCount.All++

						npmCount.OthersIDsCount++

						npmCount.OthersIDsCountOSV++
						npmCount.OthersIDsCountSnyk++
						npmCount.OthersIDsCountTrivy++

					} else if vuln.System == "Pypi" {
						pythonCount.All++

						pythonCount.OthersIDsCount++

						pythonCount.OthersIDsCountOSV++
						pythonCount.OthersIDsCountSnyk++
						pythonCount.OthersIDsCountTrivy++

					} else {
						elseCount.All++

						elseCount.OthersIDsCount++

						elseCount.OthersIDsCountOSV++
						elseCount.OthersIDsCountSnyk++
						elseCount.OthersIDsCountTrivy++
					}
				} else if vuln.OSV && vuln.Snyk {
					outputData.ProjectsVulns[project].OthersIDs[vuln.OthersID[id]] = Scanner{
						OSV:  vuln.OSV,
						Snyk: vuln.Snyk,
					}
					othersIDCountsOSV++
					othersIDCountsSnyk++

					idsOSV_Snyk.OthersID = append(idsOSV_Snyk.OthersID, vuln.OthersID[id])

					if vuln.System == "Go" {
						goCount.All++

						goCount.OthersIDsCount++

						goCount.OthersIDsCountOSV++
						goCount.OthersIDsCountSnyk++

					} else if vuln.System == "Npm" {
						npmCount.All++

						npmCount.OthersIDsCount++

						npmCount.OthersIDsCountOSV++
						npmCount.OthersIDsCountSnyk++

					} else if vuln.System == "Pypi" {
						pythonCount.All++

						pythonCount.OthersIDsCount++

						pythonCount.OthersIDsCountOSV++
						pythonCount.OthersIDsCountSnyk++

					} else {
						elseCount.All++

						elseCount.OthersIDsCount++

						elseCount.OthersIDsCountOSV++
						elseCount.OthersIDsCountSnyk++
					}
				} else if vuln.OSV && vuln.Trivy && !vuln.Snyk {
					outputData.ProjectsVulns[project].OthersIDs[vuln.OthersID[id]] = Scanner{
						OSV:   vuln.OSV,
						Trivy: vuln.Trivy,
					}
					othersIDCountsOSV++
					othersIDCountsTrivy++

					idsOSV_Trivy.OthersID = append(idsOSV_Trivy.OthersID, vuln.OthersID[id])

					if vuln.System == "Go" {
						goCount.All++

						goCount.OthersIDsCount++

						goCount.OthersIDsCountOSV++
						goCount.OthersIDsCountTrivy++

						goCount.GoOSV_TrivyIDs = append(goCount.GoOSV_TrivyIDs, vuln.OthersID[id])

					} else if vuln.System == "Npm" {
						npmCount.All++

						npmCount.OthersIDsCount++

						npmCount.OthersIDsCountOSV++
						npmCount.OthersIDsCountTrivy++

					} else if vuln.System == "Pypi" {
						pythonCount.All++

						pythonCount.OthersIDsCount++

						pythonCount.OthersIDsCountOSV++
						pythonCount.OthersIDsCountTrivy++

					} else {
						elseCount.All++

						elseCount.OthersIDsCount++

						elseCount.OthersIDsCountOSV++
						elseCount.OthersIDsCountTrivy++
					}
				} else if vuln.Snyk && vuln.Trivy {
					outputData.ProjectsVulns[project].OthersIDs[vuln.OthersID[id]] = Scanner{
						Snyk:  vuln.Snyk,
						Trivy: vuln.Trivy,
					}
					othersIDCountsSnyk++
					othersIDCountsTrivy++

					idsSnyk_Trivy.OthersID = append(idsSnyk_Trivy.OthersID, vuln.OthersID[id])

					if vuln.System == "Go" {
						goCount.All++

						goCount.OthersIDsCount++

						goCount.OthersIDsCountSnyk++
						goCount.OthersIDsCountTrivy++

					} else if vuln.System == "Npm" {
						npmCount.All++

						npmCount.OthersIDsCount++

						npmCount.OthersIDsCountSnyk++
						npmCount.OthersIDsCountTrivy++

					} else if vuln.System == "Pypi" {
						pythonCount.All++

						pythonCount.OthersIDsCount++

						pythonCount.OthersIDsCountSnyk++
						pythonCount.OthersIDsCountTrivy++

					} else {
						elseCount.All++

						elseCount.OthersIDsCount++

						elseCount.OthersIDsCountSnyk++
						elseCount.OthersIDsCountTrivy++
					}
				} else if vuln.OSV {
					outputData.ProjectsVulns[project].OthersIDs[vuln.OthersID[id]] = Scanner{
						OSV: vuln.OSV,
					}
					othersIDCountsOSV++

					idsOnlyOSV.OthersID = append(idsOnlyOSV.OthersID, vuln.OthersID[id])

					if vuln.System == "Go" {
						goCount.All++

						goCount.OthersIDsCount++

						goCount.OthersIDsCountOSV++

					} else if vuln.System == "Npm" {
						npmCount.All++

						npmCount.OthersIDsCount++

						npmCount.OthersIDsCountOSV++

					} else if vuln.System == "Pypi" {
						pythonCount.All++

						pythonCount.OthersIDsCount++

						pythonCount.OthersIDsCountOSV++

					} else {
						elseCount.All++

						elseCount.OthersIDsCount++

						elseCount.OthersIDsCountOSV++
					}
				} else if vuln.Snyk {
					outputData.ProjectsVulns[project].OthersIDs[vuln.OthersID[id]] = Scanner{
						Snyk: vuln.Snyk,
					}
					othersIDCountsSnyk++

					idsOnlySnyk.OthersID = append(idsOnlySnyk.OthersID, vuln.OthersID[id])

					if vuln.System == "Go" {
						goCount.All++

						goCount.OthersIDsCount++

						goCount.OthersIDsCountSnyk++

					} else if vuln.System == "Npm" {
						npmCount.All++

						npmCount.OthersIDsCount++

						npmCount.OthersIDsCountSnyk++

					} else if vuln.System == "Pypi" {
						pythonCount.All++

						pythonCount.OthersIDsCount++

						pythonCount.OthersIDsCountSnyk++

					} else {
						elseCount.All++

						elseCount.OthersIDsCount++

						elseCount.OthersIDsCountSnyk++
					}
				} else if vuln.Trivy {
					outputData.ProjectsVulns[project].OthersIDs[vuln.OthersID[id]] = Scanner{
						Trivy: vuln.Trivy,
					}
					othersIDCountsTrivy++

					idsOnlyTrivy.OthersID = append(idsOnlyTrivy.OthersID, vuln.OthersID[id])

					if vuln.System == "Go" {
						goCount.All++

						goCount.OthersIDsCount++

						goCount.OthersIDsCountTrivy++

					} else if vuln.System == "Npm" {
						npmCount.All++

						npmCount.OthersIDsCount++

						npmCount.OthersIDsCountTrivy++

					} else if vuln.System == "Pypi" {
						pythonCount.All++

						pythonCount.OthersIDsCount++

						pythonCount.OthersIDsCountTrivy++

					} else {
						elseCount.All++

						elseCount.OthersIDsCount++

						elseCount.OthersIDsCountTrivy++
					}
				}
			}
		}

		if vuln.OSV && !vuln.Snyk && !vuln.Trivy {
			onlyOSVAll++
			if vuln.System == "Go" {
				onlyOSVGO++
				if vuln.StandrdLibOSV {
					onlyOSVStdlibCount++
				} else {
					onlyOSVNotStdlibCount++
					onlyOSVNotStdlib = append(onlyOSVNotStdlib, vuln.CVEID)
				}
			} else {
				onlyOSVRest++
			}
		}
	}

	var all int
	onlyOSV := 0
	var onlySnyk int
	var onlyTrivy int
	var osvSnyk int
	var osvTrivy int
	var snykTrivy int

	var allCVEs int
	var onlyOSVCVEs int
	var onlySnykCVEs int
	var onlyTrivyCVEs int
	var osvSnykCVEs int
	var osvTrivyCVEs int
	var snykTrivyCVEs int

	var allGHSA int
	var onlyOSVGHSA int
	var onlySnykGHSA int
	var onlyTrivyGHSA int
	var osvSnykGHSA int
	var osvTrivyGHSA int
	var snykTrivyGHSA int

	for _, vuln := range inputData.Vuln {
		if vuln.OSV && vuln.Snyk && vuln.Trivy {
			if vuln.CVEID != "" {
				allCVEs++
			} else if vuln.GHSA != "" {
				allGHSA++
			}
			all++

			if vuln.System == "Go" {
				goCount.GoAll++
			}
		} else if vuln.OSV && vuln.Snyk && !vuln.Trivy {

			if vuln.CVEID != "" {
				osvSnykCVEs++
			} else if vuln.GHSA != "" {
				osvSnykGHSA++
			}
			osvSnyk++

			if vuln.System == "Go" {
				goCount.GoOSV_Snyk++
			}
		} else if vuln.OSV && vuln.Trivy && !vuln.Snyk {

			if vuln.CVEID != "" {
				osvTrivyCVEs++
			} else if vuln.GHSA != "" {
				osvTrivyGHSA++
			}

			osvTrivy++

			if vuln.System == "Go" {
				goCount.GoOSV_Trivy++
			}
		} else if vuln.Snyk && vuln.Trivy && !vuln.OSV {

			if vuln.CVEID != "" {
				snykTrivyCVEs++
			} else if vuln.GHSA != "" {
				snykTrivyGHSA++
			}

			snykTrivy++

			if vuln.System == "Go" {
				goCount.GoSnyk_Trivy++
			}
		} else if vuln.OSV && !vuln.Snyk && !vuln.Trivy {

			if vuln.CVEID != "" {
				onlyOSVCVEs++
			} else if vuln.GHSA != "" {
				onlyOSVGHSA++
			}

			onlyOSV++

			if vuln.System == "Go" {
				goCount.GoOnlyOSV++
			}
		} else if vuln.Snyk && !vuln.OSV && !vuln.Trivy {

			if vuln.CVEID != "" {
				onlySnykCVEs++
			} else if vuln.GHSA != "" {
				onlySnykGHSA++
			}

			onlySnyk++

			if vuln.System == "Go" {
				goCount.GoOnlySnyk++
			}
		} else if vuln.Trivy && !vuln.OSV && !vuln.Snyk {

			if vuln.CVEID != "" {
				onlyTrivyCVEs++
			} else if vuln.GHSA != "" {
				onlyTrivyGHSA++
			}

			onlyTrivy++

			if vuln.System == "Go" {
				goCount.GoOnlyTrivy++
			}
		}
	}
	projectVulns.CVEIDsCount = len(outputData.ProjectsVulns[project].CVEIDs)
	projectVulns.GOIDsCount = len(outputData.ProjectsVulns[project].GOIDs)
	projectVulns.GHSAsCount = len(outputData.ProjectsVulns[project].GHSAs)
	projectVulns.SnykIDsCount = len(outputData.ProjectsVulns[project].SnykIDs)
	projectVulns.OthersIDsCount = len(outputData.ProjectsVulns[project].OthersIDs)

	outputData.ProjectsVulns[project] = projectVulns

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

	// Zähler aktualisieren
	outputData.Counts.All += all
	outputData.Counts.OnlyOSV += onlyOSV
	outputData.Counts.OnlySnyk += onlySnyk
	outputData.Counts.OnlyTrivy += onlyTrivy
	outputData.Counts.OSV_Snyk += osvSnyk
	outputData.Counts.OSV_Trivy += osvTrivy
	outputData.Counts.Snyk_Trivy += snykTrivy
	outputData.Counts.Sum += len(inputData.Vuln)

	outputData.Counts.CVEIDsCount += projectVulns.CVEIDsCount
	outputData.Counts.GOIDsCount += projectVulns.GOIDsCount
	outputData.Counts.GHSAsCount += projectVulns.GHSAsCount
	outputData.Counts.SnykIDsCount += projectVulns.SnykIDsCount
	outputData.Counts.OthersIDsCount += projectVulns.OthersIDsCount

	outputData.Counts.CVEIDsCountOSV += cveIDCountsOSV
	outputData.Counts.GOIDsCountOSV += goidCountsOSV
	outputData.Counts.GHSAsCountOSV += ghsaCountsOSV
	outputData.Counts.SnykIDsCountOSV += snykIDCountsOSV
	outputData.Counts.OthersIDsCountOSV += othersIDCountsOSV

	outputData.Counts.CVEIDsCountSnyk += cveIDCountsSnyk
	outputData.Counts.GOIDsCountSnyk += goidCountsSnyk
	outputData.Counts.GHSAsCountSnyk += ghsaCountsSnyk
	outputData.Counts.SnykIDsCountSnyk += snykIDCountsSnyk
	outputData.Counts.OthersIDsCountSnyk += othersIDCountsSnyk

	outputData.Counts.CVEIDsCountTrivy += cveIDCountsTrivy
	outputData.Counts.GOIDsCountTrivy += goidCountsTrivy
	outputData.Counts.GHSAsCountTrivy += ghsaCountsTrivy
	outputData.Counts.SnykIDsCountTrivy += snykIDCountsTrivy
	outputData.Counts.OthersIDsCountTrivy += othersIDCountsTrivy

	outputData.Counts.AllCVEs += allCVEs
	outputData.Counts.OnlyOSVCVEs += onlyOSVCVEs
	outputData.Counts.OnlySnykCVEs += onlySnykCVEs
	outputData.Counts.OnlyTrivyCVEs += onlyTrivyCVEs
	outputData.Counts.OSV_SnykCVEs += osvSnykCVEs
	outputData.Counts.OSV_TrivyCVEs += osvTrivyCVEs
	outputData.Counts.Snyk_TrivyCVEs += snykTrivyCVEs

	outputData.Counts.AllGHSA += allGHSA
	outputData.Counts.OnlyOSVGHSA += onlyOSVGHSA
	outputData.Counts.OnlySnykGHSA += onlySnykGHSA
	outputData.Counts.OnlyTrivyGHSA += onlyTrivyGHSA
	outputData.Counts.OSV_SnykGHSA += osvSnykGHSA
	outputData.Counts.OSV_TrivyGHSA += osvTrivyGHSA
	outputData.Counts.Snyk_TrivyGHSA += snykTrivyGHSA

	// IDs aktualisieren
	outputData.Counts.IDsAll.CVEID = append(outputData.Counts.IDsAll.CVEID, idsAll.CVEID...)
	outputData.Counts.IDsAll.GOID = append(outputData.Counts.IDsAll.GOID, idsAll.GOID...)
	outputData.Counts.IDsAll.GHSA = append(outputData.Counts.IDsAll.GHSA, idsAll.GHSA...)
	outputData.Counts.IDsAll.SnykID = append(outputData.Counts.IDsAll.SnykID, idsAll.SnykID...)
	outputData.Counts.IDsAll.OthersID = append(outputData.Counts.IDsAll.OthersID, idsAll.OthersID...)

	outputData.Counts.IDsOnlyOSV.CVEID = append(outputData.Counts.IDsOnlyOSV.CVEID, idsOnlyOSV.CVEID...)
	outputData.Counts.IDsOnlyOSV.GOID = append(outputData.Counts.IDsOnlyOSV.GOID, idsOnlyOSV.GOID...)
	outputData.Counts.IDsOnlyOSV.GHSA = append(outputData.Counts.IDsOnlyOSV.GHSA, idsOnlyOSV.GHSA...)
	outputData.Counts.IDsOnlyOSV.SnykID = append(outputData.Counts.IDsOnlyOSV.SnykID, idsOnlyOSV.SnykID...)
	outputData.Counts.IDsOnlyOSV.OthersID = append(outputData.Counts.IDsOnlyOSV.OthersID, idsOnlyOSV.OthersID...)

	outputData.Counts.IDsOnlySnyk.CVEID = append(outputData.Counts.IDsOnlySnyk.CVEID, idsOnlySnyk.CVEID...)
	outputData.Counts.IDsOnlySnyk.GOID = append(outputData.Counts.IDsOnlySnyk.GOID, idsOnlySnyk.GOID...)
	outputData.Counts.IDsOnlySnyk.GHSA = append(outputData.Counts.IDsOnlySnyk.GHSA, idsOnlySnyk.GHSA...)
	outputData.Counts.IDsOnlySnyk.SnykID = append(outputData.Counts.IDsOnlySnyk.SnykID, idsOnlySnyk.SnykID...)
	outputData.Counts.IDsOnlySnyk.OthersID = append(outputData.Counts.IDsOnlySnyk.OthersID, idsOnlySnyk.OthersID...)

	outputData.Counts.IDsOnlyTrivy.CVEID = append(outputData.Counts.IDsOnlyTrivy.CVEID, idsOnlyTrivy.CVEID...)
	outputData.Counts.IDsOnlyTrivy.GOID = append(outputData.Counts.IDsOnlyTrivy.GOID, idsOnlyTrivy.GOID...)
	outputData.Counts.IDsOnlyTrivy.GHSA = append(outputData.Counts.IDsOnlyTrivy.GHSA, idsOnlyTrivy.GHSA...)
	outputData.Counts.IDsOnlyTrivy.SnykID = append(outputData.Counts.IDsOnlyTrivy.SnykID, idsOnlyTrivy.SnykID...)
	outputData.Counts.IDsOnlyTrivy.OthersID = append(outputData.Counts.IDsOnlyTrivy.OthersID, idsOnlyTrivy.OthersID...)

	outputData.Counts.IDsOSV_Snyk.CVEID = append(outputData.Counts.IDsOSV_Snyk.CVEID, idsOSV_Snyk.CVEID...)
	outputData.Counts.IDsOSV_Snyk.GOID = append(outputData.Counts.IDsOSV_Snyk.GOID, idsOSV_Snyk.GOID...)
	outputData.Counts.IDsOSV_Snyk.GHSA = append(outputData.Counts.IDsOSV_Snyk.GHSA, idsOSV_Snyk.GHSA...)
	outputData.Counts.IDsOSV_Snyk.SnykID = append(outputData.Counts.IDsOSV_Snyk.SnykID, idsOSV_Snyk.SnykID...)
	outputData.Counts.IDsOSV_Snyk.OthersID = append(outputData.Counts.IDsOSV_Snyk.OthersID, idsOSV_Snyk.OthersID...)

	outputData.Counts.IDsOSV_Trivy.CVEID = append(outputData.Counts.IDsOSV_Trivy.CVEID, idsOSV_Trivy.CVEID...)
	outputData.Counts.IDsOSV_Trivy.GOID = append(outputData.Counts.IDsOSV_Trivy.GOID, idsOSV_Trivy.GOID...)
	outputData.Counts.IDsOSV_Trivy.GHSA = append(outputData.Counts.IDsOSV_Trivy.GHSA, idsOSV_Trivy.GHSA...)
	outputData.Counts.IDsOSV_Trivy.SnykID = append(outputData.Counts.IDsOSV_Trivy.SnykID, idsOSV_Trivy.SnykID...)
	outputData.Counts.IDsOSV_Trivy.OthersID = append(outputData.Counts.IDsOSV_Trivy.OthersID, idsOSV_Trivy.OthersID...)

	outputData.Counts.IDsSnyk_Trivy.CVEID = append(outputData.Counts.IDsSnyk_Trivy.CVEID, idsSnyk_Trivy.CVEID...)
	outputData.Counts.IDsSnyk_Trivy.GOID = append(outputData.Counts.IDsSnyk_Trivy.GOID, idsSnyk_Trivy.GOID...)
	outputData.Counts.IDsSnyk_Trivy.GHSA = append(outputData.Counts.IDsSnyk_Trivy.GHSA, idsSnyk_Trivy.GHSA...)
	outputData.Counts.IDsSnyk_Trivy.SnykID = append(outputData.Counts.IDsSnyk_Trivy.SnykID, idsSnyk_Trivy.SnykID...)
	outputData.Counts.IDsSnyk_Trivy.OthersID = append(outputData.Counts.IDsSnyk_Trivy.OthersID, idsSnyk_Trivy.OthersID...)

	outputData.AllVulnsCVEs.OnlyOSV = append(outputData.AllVulnsCVEs.OnlyOSV, idsOnlyOSV.CVEID...)
	outputData.AllVulnsCVEs.OnlySnyk = append(outputData.AllVulnsCVEs.OnlySnyk, idsOnlySnyk.CVEID...)
	outputData.AllVulnsCVEs.OnlyTrivy = append(outputData.AllVulnsCVEs.OnlyTrivy, idsOnlyTrivy.CVEID...)
	outputData.AllVulnsCVEs.OSV_Snyk = append(outputData.AllVulnsCVEs.OSV_Snyk, idsOSV_Snyk.CVEID...)
	outputData.AllVulnsCVEs.OSV_Trivy = append(outputData.AllVulnsCVEs.OSV_Trivy, idsOSV_Trivy.CVEID...)
	outputData.AllVulnsCVEs.Snyk_Trivy = append(outputData.AllVulnsCVEs.Snyk_Trivy, idsSnyk_Trivy.CVEID...)
	outputData.AllVulnsCVEs.All = append(outputData.AllVulnsCVEs.All, idsAll.CVEID...)

	outputData.AllVulnsGHSA.OnlyOSV = append(outputData.AllVulnsGHSA.OnlyOSV, idsOnlyOSV.GHSA...)
	outputData.AllVulnsGHSA.OnlySnyk = append(outputData.AllVulnsGHSA.OnlySnyk, idsOnlySnyk.GHSA...)
	outputData.AllVulnsGHSA.OnlyTrivy = append(outputData.AllVulnsGHSA.OnlyTrivy, idsOnlyTrivy.GHSA...)
	outputData.AllVulnsGHSA.OSV_Snyk = append(outputData.AllVulnsGHSA.OSV_Snyk, idsOSV_Snyk.GHSA...)
	outputData.AllVulnsGHSA.OSV_Trivy = append(outputData.AllVulnsGHSA.OSV_Trivy, idsOSV_Trivy.GHSA...)
	outputData.AllVulnsGHSA.Snyk_Trivy = append(outputData.AllVulnsGHSA.Snyk_Trivy, idsSnyk_Trivy.GHSA...)
	outputData.AllVulnsGHSA.All = append(outputData.AllVulnsGHSA.All, idsAll.GHSA...)

	outputData.OnlyOsvNotStdlib = append(outputData.OnlyOsvNotStdlib, onlyOSVNotStdlib...)
	outputData.OnlyOSVAll += onlyOSVAll
	outputData.OnlyOSVGO += onlyOSVGO
	fmt.Println("OnlyOSVGO", onlyOSVGO)
	outputData.OnlyOSVRest += onlyOSVRest
	outputData.OnlyOSVStdlib += onlyOSVStdlibCount
	outputData.OnlyOSVNotStdlib += onlyOSVNotStdlibCount

	outputData.GoCounts = updateCounts(outputData.GoCounts, goCount)
	outputData.NPMCounts = updateCounts(outputData.NPMCounts, npmCount)
	outputData.PythonCounts = updateCounts(outputData.PythonCounts, pythonCount)
	outputData.ElseCounts = updateCounts(outputData.ElseCounts, elseCount)

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

func updateCounts(old MiniCounts, new MiniCounts) MiniCounts {
	old.All += new.All

	old.CVEIDsCount += new.CVEIDsCount
	old.GOIDsCount += new.GOIDsCount
	old.GHSAsCount += new.GHSAsCount
	old.SnykIDsCount += new.SnykIDsCount
	old.OthersIDsCount += new.OthersIDsCount

	old.CVEIDsCountOSV += new.CVEIDsCountOSV
	old.GOIDsCountOSV += new.GOIDsCountOSV
	old.GHSAsCountOSV += new.GHSAsCountOSV
	old.SnykIDsCountOSV += new.SnykIDsCountOSV
	old.OthersIDsCountOSV += new.OthersIDsCountOSV

	old.CVEIDsCountSnyk += new.CVEIDsCountSnyk
	old.GOIDsCountSnyk += new.GOIDsCountSnyk
	old.GHSAsCountSnyk += new.GHSAsCountSnyk
	old.SnykIDsCountSnyk += new.SnykIDsCountSnyk
	old.OthersIDsCountSnyk += new.OthersIDsCountSnyk

	old.CVEIDsCountTrivy += new.CVEIDsCountTrivy
	old.GOIDsCountTrivy += new.GOIDsCountTrivy
	old.GHSAsCountTrivy += new.GHSAsCountTrivy
	old.SnykIDsCountTrivy += new.SnykIDsCountTrivy
	old.OthersIDsCountTrivy += new.OthersIDsCountTrivy

	old.GoAll += new.GoAll
	old.GoOnlyOSV += new.GoOnlyOSV
	old.GoOnlySnyk += new.GoOnlySnyk
	old.GoOnlyTrivy += new.GoOnlyTrivy
	old.GoOSV_Snyk += new.GoOSV_Snyk
	old.GoOSV_Trivy += new.GoOSV_Trivy
	old.GoSnyk_Trivy += new.GoSnyk_Trivy

	old.GoOSV_TrivyIDs = append(old.GoOSV_TrivyIDs, new.GoOSV_TrivyIDs...)

	return old
}

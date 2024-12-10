package modul

type VulnInfo struct {
	Counts struct {
		Target       string `json:"Target"`
		TotalEntries int    `json:"TotalEntries"`
		CountOSV     int    `json:"CountOSV"`
		CountTrivy   int    `json:"CountTrivy"`
		CountSnyk    int    `json:"CountSnyk"`
	} `json:"Counts"`
	Vuln []struct {
		CVEID string `json:"CVE-ID"`
		GHSA  string `json:"GHSA"`
		GOID  string `json:"GO-ID"`
		OSV   bool   `json:"OSV"`
		Trivy bool   `json:"Trivy"`
		Snyk  bool   `json:"Snyk"`
	} `json:"Vuln"`
}

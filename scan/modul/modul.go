package modul

type VulnInfo struct {
	Counts struct {
		Target       string `json:"Target"`
		TotalEntries int    `json:"TotalEntries"`
		CountOSV     int    `json:"CountOSV"`
		CountTrivy   int    `json:"CountTrivy"`
		CountSnyk    int    `json:"CountSnyk"`

		OnlyOSV   int `json:"OnlyOSV"`
		OnlyTrivy int `json:"OnlyTrivy"`
		OnlySnyk  int `json:"OnlySnyk"`
		OSVTrivy  int `json:"OSVTrivy"`
		OSVSnyk   int `json:"OSVSnyk"`
		TrivySnyk int `json:"TrivySnyk"`
		AllThree  int `json:"AllThree"`

		VulnOnlyOSV   []Vuln `json:"VulnOnlyOSV"`
		VulnOnlyTrivy []Vuln `json:"VulnOnlyTrivy"`
		VulnOnlySnyk  []Vuln `json:"VulnOnlySnyk"`
		VulnOSVTrivy  []Vuln `json:"VulnOSVTrivy"`
		VulnOSVSnyk   []Vuln `json:"VulnOSVSnyk"`
		VulnTrivySnyk []Vuln `json:"VulnTrivySnyk"`
		VulnAllThree  []Vuln `json:"VulnAllThree"`
	} `json:"Counts"`
	Vuln []Vuln `json:"Vuln"`
}

type Vuln struct {
	ID string `json:"ID"`

	CVEID    string            `json:"CVE-ID"`
	GHSA     string            `json:"GHSA"`
	GOID     string            `json:"GO-ID"`
	SnykID   string            `json:"SnykID"`
	OthersID map[string]string `json:"OthersID"`
	OSV      bool              `json:"OSV"`
	Trivy    bool              `json:"Trivy"`
	Snyk     bool              `json:"Snyk"`

	System        string `json:"System"`
	StandrdLibOSV bool   `json:"StandardLibOSV"`
}

func (v *Vuln) SetScanType(scanType string, id string) {
	switch scanType {
	case "OSV":
		v.OSV = true
	case "Trivy":
		v.Trivy = true
	case "Snyk":
		v.Snyk = true
		v.SnykID = id
	}
}

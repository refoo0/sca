package modul

type VulnInfo struct {
	Target       string `json:"Target"`
	TotalEntries int    `json:"TotalEntries"`
	CountOSV     int    `json:"CountOSV"`
	CountTrivy   int    `json:"CountTrivy"`
	CountSnyk    int    `json:"CountSnyk"`
	Vuln         []Vuln `json:"Vuln"`
}

type Vuln struct {
	ID string `json:"ID"`

	GhsaIDs   []string `json:"GHSAIDS"`
	OthersIDS []string `json:"OthersIDS"`

	Scanner Scanner `json:"Scanner"`

	System        string `json:"System"`
	StandrdLibOSV bool   `json:"StandardLibOSV"`
}

func (v *Scanner) SetScanType(scanType string) {
	switch scanType {
	case "OSV":
		v.OSV = true
	case "Trivy":
		v.Trivy = true
	case "Snyk":
		v.Snyk = true
	}
}

type Scanner struct {
	OSV   bool `json:"OSV"`
	Snyk  bool `json:"Snyk"`
	Trivy bool `json:"Trivy"`
}

type OutputFile struct {
	AllVulns      Counts            `json:"AllVulns"`
	SystemsVulns  map[string]Counts `json:"SystemsVulns"`
	ProjectsVulns map[string]Counts `json:"ProjectsVulns"`
}

type Counts struct {
	CountOSV   int `json:"CountOSV"`
	CountTrivy int `json:"CountTrivy"`
	CountSnyk  int `json:"CountSnyk"`

	Sum        int `json:"Sum"`
	OnlyOSV    int `json:"OnlyOSV"`
	OnlySnyk   int `json:"OnlySnyk"`
	OnlyTrivy  int `json:"OnlyTrivy"`
	OSV_Snyk   int `json:"OSV_Snyk"`
	OSV_Trivy  int `json:"OSV_Trivy"`
	Snyk_Trivy int `json:"Snyk_Trivy"`
	All        int `json:"All"`

	CVEIDsCount   int `json:"CVEIDsCount"`
	GHSAIDsCount  int `json:"GHSAsCount"`
	OtherIDsCount int `json:"OtherIDsCount"`

	StdLibOSVOnly int `json:"StdLibOSVOnly"`

	IDsOnlyOSV    []string `json:"IDsOnlyOSV"`
	IDsOnlySnyk   []string `json:"IDsOnlySnyk"`
	IDsOnlyTrivy  []string `json:"IDsOnlyTrivy"`
	IDsOSV_Snyk   []string `json:"IDsOSV_Snyk"`
	IDsOSV_Trivy  []string `json:"IDsOSV_Trivy"`
	IDsSnyk_Trivy []string `json:"IDsSnyk_Trivy"`
	IDsAll        []string `json:"IDsAll"`
}

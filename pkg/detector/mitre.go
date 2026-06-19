// Package detector - MITRE ATT&CK technique mappings.
package detector

// MITRETechnique represents a MITRE ATT&CK technique.
type MITRETechnique struct {
	TechniqueID string `json:"technique_id"`
	Name        string `json:"name"`
	Tactic      string `json:"tactic"`
	URL         string `json:"url"`
}

// FindingType categorizes the type of detection.
type FindingType string

const (
	FindingSyscallHook    FindingType = "SYSCALL_HOOK"
	FindingHiddenProcess  FindingType = "HIDDEN_PROCESS"
	FindingSuspiciousBPF  FindingType = "SUSPICIOUS_BPF_PROGRAM"
	FindingMemoryPatch    FindingType = "MEMORY_PATCH"
	FindingBehavioral     FindingType = "BEHAVIORAL_ANOMALY"
	FindingHiddenModule   FindingType = "HIDDEN_KERNEL_MODULE"
	FindingNetworkAnomaly FindingType = "NETWORK_ANOMALY"
)

var mitreDB = map[FindingType][]MITRETechnique{
	FindingSyscallHook: {
		{TechniqueID: "T1014", Name: "Rootkit", Tactic: "Defense Evasion",
			URL: "https://attack.mitre.org/techniques/T1014/"},
		{TechniqueID: "T1601", Name: "Modify System Image", Tactic: "Defense Evasion",
			URL: "https://attack.mitre.org/techniques/T1601/"},
	},
	FindingHiddenProcess: {
		{TechniqueID: "T1014", Name: "Rootkit", Tactic: "Defense Evasion",
			URL: "https://attack.mitre.org/techniques/T1014/"},
		{TechniqueID: "T1057", Name: "Process Discovery", Tactic: "Discovery",
			URL: "https://attack.mitre.org/techniques/T1057/"},
		{TechniqueID: "T1564.001", Name: "Hide Artifacts: Hidden Files and Directories",
			Tactic: "Defense Evasion", URL: "https://attack.mitre.org/techniques/T1564/001/"},
	},
	FindingSuspiciousBPF: {
		{TechniqueID: "T1014", Name: "Rootkit", Tactic: "Defense Evasion",
			URL: "https://attack.mitre.org/techniques/T1014/"},
		{TechniqueID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "Execution",
			URL: "https://attack.mitre.org/techniques/T1059/"},
	},
	FindingMemoryPatch: {
		{TechniqueID: "T1014", Name: "Rootkit", Tactic: "Defense Evasion",
			URL: "https://attack.mitre.org/techniques/T1014/"},
		{TechniqueID: "T1055", Name: "Process Injection", Tactic: "Defense Evasion",
			URL: "https://attack.mitre.org/techniques/T1055/"},
	},
	FindingHiddenModule: {
		{TechniqueID: "T1014", Name: "Rootkit", Tactic: "Defense Evasion",
			URL: "https://attack.mitre.org/techniques/T1014/"},
		{TechniqueID: "T1547.006", Name: "Boot or Logon Autostart: Kernel Modules",
			Tactic: "Persistence", URL: "https://attack.mitre.org/techniques/T1547/006/"},
	},
	FindingBehavioral: {
		{TechniqueID: "T1499", Name: "Endpoint Denial of Service", Tactic: "Impact",
			URL: "https://attack.mitre.org/techniques/T1499/"},
	},
	FindingNetworkAnomaly: {
		{TechniqueID: "T1571", Name: "Non-Standard Port", Tactic: "Command and Control",
			URL: "https://attack.mitre.org/techniques/T1571/"},
	},
}

// MITREMappings returns ATT&CK techniques for a given finding type.
func MITREMappings(ft FindingType) []MITRETechnique {
	if t, ok := mitreDB[ft]; ok {
		out := make([]MITRETechnique, len(t))
		copy(out, t)
		return out
	}
	return nil
}

package scanner

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"unicode/utf16"
)

type HeuristicMatch struct {
	Indicator string
	Category  string
	Source    string
}

type HeuristicResult struct {
	FilePath string
	Matches  []HeuristicMatch
	Score    int
	Error    error
}

func (h HeuristicResult) Detected() bool {
	return h.Score >= HeuristicThreshold
}

const HeuristicThreshold = 3

var suspiciousAPIs = map[string]struct {
	Category string
	Score    int
}{
	// Process injection
	"VirtualAllocEx":       {"Process Injection", 2},
	"VirtualAlloc":         {"Process Injection", 1},
	"WriteProcessMemory":   {"Process Injection", 3},
	"CreateRemoteThread":   {"Process Injection", 3},
	"NtCreateThreadEx":     {"Process Injection", 3},
	"QueueUserAPC":         {"Process Injection", 2},
	"SetThreadContext":     {"Process Injection", 2},
	"OpenProcess":          {"Process Injection", 1},
	"NtUnmapViewOfSection": {"Process Hollowing", 3},
	"ZwUnmapViewOfSection": {"Process Hollowing", 3},

	// Defense evasion
	"IsDebuggerPresent":          {"Anti-Debug", 2},
	"CheckRemoteDebuggerPresent": {"Anti-Debug", 2},
	"NtQueryInformationProcess":  {"Anti-Debug", 2},
	"GetTickCount":               {"Timing / Sandbox Evasion", 1},
	"Sleep":                      {"Timing / Sandbox Evasion", 1},
	"NtDelayExecution":           {"Timing / Sandbox Evasion", 2},

	// Privilege escalation
	"AdjustTokenPrivileges": {"Privilege Escalation", 2},
	"OpenProcessToken":      {"Privilege Escalation", 1},
	"LookupPrivilegeValue":  {"Privilege Escalation", 1},

	// Persistence
	"RegSetValueExA":  {"Registry Persistence", 2},
	"RegSetValueExW":  {"Registry Persistence", 2},
	"RegCreateKeyExA": {"Registry Persistence", 1},
	"RegCreateKeyExW": {"Registry Persistence", 1},
	"SHSetValue":      {"Registry Persistence", 1},

	// Network / C2
	"WSAStartup":       {"Network Activity", 1},
	"connect":          {"Network Activity", 1},
	"InternetOpenA":    {"Network Activity", 1},
	"InternetOpenW":    {"Network Activity", 1},
	"HttpSendRequestA": {"Network Activity", 1},
	"HttpSendRequestW": {"Network Activity", 1},
	"WinHttpOpen":      {"Network Activity", 1},

	// Keylogging / credential access
	"SetWindowsHookExA": {"Keylogging", 3},
	"SetWindowsHookExW": {"Keylogging", 3},
	"GetAsyncKeyState":  {"Keylogging", 2},
	"GetKeyboardState":  {"Keylogging", 1},

	// Discovery
	"GetSystemInfo":            {"System Discovery", 1},
	"GetComputerNameA":         {"System Discovery", 1},
	"GetComputerNameW":         {"System Discovery", 1},
	"EnumProcesses":            {"Process Discovery", 2},
	"CreateToolhelp32Snapshot": {"Process Discovery", 1},

	// File operations (common in ransomware)
	"MoveFileExA":   {"File Manipulation", 1},
	"MoveFileExW":   {"File Manipulation", 1},
	"DeleteFileA":   {"File Manipulation", 1},
	"DeleteFileW":   {"File Manipulation", 1},
	"CryptEncrypt":  {"Encryption / Ransomware", 3},
	"CryptGenKey":   {"Encryption / Ransomware", 2},
	"BCryptEncrypt": {"Encryption / Ransomware", 3},
}

var suspiciousStrings = []struct {
	Pattern  string
	Category string
	Score    int
}{
	// Execution via shell
	{"cmd.exe /c", "Shell Execution", 2},
	{"cmd /c", "Shell Execution", 2},
	{"powershell -e", "Encoded PowerShell", 3},
	{"powershell -enc", "Encoded PowerShell", 3},
	{"powershell -nop", "PowerShell Execution", 2},
	{"powershell -w hidden", "PowerShell Execution", 2},
	{"wscript.exe", "Script Execution", 2},
	{"cscript.exe", "Script Execution", 2},
	{"mshta.exe", "LOLBin Execution", 3},
	{"rundll32.exe", "LOLBin Execution", 2},
	{"regsvr32.exe", "LOLBin Execution", 2},
	{"certutil -decode", "LOLBin Execution", 3},
	{"bitsadmin /transfer", "LOLBin Download", 3},

	// Persistence keys
	{"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "Registry Persistence", 2},
	{"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Registry Persistence", 2},
	{"SYSTEM\\CurrentControlSet\\Services", "Service Persistence", 2},

	// Suspicious paths
	{"%TEMP%", "Temp Directory Usage", 1},
	{"\\AppData\\Roaming", "AppData Usage", 1},
	{"\\AppData\\Local\\Temp", "Temp Directory Usage", 1},

	// Credential / privilege strings
	{"SeDebugPrivilege", "Privilege Escalation", 2},
	{"net user", "Account Discovery", 2},
	{"net localgroup administrators", "Privilege Discovery", 3},

	// Network indicators
	{"http://", "Network Activity", 1},
	{"https://", "Network Activity", 1},
	{"ftp://", "Network Activity", 1},
	{"/bin/sh", "Unix Shell Reference", 2},
	{"wget ", "Download Activity", 2},
	{"curl ", "Download Activity", 2},

	// Ransomware
	{"YOUR FILES HAVE BEEN ENCRYPTED", "Ransomware", 3},
	{"bitcoin", "Ransom Payment", 2},
	{".onion", "Tor C2", 3},
	{"CryptoLocker", "Ransomware Family", 3},
	{"WannaCry", "Ransomware Family", 3},

	// Evasion / anti-analysis
	{"IsDebuggerPresent", "Anti-Debug String", 2},
	{"VirtualBox", "VM Detection", 2},
	{"VMware", "VM Detection", 2},
	{"VBOX", "VM Detection", 2},
	{"SandboxEnvironment", "Sandbox Detection", 3},

	// Injection strings
	{"VirtualAllocEx", "Process Injection String", 2},
	{"CreateRemoteThread", "Process Injection String", 2},
}

func ScanHeuristics(filePath string) HeuristicResult {
	result := HeuristicResult{FilePath: filePath}

	data, err := os.ReadFile(filePath)
	if err != nil {
		result.Error = fmt.Errorf("could not read file: %w", err)
		return result
	}

	importMatches := scanPEImports(filePath)
	stringMatches := scanStrings(data)

	seen := make(map[string]bool)
	for _, m := range importMatches {
		seen[strings.ToLower(m.Indicator)] = true
		result.Matches = append(result.Matches, m)
		result.Score += apiScore(m.Indicator)
	}
	for _, m := range stringMatches {
		if !seen[strings.ToLower(m.Indicator)] {
			result.Matches = append(result.Matches, m.HeuristicMatch)
			result.Score += m.score()
		}
	}

	return result
}

func scanPEImports(filePath string) []HeuristicMatch {
	var matches []HeuristicMatch

	f, err := pe.Open(filePath)
	if err != nil {
		// Not a PE file — silently skip import scanning
		return matches
	}
	defer f.Close()

	imports, err := f.ImportedSymbols()
	if err != nil {
		return matches
	}

	for _, sym := range imports {
		// ImportedSymbols returns "funcname:dllname"; split off function name
		name := sym
		if idx := strings.Index(sym, ":"); idx != -1 {
			name = sym[:idx]
		}
		if info, ok := suspiciousAPIs[name]; ok {
			matches = append(matches, HeuristicMatch{
				Indicator: name,
				Category:  info.Category,
				Source:    "PE Import",
			})
		}
	}
	return matches
}

func apiScore(name string) int {
	if info, ok := suspiciousAPIs[name]; ok {
		return info.Score
	}
	return 0
}

// ── Raw string extractor ──────────────────────────────────────

// stringMatch is an internal type that carries score alongside the public fields.
type stringMatch struct {
	HeuristicMatch
	_score int
}

func (s stringMatch) score() int { return s._score }

const minStringLen = 6

// scanStrings extracts printable ASCII and UTF-16LE strings from raw bytes
// and checks them against suspiciousStrings.
func scanStrings(data []byte) []stringMatch {
	var matches []stringMatch
	seen := make(map[string]bool) // avoid duplicate pattern hits

	ascii := extractASCII(data)
	utf16s := extractUTF16(data)
	allStrings := append(ascii, utf16s...)

	lower := func(s string) string { return strings.ToLower(s) }

	for _, s := range allStrings {
		sl := lower(s)
		for _, sig := range suspiciousStrings {
			key := sig.Pattern + "|" + s
			if seen[key] {
				continue
			}
			if strings.Contains(sl, lower(sig.Pattern)) {
				seen[key] = true
				matches = append(matches, stringMatch{
					HeuristicMatch: HeuristicMatch{
						Indicator: s,
						Category:  sig.Category,
						Source:    "String",
					},
					_score: sig.Score,
				})
			}
		}
	}
	return matches
}

// extractASCII pulls printable ASCII sequences of minStringLen+ chars.
func extractASCII(data []byte) []string {
	var results []string
	start := -1
	for i, b := range data {
		if isPrintableASCII(b) {
			if start == -1 {
				start = i
			}
		} else {
			if start != -1 && i-start >= minStringLen {
				results = append(results, string(data[start:i]))
			}
			start = -1
		}
	}
	if start != -1 && len(data)-start >= minStringLen {
		results = append(results, string(data[start:]))
	}
	return results
}

// extractUTF16 pulls UTF-16LE sequences of minStringLen+ chars.
func extractUTF16(data []byte) []string {
	var results []string
	var buf []uint16
	for i := 0; i+1 < len(data); i += 2 {
		v := binary.LittleEndian.Uint16(data[i : i+2])
		if v >= 0x20 && v <= 0x7e {
			buf = append(buf, v)
		} else {
			if len(buf) >= minStringLen {
				runes := utf16.Decode(buf)
				results = append(results, string(runes))
			}
			buf = buf[:0]
		}
	}
	if len(buf) >= minStringLen {
		runes := utf16.Decode(buf)
		results = append(results, string(runes))
	}
	return results
}

func isPrintableASCII(b byte) bool {
	return b >= 0x20 && b <= 0x7e
}

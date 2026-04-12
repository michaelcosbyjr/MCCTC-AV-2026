package scanner

import (
	"encoding/binary"
	"fmt"
	"os"
)

// ============================================================
// MCCTC AV Engine — Header & Section Analysis
// scanner/pe_scanner.go
// ============================================================

// PEResult holds the result of a PE header analysis.
type PEResult struct {
	FilePath   string
	IsPE       bool
	Suspicious bool
	Findings   []PEFinding
	Error      error
}

// PEFinding holds a single suspicious finding from PE analysis.
type PEFinding struct {
	Category string
	Detail   string
	Severity string
}

const (
	dosSignature = 0x5A4D     // MZ
	peSignature  = 0x00004550 // PE\0\0
)

// ScanPE analyzes the PE header and section table of a file.
func ScanPE(path string) PEResult {
	result := PEResult{FilePath: path}

	f, err := os.Open(path)
	if err != nil {
		result.Error = err
		return result
	}
	defer f.Close()

	// ── Check DOS header (MZ) ────────────────────────────
	var dosMagic uint16
	if err := binary.Read(f, binary.LittleEndian, &dosMagic); err != nil {
		result.Error = fmt.Errorf("could not read DOS header: %w", err)
		return result
	}
	if dosMagic != dosSignature {
		// Not a PE file — skip silently
		return result
	}

	// ── Read e_lfanew (offset to PE header) ─────────────
	if _, err := f.Seek(0x3C, 0); err != nil {
		result.Error = fmt.Errorf("could not seek to e_lfanew: %w", err)
		return result
	}
	var peOffset uint32
	if err := binary.Read(f, binary.LittleEndian, &peOffset); err != nil {
		result.Error = fmt.Errorf("could not read PE offset: %w", err)
		return result
	}

	// ── Check PE signature ───────────────────────────────
	if _, err := f.Seek(int64(peOffset), 0); err != nil {
		result.Error = fmt.Errorf("could not seek to PE header: %w", err)
		return result
	}
	var peSig uint32
	if err := binary.Read(f, binary.LittleEndian, &peSig); err != nil {
		result.Error = fmt.Errorf("could not read PE signature: %w", err)
		return result
	}
	if peSig != peSignature {
		result.Findings = append(result.Findings, PEFinding{
			Category: "Malformed Header",
			Detail:   "Invalid PE signature — file may be corrupted or tampered",
			Severity: "HIGH",
		})
		result.Suspicious = true
		return result
	}

	result.IsPE = true

	// ── Read COFF File Header ────────────────────────────
	var machine uint16
	var numSections uint16
	var timeDateStamp uint32
	var symTablePtr uint32
	var numSymbols uint32
	var optHeaderSize uint16
	var characteristics uint16

	binary.Read(f, binary.LittleEndian, &machine)
	binary.Read(f, binary.LittleEndian, &numSections)
	binary.Read(f, binary.LittleEndian, &timeDateStamp)
	binary.Read(f, binary.LittleEndian, &symTablePtr)
	binary.Read(f, binary.LittleEndian, &numSymbols)
	binary.Read(f, binary.LittleEndian, &optHeaderSize)
	binary.Read(f, binary.LittleEndian, &characteristics)

	// Flag suspicious section count
	if numSections == 0 {
		result.Findings = append(result.Findings, PEFinding{
			Category: "Malformed Header",
			Detail:   "PE file has zero sections — highly abnormal",
			Severity: "HIGH",
		})
		result.Suspicious = true
	}
	if numSections > 20 {
		result.Findings = append(result.Findings, PEFinding{
			Category: "Malformed Header",
			Detail:   fmt.Sprintf("Unusually high section count: %d", numSections),
			Severity: "MEDIUM",
		})
		result.Suspicious = true
	}

	// Flag zero timestamp (common in packed/obfuscated PE)
	if timeDateStamp == 0 {
		result.Findings = append(result.Findings, PEFinding{
			Category: "Suspicious Timestamp",
			Detail:   "Compile timestamp is zero — common in packed or generated malware",
			Severity: "MEDIUM",
		})
		result.Suspicious = true
	}

	// ── Skip optional header, read section table ─────────
	optHeaderOffset := int64(peOffset) + 4 + 20
	if _, err := f.Seek(optHeaderOffset+int64(optHeaderSize), 0); err != nil {
		result.Error = fmt.Errorf("could not seek to section table: %w", err)
		return result
	}

	// ── Analyze each section ─────────────────────────────
	suspiciousSectionNames := map[string]bool{
		".upx0": true, ".upx1": true, ".upx2": true,
		".aspack": true, ".adata": true, ".packed": true,
		".themida": true, ".vmp0": true, ".vmp1": true,
	}

	for i := 0; i < int(numSections); i++ {
		name := make([]byte, 8)
		var virtualSize uint32
		var virtualAddress uint32
		var rawSize uint32
		var rawOffset uint32
		var relocOffset uint32
		var lineNumOffset uint32
		var relocCount uint16
		var lineNumCount uint16
		var sectionChars uint32

		binary.Read(f, binary.LittleEndian, &name)
		binary.Read(f, binary.LittleEndian, &virtualSize)
		binary.Read(f, binary.LittleEndian, &virtualAddress)
		binary.Read(f, binary.LittleEndian, &rawSize)
		binary.Read(f, binary.LittleEndian, &rawOffset)
		binary.Read(f, binary.LittleEndian, &relocOffset)
		binary.Read(f, binary.LittleEndian, &lineNumOffset)
		binary.Read(f, binary.LittleEndian, &relocCount)
		binary.Read(f, binary.LittleEndian, &lineNumCount)
		binary.Read(f, binary.LittleEndian, &sectionChars)

		// Trim null bytes from section name
		sectionName := ""
		for _, b := range name {
			if b == 0 {
				break
			}
			sectionName += string(b)
		}

		// Flag known packer section names
		if suspiciousSectionNames[sectionName] {
			result.Findings = append(result.Findings, PEFinding{
				Category: "Packer Detected",
				Detail:   fmt.Sprintf("Known packer section name: %s", sectionName),
				Severity: "HIGH",
			})
			result.Suspicious = true
		}

		// Flag writable + executable sections (common injection technique)
		const IMAGE_SCN_MEM_EXECUTE = 0x20000000
		const IMAGE_SCN_MEM_WRITE = 0x80000000
		if sectionChars&IMAGE_SCN_MEM_EXECUTE != 0 && sectionChars&IMAGE_SCN_MEM_WRITE != 0 {
			result.Findings = append(result.Findings, PEFinding{
				Category: "Suspicious Permissions",
				Detail:   fmt.Sprintf("Section %s is both writable and executable (W+X)", sectionName),
				Severity: "HIGH",
			})
			result.Suspicious = true
		}

		// Flag sections where virtual size >> raw size (common in packers)
		if rawSize > 0 && virtualSize > rawSize*10 {
			result.Findings = append(result.Findings, PEFinding{
				Category: "Size Mismatch",
				Detail:   fmt.Sprintf("Section %s virtual size (%d) far exceeds raw size (%d)", sectionName, virtualSize, rawSize),
				Severity: "MEDIUM",
			})
			result.Suspicious = true
		}

		_ = relocOffset
		_ = lineNumOffset
		_ = relocCount
		_ = lineNumCount
		_ = virtualAddress
	}

	return result
}

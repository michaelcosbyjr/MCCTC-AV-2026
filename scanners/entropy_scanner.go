package scanner

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
)

// ============================================================
// MCCTC AV Engine — Entropy Analysis
// scanner/entropy_scanner.go
// ============================================================

// EntropyResult holds the result of entropy analysis on a file.
type EntropyResult struct {
	FilePath        string
	IsPE            bool
	OverallEntropy  float64
	SectionEntropy  []SectionEntropy
	Suspicious      bool
	Findings        []EntropyFinding
	Error           error
}

// SectionEntropy holds the entropy of a single PE section.
type SectionEntropy struct {
	Name    string
	Entropy float64
	RawSize uint32
}

// EntropyFinding holds a single entropy-based suspicious finding.
type EntropyFinding struct {
	Section  string
	Entropy  float64
	Detail   string
	Severity string
}

const (
	highEntropyThreshold   = 7.0 // above this = likely packed/encrypted
	mediumEntropyThreshold = 6.2 // above this = suspicious
)

// shannonEntropy calculates the Shannon entropy of a byte slice.
func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}
	entropy := 0.0
	length := float64(len(data))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// ScanEntropy calculates entropy for the whole file and each PE section.
func ScanEntropy(path string) EntropyResult {
	result := EntropyResult{FilePath: path}

	data, err := os.ReadFile(path)
	if err != nil {
		result.Error = fmt.Errorf("could not read file: %w", err)
		return result
	}

	// ── Overall file entropy ─────────────────────────────
	result.OverallEntropy = shannonEntropy(data)

	if result.OverallEntropy >= highEntropyThreshold {
		result.Findings = append(result.Findings, EntropyFinding{
			Section:  "Overall",
			Entropy:  result.OverallEntropy,
			Detail:   fmt.Sprintf("High overall entropy (%.2f) — file may be packed or encrypted", result.OverallEntropy),
			Severity: "HIGH",
		})
		result.Suspicious = true
	} else if result.OverallEntropy >= mediumEntropyThreshold {
		result.Findings = append(result.Findings, EntropyFinding{
			Section:  "Overall",
			Entropy:  result.OverallEntropy,
			Detail:   fmt.Sprintf("Elevated overall entropy (%.2f) — worth investigating", result.OverallEntropy),
			Severity: "MEDIUM",
		})
		result.Suspicious = true
	}

	// ── PE section entropy ───────────────────────────────
	if len(data) < 64 {
		return result
	}

	// Check MZ signature
	if data[0] != 0x4D || data[1] != 0x5A {
		return result
	}

	result.IsPE = true

	peOffset := binary.LittleEndian.Uint32(data[0x3C:])
	if int(peOffset)+24 > len(data) {
		return result
	}

	// Check PE signature
	if data[peOffset] != 0x50 || data[peOffset+1] != 0x45 {
		return result
	}

	numSections := binary.LittleEndian.Uint16(data[peOffset+6:])
	optHeaderSize := binary.LittleEndian.Uint16(data[peOffset+20:])

	sectionTableOffset := int(peOffset) + 24 + int(optHeaderSize)

	for i := 0; i < int(numSections); i++ {
		sectionOffset := sectionTableOffset + i*40
		if sectionOffset+40 > len(data) {
			break
		}

		// Read section name
		nameBytes := data[sectionOffset : sectionOffset+8]
		name := ""
		for _, b := range nameBytes {
			if b == 0 {
				break
			}
			name += string(b)
		}

		virtualSize := binary.LittleEndian.Uint32(data[sectionOffset+8:])
		rawSize := binary.LittleEndian.Uint32(data[sectionOffset+16:])
		rawOffset := binary.LittleEndian.Uint32(data[sectionOffset+20:])

		if rawSize == 0 || int(rawOffset)+int(rawSize) > len(data) {
			continue
		}

		sectionData := data[rawOffset : rawOffset+rawSize]
		entropy := shannonEntropy(sectionData)

		result.SectionEntropy = append(result.SectionEntropy, SectionEntropy{
			Name:    name,
			Entropy: entropy,
			RawSize: rawSize,
		})

		if entropy >= highEntropyThreshold {
			result.Findings = append(result.Findings, EntropyFinding{
				Section:  name,
				Entropy:  entropy,
				Detail:   fmt.Sprintf("Section %s has high entropy (%.2f) — likely packed or encrypted", name, entropy),
				Severity: "HIGH",
			})
			result.Suspicious = true
		} else if entropy >= mediumEntropyThreshold {
			result.Findings = append(result.Findings, EntropyFinding{
				Section:  name,
				Entropy:  entropy,
				Detail:   fmt.Sprintf("Section %s has elevated entropy (%.2f)", name, entropy),
				Severity: "MEDIUM",
			})
		}

		_ = virtualSize
	}

	return result
}

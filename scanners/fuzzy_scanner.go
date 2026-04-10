package scanner

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ============================================================
// MCCTC AV Engine — Fuzzy Hashing (ssdeep)
// scanner/fuzzy_scanner.go
// ============================================================

// FuzzyResult holds the result of fuzzy hash comparison.
type FuzzyResult struct {
	FilePath    string
	FuzzyHash   string
	Matches     []FuzzyMatch
	Suspicious  bool
	Error       error
}

// FuzzyMatch holds a single fuzzy hash similarity match.
type FuzzyMatch struct {
	ThreatName string
	Score      int    // 0-100 similarity score
	KnownHash  string
}

// FuzzyDB holds known malware fuzzy hashes for comparison.
type FuzzyDB struct {
	entries []FuzzyEntry
}

// FuzzyEntry is a single entry in the fuzzy hash database.
type FuzzyEntry struct {
	Hash       string
	ThreatName string
}

const fuzzyMatchThreshold = 50 // similarity score 50+ = suspicious

// LoadFuzzyDB loads a fuzzy hash database from a file.
// Format: FUZZY_HASH|THREAT_NAME
func LoadFuzzyDB(path string) (*FuzzyDB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not open fuzzy hash database: %w", err)
	}

	db := &FuzzyDB{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			continue
		}
		db.entries = append(db.entries, FuzzyEntry{
			Hash:       strings.TrimSpace(parts[0]),
			ThreatName: strings.TrimSpace(parts[1]),
		})
	}
	return db, nil
}

// Count returns the number of fuzzy hashes loaded.
func (db *FuzzyDB) Count() int {
	return len(db.entries)
}

// computeFuzzyHash runs ssdeep on a file and returns its fuzzy hash.
func computeFuzzyHash(path string) (string, error) {
	if _, err := exec.LookPath("ssdeep"); err != nil {
		return "", fmt.Errorf("ssdeep binary not found — install ssdeep and add it to PATH")
	}

	out, err := exec.Command("ssdeep", "-b", path).Output()
	if err != nil {
		return "", fmt.Errorf("ssdeep error: %w", err)
	}

	// ssdeep output: header line then hash,filename
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		if strings.Contains(line, ":") && !strings.HasPrefix(line, "ssdeep") {
			parts := strings.SplitN(line, ",", 2)
			if len(parts) >= 1 {
				return strings.TrimSpace(parts[0]), nil
			}
		}
	}
	return "", fmt.Errorf("could not parse ssdeep output")
}

// compareFuzzyHashes runs ssdeep to compare two fuzzy hashes.
// Returns a similarity score 0-100.
func compareFuzzyHashes(hash1, hash2 string) (int, error) {
	if _, err := exec.LookPath("ssdeep"); err != nil {
		return 0, fmt.Errorf("ssdeep not found")
	}

	out, err := exec.Command("ssdeep", "-d", "-a", hash1, hash2).Output()
	if err != nil {
		// ssdeep exits non-zero when no match — not a real error
		return 0, nil
	}

	output := string(out)
	// Parse score from output like: "hash1 matches hash2 (85)"
	var score int
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "matches") {
			start := strings.LastIndex(line, "(")
			end := strings.LastIndex(line, ")")
			if start != -1 && end != -1 && end > start {
				fmt.Sscanf(line[start+1:end], "%d", &score)
			}
		}
	}
	return score, nil
}

// ScanFuzzy computes the fuzzy hash of a file and compares it
// against the fuzzy hash database.
func ScanFuzzy(path string, db *FuzzyDB) FuzzyResult {
	result := FuzzyResult{FilePath: path}

	hash, err := computeFuzzyHash(path)
	if err != nil {
		result.Error = err
		return result
	}
	result.FuzzyHash = hash

	if db == nil || len(db.entries) == 0 {
		return result
	}

	for _, entry := range db.entries {
		score, err := compareFuzzyHashes(hash, entry.Hash)
		if err != nil {
			continue
		}
		if score >= fuzzyMatchThreshold {
			result.Matches = append(result.Matches, FuzzyMatch{
				ThreatName: entry.ThreatName,
				Score:      score,
				KnownHash:  entry.Hash,
			})
			result.Suspicious = true
		}
	}

	return result
}

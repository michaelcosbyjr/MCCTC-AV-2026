package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/michaelcosbyjr/MCCTC-AV-2026/scanner"
)


const version = "0.6.0"

func defaultSigDB() string {
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join("signatures", "hashes.txt")
	}
	return filepath.Join(filepath.Dir(exe), "signatures", "hashes.txt")
}

func defaultFuzzyDB() string {
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join("signatures", "fuzzy.txt")
	}
	return filepath.Join(filepath.Dir(exe), "signatures", "fuzzy.txt")
}

func defaultRulesDir() string {
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join("rules")
	}
	return filepath.Join(filepath.Dir(exe), "rules")
}

func printBanner() {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf(" MCCTC AV Engine v%s\n", version)
	fmt.Println(" Michael Cosby — Senior Capstone 2026")
	fmt.Println(" Detection: Hash | YARA | Heuristics | PE | Entropy | Fuzzy")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()
}

func printResult(r scanner.ScanResult) {
	if r.Error != nil {
		fmt.Printf(" [ERR] %s\n      %v\n\n", r.FilePath, r.Error)
		return
	}

	// ── Hash match ───────────────────────────────────────
	if r.Detected {
		fmt.Println(" [!] DETECTED (Hash) —", r.FilePath)
		fmt.Printf("     %-10s: %s\n", r.MatchType, r.MatchHash)
		fmt.Printf("     %-10s: %s\n", "Match", r.ThreatName)
		fmt.Printf("     %-10s: %s\n", "Verdict", r.Verdict)
		fmt.Printf("     %-10s: %s\n\n", "Scan time", r.ScanTime)
	}

	// ── YARA matches ─────────────────────────────────────
	if len(r.YaraMatches) > 0 {
		if !r.Detected {
			fmt.Println(" [!] DETECTED (YARA) —", r.FilePath)
			fmt.Printf("     %-10s: %s\n", "Verdict", r.Verdict)
		} else {
			fmt.Printf("     Also matched %d YARA rule(s):\n", len(r.YaraMatches))
		}
		for _, m := range r.YaraMatches {
			tags := ""
			if len(m.Tags) > 0 {
				tags = fmt.Sprintf(" [%s]", strings.Join(m.Tags, ", "))
			}
			fmt.Printf("     [YARA] %s::%s%s\n", m.Namespace, m.RuleName, tags)
			for _, s := range m.Strings {
				data := s.Data
				suffix := ""
				if len(data) > 32 {
					data = data[:32]
					suffix = "..."
				}
				fmt.Printf("            %s @ 0x%x : %q%s\n", s.Name, s.Offset, data, suffix)
			}
		}
		fmt.Printf("     %-10s: %s\n\n", "Scan time", r.ScanTime)
	}

	// ── Clean ────────────────────────────────────────────
	if !r.Detected && len(r.YaraMatches) == 0 {
		fmt.Printf(" [CLEAN] %s\n", r.FilePath)
	}
}

func printHeuristicResult(h scanner.HeuristicResult) {
	if h.Error != nil {
		fmt.Printf(" [ERR] Heuristics on %s: %v\n\n", h.FilePath, h.Error)
		return
	}
	if h.Detected() {
		fmt.Printf(" [!] DETECTED (Heuristics) — %s\n", h.FilePath)
		fmt.Printf("     %-10s: %s\n", "Verdict", "SUSPICIOUS")
		fmt.Printf("     %-10s: %d / %d threshold\n\n", "Score", h.Score, scanner.HeuristicThreshold)

		byCategory := make(map[string][]scanner.HeuristicMatch)
		var categoryOrder []string
		for _, m := range h.Matches {
			if _, exists := byCategory[m.Category]; !exists {
				categoryOrder = append(categoryOrder, m.Category)
			}
			byCategory[m.Category] = append(byCategory[m.Category], m)
		}
		for _, category := range categoryOrder {
			fmt.Printf("     [%s]\n", category)
			for _, hit := range byCategory[category] {
				fmt.Printf("       %-14s %s\n", "["+hit.Source+"]", hit.Indicator)
			}
		}
		fmt.Println()
	} else if len(h.Matches) > 0 {
		fmt.Printf(" [~] LOW SUSPICION — %s (score: %d)\n", h.FilePath, h.Score)
	}
}

func printPEResult(r scanner.PEResult) {
	if r.Error != nil {
		fmt.Printf(" [ERR] PE analysis on %s: %v\n\n", r.FilePath, r.Error)
		return
	}
	if !r.IsPE {
		return // not a PE file, stay quiet
	}
	if r.Suspicious {
		fmt.Printf(" [!] DETECTED (PE Analysis) — %s\n", r.FilePath)
		for _, f := range r.Findings {
			fmt.Printf("     [%s][%s] %s\n", f.Severity, f.Category, f.Detail)
		}
		fmt.Println()
	}
}

func printEntropyResult(r scanner.EntropyResult) {
	if r.Error != nil {
		fmt.Printf(" [ERR] Entropy analysis on %s: %v\n\n", r.FilePath, r.Error)
		return
	}
	if r.Suspicious {
		fmt.Printf(" [!] DETECTED (Entropy) — %s\n", r.FilePath)
		fmt.Printf("     Overall entropy: %.4f\n", r.OverallEntropy)
		for _, f := range r.Findings {
			fmt.Printf("     [%s][%s] %s\n", f.Severity, f.Section, f.Detail)
		}
		if len(r.SectionEntropy) > 0 {
			fmt.Println("     Section breakdown:")
			for _, s := range r.SectionEntropy {
				fmt.Printf("       %-12s %.4f\n", s.Name, s.Entropy)
			}
		}
		fmt.Println()
	}
}

func printFuzzyResult(r scanner.FuzzyResult) {
	if r.Error != nil {
		// ssdeep not installed — warn once but don't spam
		return
	}
	if r.Suspicious {
		fmt.Printf(" [!] DETECTED (Fuzzy Hash) — %s\n", r.FilePath)
		for _, m := range r.Matches {
			fmt.Printf("     [FUZZY] %s — similarity: %d%%\n", m.ThreatName, m.Score)
		}
		fmt.Println()
	}
}

func printSummary(
	results []scanner.ScanResult,
	hResults []scanner.HeuristicResult,
	peResults []scanner.PEResult,
	entropyResults []scanner.EntropyResult,
	fuzzyResults []scanner.FuzzyResult,
	elapsed time.Duration,
) {
	total, hashDet, yaraDet, heurDet, peDet, entropyDet, fuzzyDet, errors := 0, 0, 0, 0, 0, 0, 0, 0

	for _, r := range results {
		total++
		if r.Detected {
			hashDet++
		}
		if len(r.YaraMatches) > 0 {
			yaraDet++
		}
		if r.Error != nil {
			errors++
		}
	}
	for _, h := range hResults {
		if h.Error != nil {
			errors++
		} else if h.Detected() {
			heurDet++
		}
	}
	for _, p := range peResults {
		if p.Suspicious {
			peDet++
		}
	}
	for _, e := range entropyResults {
		if e.Suspicious {
			entropyDet++
		}
	}
	for _, f := range fuzzyResults {
		if f.Suspicious {
			fuzzyDet++
		}
	}

	totalDetections := hashDet + yaraDet + heurDet + peDet + entropyDet + fuzzyDet

	fmt.Println()
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf(" Scan complete         : %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf(" Files scanned         : %d\n", total)
	fmt.Printf(" Hash detections       : %d\n", hashDet)
	fmt.Printf(" YARA detections       : %d\n", yaraDet)
	fmt.Printf(" Heuristic detections  : %d\n", heurDet)
	fmt.Printf(" PE detections         : %d\n", peDet)
	fmt.Printf(" Entropy detections    : %d\n", entropyDet)
	fmt.Printf(" Fuzzy detections      : %d\n", fuzzyDet)
	fmt.Printf(" Errors                : %d\n", errors)
	fmt.Println(strings.Repeat("-", 60))

	if totalDetections > 0 {
		fmt.Println("\n *** THREATS DETECTED — DO NOT EXECUTE FLAGGED FILES ***")
	} else {
		fmt.Println("\n No threats detected.")
	}
}

func main() {
	printBanner()

	scanCmd          := flag.NewFlagSet("scan", flag.ExitOnError)
	scanFile         := scanCmd.String("file", "", "Path to a single file to scan")
	scanDir          := scanCmd.String("dir", "", "Path to a directory to scan recursively")
	scanDB           := scanCmd.String("db", defaultSigDB(), "Path to signature database")
	scanRules        := scanCmd.String("rules", "", "Path to a YARA rule file or directory (optional)")
	scanFuzzyDB      := scanCmd.String("fuzzy-db", defaultFuzzyDB(), "Path to fuzzy hash database")
	scanNoHeuristics := scanCmd.Bool("no-heuristics", false, "Disable heuristic scanning")
	scanNoPE         := scanCmd.Bool("no-pe", false, "Disable PE header analysis")
	scanNoEntropy    := scanCmd.Bool("no-entropy", false, "Disable entropy analysis")
	scanNoFuzzy      := scanCmd.Bool("no-fuzzy", false, "Disable fuzzy hash scanning")

	addCmd  := flag.NewFlagSet("add-hash", flag.ExitOnError)
	addHash := addCmd.String("hash", "", "Hash value to add")
	addType := addCmd.String("type", "SHA256", "Hash type: MD5, SHA1, or SHA256")
	addName := addCmd.String("name", "", "Threat name (e.g. \"WannaCry Ransomware\")")
	addDB   := addCmd.String("db", defaultSigDB(), "Path to signature database")

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  mcctc-av scan --file <path> [--rules <path>] [--no-heuristics] [--no-pe] [--no-entropy] [--no-fuzzy]")
		fmt.Fprintln(os.Stderr, "  mcctc-av scan --dir  <path> [--rules <path>]")
		fmt.Fprintln(os.Stderr, "  mcctc-av add-hash --hash <hash> --name <threat>")
		os.Exit(1)
	}

	switch os.Args[1] {

	case "scan":
		scanCmd.Parse(os.Args[2:])

		if *scanFile == "" && *scanDir == "" {
			fmt.Fprintln(os.Stderr, "[ERROR] Provide --file or --dir")
			scanCmd.Usage()
			os.Exit(1)
		}

		// Load hash signature database
		db, err := scanner.LoadSignatures(*scanDB)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] Loaded %d hash signatures from %s\n", db.Count(), *scanDB)

		// Load YARA rules (optional)
		var ys *scanner.YaraScanner
		if *scanRules != "" {
			var ruleCount int
			ys, ruleCount, err = scanner.LoadYaraRules(*scanRules)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] YARA: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("[*] Loaded %d YARA rule file(s) from %s\n", ruleCount, *scanRules)
		} else {
			fmt.Println("[*] YARA scanning disabled (use --rules to enable)")
		}

		// Load fuzzy hash database (optional)
		var fuzzyDB *scanner.FuzzyDB
		if !*scanNoFuzzy {
			fuzzyDB, err = scanner.LoadFuzzyDB(*scanFuzzyDB)
			if err != nil {
				fmt.Printf("[*] Fuzzy hash DB not found — fuzzy scanning disabled (%v)\n", err)
				fuzzyDB = nil
			} else {
				fmt.Printf("[*] Loaded %d fuzzy hashes from %s\n", fuzzyDB.Count(), *scanFuzzyDB)
			}
		} else {
			fmt.Println("[*] Fuzzy hash scanning disabled")
		}

		// Print detection status
		if !*scanNoHeuristics {
			fmt.Printf("[*] Heuristics enabled (threshold: %d)\n", scanner.HeuristicThreshold)
		} else {
			fmt.Println("[*] Heuristics disabled")
		}
		if !*scanNoPE {
			fmt.Println("[*] PE header analysis enabled")
		}
		if !*scanNoEntropy {
			fmt.Println("[*] Entropy analysis enabled")
		}
		fmt.Println()

		start := time.Now()
		var results         []scanner.ScanResult
		var heuristicResults []scanner.HeuristicResult
		var peResults        []scanner.PEResult
		var entropyResults   []scanner.EntropyResult
		var fuzzyResults     []scanner.FuzzyResult

		if *scanFile != "" {
			fmt.Printf("[*] Scanning file: %s\n\n", *scanFile)
			results = append(results, scanner.ScanFile(*scanFile, db, ys))
		} else {
			fmt.Printf("[*] Scanning directory: %s\n\n", *scanDir)
			results = scanner.ScanDirectory(*scanDir, db, ys)
		}

		for _, r := range results {
			printResult(r)

			if !*scanNoHeuristics {
				h := scanner.ScanHeuristics(r.FilePath)
				heuristicResults = append(heuristicResults, h)
				printHeuristicResult(h)
			}
			if !*scanNoPE {
				p := scanner.ScanPE(r.FilePath)
				peResults = append(peResults, p)
				printPEResult(p)
			}
			if !*scanNoEntropy {
				e := scanner.ScanEntropy(r.FilePath)
				entropyResults = append(entropyResults, e)
				printEntropyResult(e)
			}
			if !*scanNoFuzzy {
				f := scanner.ScanFuzzy(r.FilePath, fuzzyDB)
				fuzzyResults = append(fuzzyResults, f)
				printFuzzyResult(f)
			}
		}

		printSummary(results, heuristicResults, peResults, entropyResults, fuzzyResults, time.Since(start))

	case "add-hash":
		addCmd.Parse(os.Args[2:])

		if *addHash == "" || *addName == "" {
			fmt.Fprintln(os.Stderr, "[ERROR] --hash and --name are required")
			addCmd.Usage()
			os.Exit(1)
		}

		validTypes := map[string]bool{"MD5": true, "SHA1": true, "SHA256": true}
		hashType := strings.ToUpper(*addType)
		if !validTypes[hashType] {
			fmt.Fprintf(os.Stderr, "[ERROR] Invalid hash type %q — must be MD5, SHA1, or SHA256\n", *addType)
			os.Exit(1)
		}

		if err := scanner.AddSignature(*addDB, hashType, *addHash, *addName); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] Added signature: %s|%s|%s\n", hashType, *addHash, *addName)

	default:
		fmt.Fprintf(os.Stderr, "[ERROR] Unknown command %q\n", os.Args[1])
		fmt.Fprintln(os.Stderr, "Commands: scan, add-hash")
		os.Exit(1)
	}
}

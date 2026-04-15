# MCCTC AV — Antivirus Engine

> **Senior Capstone Project** — Built in Go, inspired by the ASTRA Labs open-source AV series.

---

## About This Project

MCCTC AV is a command-line antivirus scanner built in Golang (Go) for my **senior capstone project**. The goal was to go beyond just using security tools and actually understand how they work under the hood — how does an antivirus engine decide if a file is malicious? How does it scan thousands of files efficiently? What are its weaknesses?

This project gave me hands-on experience with:
- Cryptographic hashing (MD5, SHA-1, SHA-256)
- Malware signature databases and IOC (Indicator of Compromise) matching
- YARA rule-based pattern matching
- String and API heuristic detection
- PE header and section analysis
- Entropy-based detection of packed and obfuscated files
- Fuzzy hashing for detecting malware variants
- Recursive file system scanning
- Real-world malware families and how they are tracked

---

## Inspiration & Credit

This project was built by following the **ASTRA Labs AV Engine** YouTube series by [ASTRA-LabsHQ](https://github.com/ASTRA-LabsHQ). The series walks through building a real antivirus engine episode by episode, starting from hash detection all the way to YARA rules and malware evasion techniques.

> All core engine design, architecture, and concepts belong to ASTRA Labs. This repo represents my personal implementation and learning journey following their series.

**Original Repo:** [ASTRA-LabsHQ/Astra-Av-Engine](https://github.com/ASTRA-LabsHQ/Astra-Av-Engine)

---

## What's In the AV

```
| # | Feature | Status |
|---|---------|--------|
| 1 | Hash-based detection (MD5, SHA-1, SHA-256) | ✅ Complete |
| 2 | YARA rule scanning | ✅ Complete |
| 3 | String & API heuristics | ✅ Complete |
| 4 | PE header & section analysis | ✅ Complete |
| 5 | Entropy analysis (packed/encrypted file detection) | ✅ Complete |
| 6 | Fuzzy hashing (ssdeep/TLSH) | ✅ Complete |
```

---

## How It Works

The engine runs six detection layers on every scan simultaneously:

**1. Hash-based detection** — the most fundamental method used by real antivirus software. Computes MD5, SHA-1, and SHA-256 of the target file in a single read pass and checks them against a local database of known malware signatures. If any hash matches, the file is flagged as MALICIOUS.

**2. YARA rule scanning** — pattern matching on strings, byte sequences, and file structure. Loads `.yar` rule files from the `rules/` directory and reports matched rule names, matched strings, and their byte offsets inside the file.

**3. String & API heuristics** — flags suspicious behaviors without needing a known signature. Scans for dangerous API calls like `VirtualAllocEx`, `CreateRemoteThread`, and `WriteProcessMemory`, as well as persistence mechanisms, ransomware indicators, and credential dumping strings. Returns a suspicion score and flags files above the threshold.

**4. PE header & section analysis** — examines the internal structure of Windows executable files. Parses the DOS header, PE signature, file header, optional header, and section table to detect malformed headers, packer section names, writable-and-executable sections, and size mismatches that indicate tampering or injection.

**5. Entropy analysis** — measures how random the data inside a file's sections is using Shannon entropy. Legitimate code has low, predictable entropy. Packed, encrypted, or obfuscated malware produces high-entropy sections that look like random noise. The engine calculates entropy per section and flags suspicious regions.

**6. Fuzzy hashing** — measures similarity between files instead of requiring exact matches. Uses ssdeep to generate a signature that partially matches files sharing overlapping content, allowing the engine to detect malware variants and repacked samples that evade exact hash detection.

---

## Project Structure

```
MCCTC-AV-2026/
├── main.go
├── go.mod
├── scanner/
│   ├── hash_scanner.go       # Part 1 — hash detection
│   ├── yara.go               # Part 2 — YARA rule scanning
│   ├── heuristics.go         # Part 3 — string & API heuristics
│   ├── pe_scanner.go         # Part 4 — PE header analysis
│   ├── entropy_scanner.go    # Part 5 — entropy analysis
│   └── fuzzy_scanner.go      # Part 6 — fuzzy hashing
├── rules/
│   └── malware_generic.yar   # YARA detection rules
└── signatures/
    ├── hashes.txt             # Malware hash database
    └── fuzzy.txt              # Fuzzy hash database
```

---

## Getting Started

### Requirements

- [Go 1.21+](https://go.dev/dl/)
- `yara` binary in PATH — required for YARA scanning
- `ssdeep` binary in PATH — required for fuzzy hashing

**Install YARA:**

Windows — download from [github.com/VirusTotal/yara/releases](https://github.com/VirusTotal/yara/releases)

Linux:
```
sudo apt install yara
```

**Install ssdeep:**

Windows — download from [github.com/ssdeep-project/ssdeep/releases](https://github.com/ssdeep-project/ssdeep/releases)

Linux:
```
sudo apt install ssdeep
```

---

## Step-by-Step Usage

### Windows

### Step 1 — Clone the repo
```
git clone https://github.com/michaelcosbyjr/MCCTC-AV-2026.git
cd MCCTC-AV-2026
```

### Step 2 — Build the binary
```
go build -o mcctc-av.exe .
```

### Step 3 — Run your first scan

**Scan a single file (all detections enabled by default):**
```
.\mcctc-av.exe scan --file suspicious.exe
```

**Scan a single file with YARA rules:**
```
.\mcctc-av.exe scan --file suspicious.exe --rules .\rules
```

**Scan a full directory with all detections:**
```
.\mcctc-av.exe scan --dir .\samples --rules .\rules
```

**Scan with specific layers disabled:**
```
.\mcctc-av.exe scan --file suspicious.exe --no-heuristics
.\mcctc-av.exe scan --file suspicious.exe --no-pe
.\mcctc-av.exe scan --file suspicious.exe --no-entropy
.\mcctc-av.exe scan --file suspicious.exe --no-fuzzy
```

**Add a hash to the signature database:**
```
.\mcctc-av.exe add-hash --hash <sha256> --name "WannaCry Ransomware"
```

**Add a hash with a specific type:**
```
.\mcctc-av.exe add-hash --hash <md5> --type MD5 --name "Emotet Trojan"
```

---

### Linux / macOS

### Step 1 — Clone the repo
```
git clone https://github.com/michaelcosbyjr/MCCTC-AV-2026.git
cd MCCTC-AV-2026
```

### Step 2 — Build the binary
```
go build -o mcctc-av .
```

### Step 3 — Run your first scan

**Scan a single file (all detections enabled by default):**
```
./mcctc-av scan --file suspicious
```

**Scan a single file with YARA rules:**
```
./mcctc-av scan --file suspicious --rules ./rules
```

**Scan a full directory with all detections:**
```
./mcctc-av scan --dir ./samples --rules ./rules
```

**Scan with specific layers disabled:**
```
./mcctc-av scan --file suspicious --no-heuristics
./mcctc-av scan --file suspicious --no-pe
./mcctc-av scan --file suspicious --no-entropy
./mcctc-av scan --file suspicious --no-fuzzy
```

**Add a hash to the signature database:**
```
./mcctc-av add-hash --hash <sha256> --name "WannaCry Ransomware"
```

**Add a hash with a specific type:**
```
./mcctc-av add-hash --hash <md5> --type MD5 --name "Emotet Trojan"
```

---

## Signature Database

Hashes are stored in `signatures/hashes.txt` in a pipe-delimited format:

```
SHA256|24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c|WannaCry Ransomware
MD5|84c82835a5d21bbcf75a61706d8ab549|WannaCry Ransomware
SHA1|4da1f312a214c07143abeeafb695d904440a420a|WannaCry Ransomware
```

Hashes were sourced from [MalwareBazaar](https://bazaar.abuse.ch/), Avast public IOC feeds, and Palo Alto Networks Unit42 threat intelligence reports, covering families like WannaCry, NotPetya, Emotet, Ryuk, REvil, LockBit, Conti, RansomHub, Cobalt Strike, AgentTesla, AsyncRAT, Dridex, TrickBot, FormBook, and more.

---

## What I Learned

- How cryptographic hashing works and why it is used for file identification
- How antivirus engines structure their signature databases
- How YARA rules are written and used for pattern-based malware detection
- How heuristics catch unknown malware by flagging suspicious API usage and behavior
- How PE header analysis detects structural anomalies in Windows executables
- How Shannon entropy reveals packed, encrypted, or obfuscated malware
- How fuzzy hashing identifies malware variants that evade exact hash matching
- The limitations of each detection method and how malware evades them
- How to build and maintain a public GitHub repository as a professional portfolio artifact

---

## Disclaimer

This project is for **educational purposes only** as part of a high school senior capstone. No actual malware samples are included in this repository. All hashes are references to known malware and are safe to store as plain text.

---

## Credits

- **ASTRA Labs** — for the open-source series this project is based on: [github.com/ASTRA-LabsHQ](https://github.com/ASTRA-LabsHQ)
- **MalwareBazaar** — for the public malware hash dataset: [bazaar.abuse.ch](https://bazaar.abuse.ch/)
- **Avast Threat Intelligence** — for public IOC data: [github.com/avast/ioc](https://github.com/avast/ioc)
- **Palo Alto Networks Unit42** — for verified threat intelligence: [github.com/PaloAltoNetworks/Unit42-timely-threat-intel](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel)
```


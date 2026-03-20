#  MCCTC AV — Antivirus Engine

> **Senior Capstone Project** — Built in Go, inspired by the ASTRA Labs open-source AV series.

---

## About This Project
    MCCTC AV is a command-line antivirus scanner I built from scratch in Go for my **senior capstone project**. The goal was to go beyond just using security tools and actually understand how they work under the hood — how does an antivirus engine decide if a file is malicious? How does it scan thousands of files efficiently? What are its weaknesses?

This project gave me hands-on experience with:
- Cryptographic hashing (MD5, SHA-1, SHA-256)
- Malware signature databases and IOC (Indicator of Compromise) matching
- Recursive file system scanning
- Real-world malware families and how they're tracked

---

## Inspiration & Credit

This project was built by following the **ASTRA Labs AV Engine** YouTube series by [ASTRA-LabsHQ](https://github.com/ASTRA-LabsHQ). The series walks through building a real antivirus engine episode by episode, starting from hash detection all the way to YARA rules and malware evasion techniques.

> All core engine design, architecture, and concepts belong to ASTRA Labs. This repo represents my personal implementation and learning journey following their series.


**Original Repo:** [ASTRA-LabsHQ/Astra-Av-Engine](https://github.com/ASTRA-LabsHQ/Astra-Av-Engine)

---

## Whats In the AV 


| 1 |Hash-based detection (MD5, SHA-1, SHA-256) 
| 2 | YARA rule scanning 
| 3 | String & API heuristics |     
| 4 | PE header & section analysis 
| 5 | Entropy analysis 

---

## How It Works

The engine currently uses **hash-based detection** — the most fundamental method used by real antivirus software.

1. When you scan a file, the engine computes its MD5, SHA-1, and SHA-256 hashes in a single read pass
2. Those hashes are checked against a local database (`hashes.txt`) of known malware signatures
3. If any hash matches, the file is flagged as **MALICIOUS** and the threat name is returned
4. If nothing matches, the file is marked **CLEAN**

This is the same core technique used by tools like VirusTotal — the difference is they have millions of signatures and multiple detection engines running in parallel.

---

## Signature Database

Hashes are stored in `signatures/hashes.txt` in a pipe-delimited format:

```
SHA256|24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c|WannaCry Ransomware
MD5|84c82835a5d21bbcf75a61706d8ab549|WannaCry Ransomware
SHA1|4da1f312a214c07143abeeafb695d904440a420a|WannaCry Ransomware
```

Hashes were sourced from [MalwareBazaar](https://bazaar.abuse.ch/) and known public IOC feeds, covering families like WannaCry, NotPetya, Emotet, Ryuk, Cobalt Strike, and more.

---

## What I Learned

- How cryptographic hashing works and why it's used for file identification
- How antivirus engines structure their signature databases
- The limitations of hash-based detection (changing one byte defeats it entirely)
- How to work with Go's standard library for file I/O, hashing, and CLI tooling
- Real malware families, how they're named, and how researchers track them

---

## Disclaimer

This project is for **educational purposes only** as part of a high school senior capstone. No actual malware samples are included in this repository. All hashes are references to known malware and are safe to store as plain text.

---

## Credits

- **ASTRA Labs** — for the open-source series this project is based on: [github.com/ASTRA-LabsHQ](https://github.com/ASTRA-LabsHQ)
- **MalwareBazaar** — for the public malware hash dataset: [bazaar.abuse.ch](https://bazaar.abuse.ch/)

## Step-by-Step Usage

### Windows

### Step 1 — Clone the repo
```bash
git clone https://github.com/michaelcosbyjr/MCCTC-AV-2026.git
cd MCCTC-AV-2026
```

### Step 2 — Build the binary
```bash
go build -o mcctc-av.exe .
```

### Step 3 — Run your first scan

**Scan a single file (all detections enabled by default):**
```bash
.\mcctc-av.exe scan --file suspicious.exe
```

**Scan a single file with YARA rules:**
```bash
.\mcctc-av.exe scan --file suspicious.exe --rules .\rules
```

**Scan a full directory with all detections:**
```bash
.\mcctc-av.exe scan --dir .\samples --rules .\rules
```

**Scan with specific layers disabled:**
```bash
.\mcctc-av.exe scan --file suspicious.exe --no-heuristics
.\mcctc-av.exe scan --file suspicious.exe --no-pe
.\mcctc-av.exe scan --file suspicious.exe --no-entropy
.\mcctc-av.exe scan --file suspicious.exe --no-fuzzy
```

**Add a hash to the signature database:**
```bash
.\mcctc-av.exe add-hash --hash <sha256> --name "WannaCry Ransomware"
```

**Add a hash with a specific type:**
```bash
.\mcctc-av.exe add-hash --hash <md5> --type MD5 --name "Emotet Trojan"
```

---

### Linux / macOS

### Step 1 — Clone the repo
```bash
git clone https://github.com/michaelcosbyjr/MCCTC-AV-2026.git
cd MCCTC-AV-2026
```

### Step 2 — Build the binary
```bash
go build -o mcctc-av .
```

### Step 3 — Run your first scan

**Scan a single file (all detections enabled by default):**
```bash
./mcctc-av scan --file suspicious
```

**Scan a single file with YARA rules:**
```bash
./mcctc-av scan --file suspicious --rules ./rules
```

**Scan a full directory with all detections:**
```bash
./mcctc-av scan --dir ./samples --rules ./rules
```

**Scan with specific layers disabled:**
```bash
./mcctc-av scan --file suspicious --no-heuristics
./mcctc-av scan --file suspicious --no-pe
./mcctc-av scan --file suspicious --no-entropy
./mcctc-av scan --file suspicious --no-fuzzy
```

**Add a hash to the signature database:**
```bash
./mcctc-av add-hash --hash <sha256> --name "WannaCry Ransomware"
```

**Add a hash with a specific type:**
```bash
./mcctc-av add-hash --hash <md5> --type MD5 --name "Emotet Trojan"
```

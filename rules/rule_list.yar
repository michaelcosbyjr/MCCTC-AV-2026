// ============================================================
// MCCTC AV Engine — YARA Rules
// rules/malware_generic.yar
// Original rules by ASTRA Labs — expanded by Michael Cosby
// ============================================================

// ── WannaCry Ransomware ──────────────────────────────────────
rule wannacry_ransomware
{
    meta:
        author      = "ASTRA Labs"
        description = "Detects strings found in WannaCry ransomware"
        threat_level = 3
        in_the_wild = true
    strings:
        $a = "C:\\%s\\qeriuwjhrf"
        $b = "WNcry@2017"
        $c = "msg/m_bulgarian.wnry"
        $d = "WanaCryptor"
        $e = "tasksche.exe"
        $f = "mssecsvc.exe"
        $g = "@WanaDecryptor"
    condition:
        3 of them
}

// ── NotPetya / Petya Ransomware ──────────────────────────────
rule notpetya_ransomware
{
    meta:
        author      = "Michael Cosby"
        description = "Detects NotPetya/Petya ransomware strings"
        threat_level = 5
        in_the_wild = true
    strings:
        $a = "chkdsk" nocase
        $b = "MBR" nocase
        $c = "wevtutil cl Setup" nocase
        $d = "Oops, your important files are encrypted" nocase
        $e = "send $300 worth of bitcoin" nocase
        $f = "1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX" // known NotPetya BTC address
    condition:
        2 of them
}

// ── Ryuk Ransomware ──────────────────────────────────────────
rule ryuk_ransomware
{
    meta:
        author      = "Michael Cosby"
        description = "Detects Ryuk ransomware strings"
        threat_level = 5
        in_the_wild = true
    strings:
        $a = "RyukReadMe" nocase
        $b = "UNIQUE_ID_DO_NOT_REMOVE" nocase
        $c = "No system is safe" nocase
        $d = "Balance of Shadow Universe" nocase
        $e = "RyukReadMe.txt" nocase
    condition:
        2 of them
}

// ── LockBit Ransomware ───────────────────────────────────────
rule lockbit_ransomware
{
    meta:
        author      = "Michael Cosby"
        description = "Detects LockBit ransomware strings"
        threat_level = 5
        in_the_wild = true
    strings:
        $a = "LockBit" nocase
        $b = "Restore-My-Files.txt" nocase
        $c = "lockbit" nocase
        $d = "All your files are stolen and encrypted" nocase
    condition:
        2 of them
}

// ── Conti Ransomware ─────────────────────────────────────────
rule conti_ransomware
{
    meta:
        author      = "Michael Cosby"
        description = "Detects Conti ransomware strings"
        threat_level = 5
        in_the_wild = true
    strings:
        $a = "CONTI" nocase
        $b = "readme.txt" nocase
        $c = "All of your files are currently encrypted" nocase
        $d = "contirecovery" nocase
        $e = "www.contirecovery.best" nocase
    condition:
        2 of them
}

// ── Generic Ransomware Extensions ───────────────────────────
rule generic_ransomware_extensions
{
    meta:
        author      = "ASTRA Labs"
        description = "Detects generic ransomware file extension patterns"
        threat_level = 3
    strings:
        $r1 = ".locked"
        $r2 = ".encrypted"
        $r3 = ".crypt"
        $r4 = "restore_files"
        $r5 = "readme.txt"
        $r6 = "YOUR_FILES_ARE_ENCRYPTED"
        $r7 = "HOW_TO_RECOVER"
        $r8 = "decrypt_instructions"
    condition:
        3 of them
}

// ── Shadow Copy Deletion ─────────────────────────────────────
rule shadow_copy_deletion
{
    meta:
        author      = "Michael Cosby"
        description = "Detects shadow copy deletion — universal ransomware behavior"
        threat_level = 5
        in_the_wild = true
    strings:
        $a = "vssadmin delete shadows" nocase
        $b = "wmic shadowcopy delete" nocase
        $c = "bcdedit /set {default} recoveryenabled no" nocase
        $d = "wbadmin delete catalog" nocase
    condition:
        any of them
}

// ── Mimikatz Credential Dumper ───────────────────────────────
rule mimikatz_strings
{
    meta:
        author      = "ASTRA Labs"
        description = "Detects Mimikatz credential dumping tool"
        threat_level = 5
    strings:
        $m1 = "sekurlsa::logonpasswords"
        $m2 = "mimikatz"
        $m3 = "lsadump::sam"
        $m4 = "kerberos::tickets"
        $m5 = "privilege::debug"
        $m6 = "sekurlsa::wdigest"
        $m7 = "lsadump::dcsync"
    condition:
        2 of them
}

// ── LokiBot Stealer ──────────────────────────────────────────
rule lokibot_stealer
{
    meta:
        author      = "ASTRA Labs"
        description = "Detects LokiBot infostealer behavior"
        threat_level = 4
    strings:
        $l1 = "pass.txt"
        $l2 = "wallet.dat"
        $l3 = "cookies.sqlite"
        $l4 = "logins.json"
        $l5 = "FileZilla"
        $l6 = "key3.db"
        $l7 = "signons.sqlite"
    condition:
        3 of them
}

// ── AgentTesla RAT ───────────────────────────────────────────
rule agenttesla_rat
{
    meta:
        author      = "Michael Cosby"
        description = "Detects AgentTesla RAT strings"
        threat_level = 4
        in_the_wild = true
    strings:
        $a = "AgentTesla" nocase
        $b = "agent tesla" nocase
        $c = "smtp.gmail.com" nocase
        $d = "GetKeyboardLayoutList" nocase
        $e = "KeyLoggerLog" nocase
        $f = "ScreenCapture" nocase
    condition:
        2 of them
}

// ── AsyncRAT ─────────────────────────────────────────────────
rule asyncrat
{
    meta:
        author      = "Michael Cosby"
        description = "Detects AsyncRAT remote access trojan"
        threat_level = 4
        in_the_wild = true
    strings:
        $a = "AsyncRAT" nocase
        $b = "Async-RAT" nocase
        $c = "ServerCertificate" nocase
        $d = "GetInstallPath" nocase
        $e = "Anti-Analysis" nocase
    condition:
        2 of them
}

// ── Cobalt Strike Beacon ─────────────────────────────────────
rule cobalt_strike_beacon
{
    meta:
        author      = "Michael Cosby"
        description = "Detects Cobalt Strike beacon patterns"
        threat_level = 5
        in_the_wild = true
    strings:
        $a = "ReflectiveLoader" nocase
        $b = "beacon.dll" nocase
        $c = "cobaltstrike" nocase
        $d = "%d is an x64 process" nocase
        $e = "Started service" nocase
        $f = "METERPRETER" nocase
    condition:
        2 of them
}

// ── Process Injection APIs ───────────────────────────────────
rule suspicious_process_injection
{
    meta:
        author      = "Michael Cosby"
        description = "Detects common process injection API calls"
        threat_level = 4
    strings:
        $a = "VirtualAllocEx"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
        $d = "NtUnmapViewOfSection"
        $e = "QueueUserAPC"
        $f = "SetThreadContext"
    condition:
        2 of them
}

// ── Obfuscated PowerShell ────────────────────────────────────
rule obfuscated_powershell
{
    meta:
        author      = "ASTRA Labs"
        description = "Detects obfuscated PowerShell payloads"
        threat_level = 3
        in_the_wild = true
    strings:
        $a = "mGcVRgVTSg0q91EScQsi7mS"
        $b = "iSaH2oYMVNrRIwCV"
        $c = "L6jTXt+0GocRGF"
        $d = "wwZw0TenIvTDvtnrZM"
        $e = "-EncodedCommand" nocase
        $f = "FromBase64String" nocase
        $g = "IEX" nocase
        $h = "Invoke-Expression" nocase
    condition:
        3 of them
}

// ── Keylogger APIs ───────────────────────────────────────────
rule suspicious_keylogger
{
    meta:
        author      = "Michael Cosby"
        description = "Detects common keylogger API usage"
        threat_level = 4
    strings:
        $a = "SetWindowsHookEx"
        $b = "GetAsyncKeyState"
        $c = "GetKeyboardState"
        $d = "MapVirtualKey"
        $e = "GetForegroundWindow"
    condition:
        3 of them
}

// ── Highly Suspicious Shellcode ──────────────────────────────
rule highly_sus_shellcode
{
    meta:
        author      = "ASTRA Labs"
        description = "Detects suspicious shellcode byte patterns"
        threat_level = 3
        in_the_wild = true
    strings:
        $a = "0x89,0x00,0x00,0x00,0x60,0x89"
        $b = "0x01,0xd0,0x50,0x8b"
        $c = "0x93,0x31,0xc0,0x66"
        $d = "0x83,0xec,0x04,0xeb,0xce"
    condition:
        3 of them
}

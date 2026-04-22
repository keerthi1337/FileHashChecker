# VirusTotal Hash Checker

A small Python script that checks a file hash in VirusTotal and shows the detection results.

# Why VirusTotal?

This tool uses VirusTotal because it provides a hash-based file report API that aggregates results from many antivirus engines into one JSON response, making it easy to check file reputation and practice security scripting with real‑world data.

I used VirusTotal because it has a hash-based file report API that aggregates results from 
70+ antivirus engines into a single JSON response, which is perfect for a beginner file‑checker.

## What it does

- Asks for a file hash (MD5, SHA-1, or SHA-256)
- Sends the hash to the VirusTotal API v3
- Shows basic file details and detection counts
- Lists which antivirus engines marked the file as malicious
- Saves a text summary, full JSON response, and a log entry for each check [web:25]

## Why this project

I built this to practice:

- calling a real security API
- working with JSON data
- handling errors
- keeping simple logs of what the script did


## Files

```text
HashChecker/
├── vt_hash_checker.py   # main script
├── README.md
├── requirements.txt
└── .gitignore
```

The script creates:

- `report.txt` – human-readable summary
- `report.json` – full VirusTotal JSON response (pretty-printed) 
- `hash_checks.log` – log of all NEW hash checks

## Setup

### 1. Create and activate a virtual environment

```bash
python -m venv .venv
```

PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```bash
pip install requests
pip freeze > requirements.txt
```

### 3. Set your VirusTotal API key

```powershell
$env:VIRUSTOTAL_API_KEY="your_api_key_here"
```

The script reads this from the environment and uses it in the `x-apikey` header, as required by VirusTotal.

## How to run

```bash
python vt_hash_checker.py
```

Then:

1. Enter a hash when asked.
2. Read the results in the terminal.
3. Check `report.txt`, `report.json`, and `hash_checks.log` for saved output.

## Example terminal output

```text
VirusTotal Result
------------------------------
Input Hash: <hash>
Meaningful Name: example.exe
File Type: Win32 EXE
MD5: ...
SHA1: ...
SHA256: ...
Reputation: 0
Times Submitted: 10
Malicious: 5
Suspicious: 0
Harmless: 50
Undetected: 15
Verdict: Potentially malicious

Malicious Engines:
- EngineA: Trojan.Generic
- EngineB: Malware.Sample
```
(The exact values depend on the VirusTotal report for that hash.)

## Common issues and handling

- *API key missing* – script stops with a clear message; set `VIRUSTOTAL_API_KEY` first.
- *Invalid hash length* – warns and exits; only MD5, SHA-1, and SHA-256 are accepted.
- *401 Unauthorized* – usually a bad/expired API key; script prints a hint and logs it.
- *404 Not Found* – VirusTotal has no report for that hash; script shows this and logs it.
- *Network errors* – connection/timeouts are caught as request failures and written to the log.
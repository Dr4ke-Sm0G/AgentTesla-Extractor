# 🕵️ AgentTesla Config Extractor

> **Advanced .NET payload analysis tool for extracting C2 configuration from AgentTesla malware samples.**

***

## ⚠️ Legal Disclaimer

This tool is intended **exclusively for authorized malware analysis, threat intelligence, and defensive security research**. Usage against systems or files without explicit authorization is illegal and unethical. The author assumes no responsibility for misuse.

***

## Overview

`AgentTeslaExtractor` is an industrial-grade Python script that statically and dynamically analyzes AgentTesla .NET payloads to extract decrypted C2 (Command & Control) configuration strings — including SMTP exfiltration endpoints, FTP servers, and HTTP panel URLs.

It leverages `dnlib` (via `pythonnet`) to inspect .NET IL instructions, identify the embedded string decryption method, invoke it safely with a watchdog timeout to bypass anti-analysis loops, and filter results down to actionable IoCs.

***

## Features

| Feature | Description |
|---------|-------------|
| **OOP Architecture** | Clean, extensible class-based design |
| **Anti-Analysis Bypass** | Threaded watchdog with configurable timeout prevents infinite loops |
| **Signature-Based Detection** | Identifies decryption methods by parameter/return type signature (`Int32 → String`) |
| **IL Instruction Parsing** | Extracts `Ldc_I4` operands (integer keys) from all method bodies |
| **Statistical Outlier Removal** | Median-based filtering removes irrelevant integer keys |
| **C2 IoC Detection** | Heuristic filtering for suspicious strings (HTTP, SMTP, FTP) with domain whitelist |
| **JSON Export** | Full report with metadata, IoCs, and all decrypted strings |
| **Verbose Logging** | Structured log output with timestamps via Python `logging` |

***

## Prerequisites

### System Requirements

- Python **3.8+**
- Windows or Linux (with Mono for pythonnet on Linux)
- .NET Runtime accessible by `pythonnet`

### Python Dependencies

```bash
pip install pythonnet
```

### External Tools

- **[dnlib](https://github.com/0xd4d/dnlib)** — .NET assembly reading library  
  Download `dnlib.dll` from the [releases page](https://github.com/0xd4d/dnlib/releases).

***

## Installation

```bash
git clone https://github.com/youruser/agenttesla-extractor
cd agenttesla-extractor
pip install pythonnet
# Place dnlib.dll in the project directory or specify its path with -d
```

***

## Usage

```
python extractor.py -f <payload.exe> [-d <path/to/dnlib.dll>] [-o <report.json>] [-t <timeout>] [--dump-all] [-v]
```

### Arguments

| Argument | Short | Required | Default | Description |
|----------|-------|----------|---------|-------------|
| `--file` | `-f` | ✅ Yes | — | Path to the AgentTesla .NET payload |
| `--dnlib` | `-d` | No | `dnlib.dll` | Path to `dnlib.dll` |
| `--output` | `-o` | No | `<sample>_report.json` | JSON output file path |
| `--timeout` | `-t` | No | `2` | Max seconds per decryption invocation |
| `--dump-all` | — | No | `False` | Export all decrypted strings (not just IoCs) |
| `--verbose` | `-v` | No | `False` | Enable debug-level logging |

### Examples

**Basic extraction:**
```bash
python extractor.py -f sample.exe
```

**With custom dnlib path and JSON export:**
```bash
python extractor.py -f sample.exe -d ./tools/dnlib.dll -o sample_report.json
```

**Verbose mode with extended timeout (for slow samples):**
```bash
python extractor.py -f sample.exe -v -t 5
```

**Dump all decrypted strings (including non-IoC):**
```bash
python extractor.py -f sample.exe --dump-all -o full_dump.json
```

***

## How It Works

```
┌─────────────────────────────────────────────────────┐
│                    AgentTesla PE                    │
└───────────────────────┬─────────────────────────────┘
                        │
            1. Load via dnlib (static)
            2. Load via Reflection (dynamic)
                        │
            ┌───────────▼────────────┐
            │  Scan all methods for  │
            │  signature: Int32→str  │
            └───────────┬────────────┘
                        │
            ┌───────────▼────────────┐
            │  Extract Ldc_I4 keys   │
            │  from all method bodies│
            └───────────┬────────────┘
                        │
            ┌───────────▼────────────┐
            │  Statistical cleanup   │
            │  (median ± 10% filter) │
            └───────────┬────────────┘
                        │
            ┌───────────▼──────────────────┐
            │  Invoke decrypt(key) via      │
            │  Reflection with watchdog     │
            │  timeout (anti-analysis bypass│
            └───────────┬──────────────────┘
                        │
            ┌───────────▼────────────┐
            │  Heuristic C2 filter   │
            │  (http/smtp/ftp + no   │
            │  whitelist domains)    │
            └───────────┬────────────┘
                        │
            ┌───────────▼────────────┐
            │  JSON Report + Console │
            │  IoC Output            │
            └────────────────────────┘
```

### Key Technical Details

**Step 1 — Decryption Method Discovery**  
The script iterates all types and methods in the .NET module looking for `static` methods with exactly one `System.Int32` parameter returning `System.String`. This matches AgentTesla's typical obfuscated string decryption function.

**Step 2 — Integer Key Extraction**  
It walks every method body's IL instructions searching for `Ldc_I4` opcodes immediately followed by a `Call` opcode. These integer constants are the keys passed to the decryption routine.

**Step 3 — Statistical Filtering**  
The median of all extracted keys is computed. Only keys within 10% of the median are kept. This removes outliers that are unlikely to be valid string indices, reducing noise and invocation overhead.

**Step 4 — Watchdog Invocation**  
Each key is passed to the decryption method via .NET Reflection in a **daemon thread** with a configurable timeout. If the thread does not return within the timeout, it is abandoned. This prevents the script from hanging on AgentTesla's anti-debugging traps or infinite loops embedded in the decryption logic.

**Step 5 — C2 Heuristics**  
Decrypted strings are checked for suspicious keywords (`http`, `smtp`, `ftp`, `.com`) and filtered against a whitelist of known legitimate IP-check services (ipify, checkip.amazonaws.com, etc.) to reduce false positives.

***

## Output Format

### Console

```
=======================================================
  AGENT TESLA EXTRACTOR
=======================================================
10:42:31 - [INFO] - Starting Industrial Analysis...
10:42:31 - [INFO] - Targeting 1 methods with 87 keys.
10:42:33 - [INFO] - [+] DETECTED: smtp.mail.ru:587
10:42:33 - [INFO] - [+] DETECTED: attacker@mail.ru

==============================
 FINAL INTELLIGENCE REPORT
==============================
 [!] IoC: smtp.mail.ru:587
 [!] IoC: attacker@mail.ru
```

### JSON Report

```json
{
    "metadata": {
        "filename": "sample.exe",
        "timestamp": "2025-01-15T10:42:31.123456",
        "analysis_tool": "AdvancedAgentTeslaExtractor_v2"
    },
    "extracted_config": [
        "smtp.mail.ru:587",
        "attacker@mail.ru"
    ],
    "all_strings": [
        "smtp.mail.ru:587",
        "attacker@mail.ru",
        "Mozilla/5.0",
        "..."
    ]
}
```

***

## Customization

### Extending the Domain Whitelist

Edit the `ignored_domains` list in `AgentTeslaExtractor.__init__()` to add or remove domains that should be excluded from IoC detection:

```python
self.ignored_domains = [
    "dyn.com", "ipify.org", "checkip.amazonaws.com",
    "whatismyipaddress.com", "ident.me", "ip-api.com",
    "microsoft.com", "google.com",
    # Add your own here
]
```

### Adjusting Outlier Sensitivity

The statistical filter uses a ±10% variance window around the median. To widen or narrow it, modify `_filter_statistical_outliers()`:

```python
variance = abs(val_median * 0.2)  # Increase to 20% for a wider window
```

***

## Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| `Module 'pythonnet' is missing` | pythonnet not installed | `pip install pythonnet` |
| `dnlib.dll not found` | Wrong path | Use `-d` to specify full path |
| `Not a valid .NET PE` | Wrong target file | Confirm the sample is a .NET executable (`file sample.exe`) |
| No IoCs found | Variant uses different decryption signature | Try `--dump-all` and inspect manually; adjust method signature detection |
| Script hangs | Watchdog disabled or timeout too long | Lower `-t` value (e.g., `-t 1`) |
| Linux: CLR load fails | .NET / Mono not installed | Install `mono-complete` or the .NET runtime |

***

## Tested Against

- AgentTesla v2/v3 SMTP-based variants
- Packed samples (note: unpack first with de4dot or similar before analysis)

***

## Project Structure

```
.
├── extractor.py        # Main script
├── dnlib.dll           # Place here (not included)
└── README.md
```

***

## References

- [dnlib — .NET assembly reader/writer](https://github.com/0xd4d/dnlib)
- [pythonnet — Python/.NET interop](https://github.com/pythonnet/pythonnet)
- [AgentTesla MITRE ATT&CK profile](https://attack.mitre.org/software/S0331/)
- [ANY.RUN AgentTesla analysis samples](https://any.run/malware-trends/agenttesla)

***

## License

For educational and authorized research purposes only. See `LICENSE` for details.

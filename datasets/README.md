# ThreatLens Training & Evaluation Dataset

## Overview

This dataset provides labeled cyber threat intelligence and security incident narratives for training and evaluating text classification models in **ThreatLens**.

## Format Specification

The dataset is stored in standard CSV format with comma delimiters:

- `text` (string, required): Unstructured cyber threat report, incident log narrative, or security advisory text.
- `label` (string, required): One of the 11 supported threat categories.
- `source` (string, optional): Origin of the sample (`Synthetic`, `Public Advisory`, `SOC Incident`).

## Supported Threat Categories

1. **Phishing**: Deceptive messages, fake logins, credential lures, spearphishing.
2. **Malware**: Backdoors, trojans, droppers, info-stealers, C2 beacons.
3. **Ransomware**: File encryption, ransom demands, shadow copy deletion, extortion leak threats.
4. **Credential Theft**: Mimikatz, LSASS dumping, brute-force password spraying, Kerberoasting.
5. **Denial of Service**: Volumetric UDP/SYN flooding, Slowloris, application resource exhaustion.
6. **Web Application Attack**: SQL injection, XSS, SSRF, path traversal, web shell uploads.
7. **Vulnerability Exploitation**: Zero-day attacks, CVE exploitation, unauthenticated remote code execution.
8. **Data Exfiltration**: Covert data transfers, cloud storage staging, DNS tunneling.
9. **Reconnaissance**: Port scans, Nmap sweeps, subdomain enumeration, banner grabbing.
10. **Benign or Informational**: Routine maintenance, authorized penetration tests, hygiene audits, patch notices.
11. **Other or Unknown**: Non-security texts, ambiguous narratives without technical threat indicators.

## Synthetic Attribution Disclosure

All examples included in `threat_intelligence_dataset.csv` are synthetically generated or sanitized public security advisories using RFC 5737 documentation IP addresses (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`) and RFC 2606 reserved domains (`example.com`, `example.org`, `example.net`). They do not represent classified or proprietary enterprise intelligence.

import os
import sys
import json
import zipfile
import urllib.request
import io
import pandas as pd
from pathlib import Path
from datetime import datetime, timezone

DATASETS_DIR = Path(__file__).resolve().parent.parent / "datasets"
DATASETS_DIR.mkdir(parents=True, exist_ok=True)

def fetch_cisa_kev():
    """Fetches official CISA Known Exploited Vulnerabilities catalog."""
    kev_path = DATASETS_DIR / "cisa_kev.json"
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    print(f"[*] Fetching CISA KEV from {url}...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ThreatLens-Ingest/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            with open(kev_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            count = len(data.get("vulnerabilities", []))
            print(f"[+] Saved CISA KEV with {count} vulnerabilities to {kev_path}")
            return count
    except Exception as e:
        print(f"[!] Warning: Failed to fetch live CISA KEV: {e}")
        return 0

def fetch_and_prepare_enron():
    """Downloads Enron spam/ham corpus and prepares a clean, balanced NLP dataset."""
    dest_csv = DATASETS_DIR / "enron_spam_cleaned.csv"
    if dest_csv.exists() and dest_csv.stat().st_size > 100000:
        print(f"[+] Enron cleaned dataset already exists at {dest_csv}")
        df = pd.read_csv(dest_csv)
        return len(df)

    url = "https://raw.githubusercontent.com/MWiechmann/enron_spam_data/master/enron_spam_data.zip"
    print(f"[*] Downloading Enron email corpus from {url}...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ThreatLens-Ingest/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            content = resp.read()
            z = zipfile.ZipFile(io.BytesIO(content))
            with z.open("enron_spam_data.csv") as zf:
                df_raw = pd.read_csv(zf)
                print(f"[+] Raw Enron dataset loaded: {len(df_raw)} records")

                # Clean and normalize
                df_raw = df_raw.dropna(subset=["Message", "Spam/Ham"])
                df_raw["text"] = df_raw["Subject"].fillna("") + " " + df_raw["Message"]
                df_raw["text"] = df_raw["text"].astype(str).str.strip()
                df_raw = df_raw[df_raw["text"].str.len() > 30]

                # Map labels: ham -> Safe/Legitimate, spam -> Suspicious/Phishing
                df_raw["label"] = df_raw["Spam/Ham"].map({
                    "ham": "Safe",
                    "spam": "Suspicious"
                })

                # Deduplicate
                df_raw = df_raw.drop_duplicates(subset=["text"])

                # Balance dataset: take sample for efficient, robust training
                safe_df = df_raw[df_raw["label"] == "Safe"].sample(n=min(3000, sum(df_raw["label"] == "Safe")), random_state=42)
                susp_df = df_raw[df_raw["label"] == "Suspicious"].sample(n=min(3000, sum(df_raw["label"] == "Suspicious")), random_state=42)
                balanced_df = pd.concat([safe_df, susp_df]).sample(frac=1.0, random_state=42).reset_index(drop=True)

                balanced_df[["text", "label"]].to_csv(dest_csv, index=False)
                print(f"[+] Prepared balanced Enron dataset: {len(balanced_df)} samples ({len(safe_df)} Safe, {len(susp_df)} Suspicious)")
                return len(balanced_df)
    except Exception as e:
        print(f"[!] Warning: Failed to process Enron dataset: {e}")
        return 0

def prepare_multi_class_cti():
    """Ensures comprehensive multi-class cyber threat intelligence dataset is available."""
    cti_path = DATASETS_DIR / "threat_intelligence_dataset.csv"
    if cti_path.exists():
        df = pd.read_csv(cti_path)
        print(f"[+] Existing CTI dataset contains {len(df)} samples across {df['label'].nunique()} classes.")
        return len(df)
    return 0

def write_metadata(cisa_count, enron_count, cti_count):
    """Writes metadata.json for dataset tracking."""
    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "datasets": [
            {
                "name": "Enron Spam & Ham Corpus (Cleaned)",
                "filename": "enron_spam_cleaned.csv",
                "source": "https://raw.githubusercontent.com/MWiechmann/enron_spam_data/master/enron_spam_data.zip",
                "license": "Public Domain / Research Use",
                "total_samples": enron_count,
                "classes": ["Safe", "Suspicious"],
                "task": "Model A: Binary Suspicious vs Safe Document Classification"
            },
            {
                "name": "CISA Known Exploited Vulnerabilities Catalog",
                "filename": "cisa_kev.json",
                "source": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "license": "U.S. Public Domain (CISA)",
                "total_vulnerabilities": cisa_count,
                "task": "Threat Intelligence Feed & Indicator Enrichment"
            },
            {
                "name": "ThreatLens Multi-Class Cyber Threat Intelligence Dataset",
                "filename": "threat_intelligence_dataset.csv",
                "source": "Sanitized CTI Advisories, MITRE ATT&CK Narratives & RFC 5737 Scenarios",
                "license": "MIT License",
                "total_samples": cti_count,
                "classes": [
                    "Phishing", "Malware", "Ransomware", "Credential Theft",
                    "Denial of Service", "Web Application Attack",
                    "Vulnerability Exploitation", "Data Exfiltration",
                    "Reconnaissance", "Benign or Informational", "Other or Unknown"
                ],
                "task": "Model B: Fine-Grained Threat Category Classification"
            }
        ]
    }
    meta_path = DATASETS_DIR / "metadata.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    print(f"[+] Dataset metadata recorded at {meta_path}")

if __name__ == "__main__":
    cisa_c = fetch_cisa_kev()
    enron_c = fetch_and_prepare_enron()
    cti_c = prepare_multi_class_cti()
    write_metadata(cisa_c, enron_c, cti_c)
    print("[*] Dataset preparation complete.")

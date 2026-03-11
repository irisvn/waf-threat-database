#!/usr/bin/env python3
"""
Fetch malicious IPs from montysecurity/C2-Tracker.

Source: https://github.com/montysecurity/C2-Tracker
Raw IP list: https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/all.txt

C2-Tracker tracks active Command & Control servers for various malware families.
Data is updated frequently from active scanning and threat intelligence.

No API key required (public GitHub raw feed).
ABUSE_CH_AUTH_KEY is read for consistency but not used.
Tier 2 source — confidence: 40-60
"""

import json
import logging
import os
import sys
import time
import argparse
from typing import Dict, List, Optional

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("fetch_c2tracker")

# Primary all-in-one IP list
C2TRACKER_ALL_URL = (
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/all.txt"
)

# Per-family lists for richer metadata (fetched if primary succeeds)
C2TRACKER_FAMILY_URLS: Dict[str, str] = {
    "cobalt_strike": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Cobalt%20Strike%20C2%20IPs.txt",
    "metasploit": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Metasploit%20Framework%20C2%20IPs.txt",
    "sliver": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Sliver%20C2%20IPs.txt",
    "havoc": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Havoc%20C2%20IPs.txt",
    "brute_ratel": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Brute%20Ratel%20C2%20IPs.txt",
}

TIMEOUT_SECONDS = 30
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2  # seconds, exponential: 2, 4, 8


def _get_auth_key() -> Optional[str]:
    """Read API key from environment variable (not used for C2-Tracker public feed)."""
    return os.environ.get("ABUSE_CH_AUTH_KEY")


def _fetch_text_list(url: str, label: str) -> List[str]:
    """
    Fetch a plain-text IP list from URL with retry logic.
    Returns list of IP strings.
    """
    headers = {
        "User-Agent": "waf-threat-database/1.0 (https://github.com/irisvn/pub-waf)",
    }

    last_error: Optional[Exception] = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            logger.info("%s fetch attempt %d/%d", label, attempt, MAX_RETRIES)
            response = requests.get(url, headers=headers, timeout=TIMEOUT_SECONDS)
            response.raise_for_status()

            ips = []
            for line in response.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                ips.append(line)

            logger.info("%s: parsed %d IPs", label, len(ips))
            return ips

        except requests.exceptions.Timeout:
            last_error = Exception(f"Request timed out after {TIMEOUT_SECONDS}s")
            logger.warning("%s attempt %d timed out", label, attempt)
        except requests.exceptions.ConnectionError as e:
            last_error = e
            logger.warning("%s attempt %d connection error: %s", label, attempt, e)
        except requests.exceptions.HTTPError as e:
            last_error = e
            logger.warning("%s attempt %d HTTP error: %s", label, attempt, e)

        if attempt < MAX_RETRIES:
            wait = RETRY_BACKOFF_BASE**attempt
            logger.info("Retrying in %ds...", wait)
            time.sleep(wait)

    logger.error(
        "%s: all %d attempts failed. Last error: %s", label, MAX_RETRIES, last_error
    )
    return []


def fetch(dry_run: bool = False) -> List[Dict]:
    """
    Fetch malicious C2 IPs from montysecurity/C2-Tracker.

    Strategy:
    1. Fetch per-family lists to get richer metadata (malware family attribution)
    2. Fetch all.txt to catch any IPs not in per-family lists
    3. Merge, preferring per-family entries for metadata

    Returns:
        List of dicts with fields: ip, source, confidence, category
    """
    # Auth key is read but not used for C2-Tracker public feed
    auth_key = _get_auth_key()
    if auth_key:
        logger.debug(
            "ABUSE_CH_AUTH_KEY found (not required for C2-Tracker public feed)"
        )

    # Track IPs with family attribution
    ip_to_family: Dict[str, str] = {}

    for family_key, url in C2TRACKER_FAMILY_URLS.items():
        family_ips = _fetch_text_list(url, f"C2-Tracker/{family_key}")
        for ip in family_ips:
            if ip not in ip_to_family:
                ip_to_family[ip] = family_key

    # Fetch all.txt for any remaining IPs
    all_ips = _fetch_text_list(C2TRACKER_ALL_URL, "C2-Tracker/all")
    for ip in all_ips:
        if ip not in ip_to_family:
            ip_to_family[ip] = "unknown"

    # Build results
    results: List[Dict] = []
    for ip, family in ip_to_family.items():
        # Known families get slightly higher confidence
        confidence = 55 if family != "unknown" else 45

        results.append(
            {
                "ip": ip,
                "source": "c2tracker",
                "confidence": confidence,
                "category": "c2",
                "malware_family": family,
            }
        )

    logger.info("C2-Tracker: total %d unique IP entries", len(results))
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Fetch malicious C2 IPs from montysecurity/C2-Tracker"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch data and print to stdout without writing files",
    )
    args = parser.parse_args()

    results = fetch(dry_run=args.dry_run)
    print(json.dumps(results, indent=2))

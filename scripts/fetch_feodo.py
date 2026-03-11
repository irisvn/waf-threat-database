#!/usr/bin/env python3
"""
Fetch malicious IPs from abuse.ch Feodo Tracker blocklist.

Source: https://feodotracker.abuse.ch/
Blocklist URL: https://feodotracker.abuse.ch/downloads/ipblocklist.json
No API key required (public feed), but ABUSE_CH_AUTH_KEY is read for consistency.
Tier 1 source — confidence: 80-100
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
logger = logging.getLogger("fetch_feodo")

FEODO_BLOCKLIST_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
TIMEOUT_SECONDS = 30
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2  # seconds, exponential: 2, 4, 8


def _get_auth_key() -> Optional[str]:
    """Read API key from environment variable (not required for Feodo public feed)."""
    return os.environ.get("ABUSE_CH_AUTH_KEY")


def _parse_confidence(malware: str, status: str) -> int:
    """
    Assign confidence score based on malware family and status.
    Feodo Tracker is Tier 1: 80-100.
    Active C2s get highest confidence.
    """
    high_confidence_malware = {
        "Emotet",
        "TrickBot",
        "QakBot",
        "Dridex",
        "BazarLoader",
        "IcedID",
        "Cobalt Strike",
        "AsyncRAT",
        "AgentTesla",
    }
    if status == "online":
        return 95
    if malware in high_confidence_malware:
        return 90
    return 80


def _parse_category(malware: str) -> str:
    """Map malware family to normalized category."""
    c2_families = {
        "Emotet",
        "TrickBot",
        "QakBot",
        "Dridex",
        "BazarLoader",
        "IcedID",
        "Cobalt Strike",
        "AsyncRAT",
    }
    if malware in c2_families:
        return "c2"
    return "malware"


def fetch(dry_run: bool = False) -> List[Dict]:
    """
    Fetch malicious IPs from Feodo Tracker blocklist.

    Returns:
        List of dicts with fields: ip, source, confidence, category
    """
    # Auth key is read but not required for Feodo public feed
    auth_key = _get_auth_key()
    if auth_key:
        logger.debug("ABUSE_CH_AUTH_KEY found (not required for Feodo public feed)")

    headers = {
        "User-Agent": "waf-threat-database/1.0 (https://github.com/irisvn/pub-waf)",
    }

    last_error: Optional[Exception] = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            logger.info("Feodo Tracker fetch attempt %d/%d", attempt, MAX_RETRIES)
            response = requests.get(
                FEODO_BLOCKLIST_URL,
                headers=headers,
                timeout=TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            data = response.json()

            if not isinstance(data, list):
                logger.error(
                    "Unexpected response format: expected list, got %s", type(data)
                )
                return []

            results: List[Dict] = []
            for entry in data:
                ip = entry.get("ip_address", "").strip()
                if not ip:
                    continue

                malware = entry.get("malware", "")
                status = entry.get("status", "")

                results.append(
                    {
                        "ip": ip,
                        "source": "feodo",
                        "confidence": _parse_confidence(malware, status),
                        "category": _parse_category(malware),
                        "malware": malware,
                        "status": status,
                        "port": entry.get("port"),
                        "first_seen": entry.get("first_seen", ""),
                        "last_online": entry.get("last_online", ""),
                        "country": entry.get("country", ""),
                    }
                )

            logger.info("Feodo Tracker: fetched %d IP entries", len(results))
            return results

        except requests.exceptions.Timeout:
            last_error = Exception(f"Request timed out after {TIMEOUT_SECONDS}s")
            logger.warning("Attempt %d timed out", attempt)
        except requests.exceptions.ConnectionError as e:
            last_error = e
            logger.warning("Attempt %d connection error: %s", attempt, e)
        except requests.exceptions.HTTPError as e:
            last_error = e
            logger.warning("Attempt %d HTTP error: %s", attempt, e)
        except (ValueError, KeyError) as e:
            last_error = e
            logger.warning("Attempt %d parse error: %s", attempt, e)

        if attempt < MAX_RETRIES:
            wait = RETRY_BACKOFF_BASE**attempt
            logger.info("Retrying in %ds...", wait)
            time.sleep(wait)

    logger.error("All %d attempts failed. Last error: %s", MAX_RETRIES, last_error)
    return []


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Fetch malicious IPs from Feodo Tracker"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch data and print to stdout without writing files",
    )
    args = parser.parse_args()

    results = fetch(dry_run=args.dry_run)
    print(json.dumps(results, indent=2))

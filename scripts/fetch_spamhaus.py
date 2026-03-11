#!/usr/bin/env python3
"""
Fetch malicious IP ranges from Spamhaus DROP (Don't Route Or Peer) list.

Source: https://www.spamhaus.org/drop/
DROP list URL: https://www.spamhaus.org/drop/drop.txt
EDROP list URL: https://www.spamhaus.org/drop/edrop.txt

LICENSE NOTICE:
    The Spamhaus DROP list is free for non-commercial use.
    Commercial use requires a paid data feed license from Spamhaus.
    See: https://www.spamhaus.org/organization/dnsblusage/
    If you are using this in a commercial product, you MUST obtain
    a commercial license before using Spamhaus data.

No API key required (public feed), but ABUSE_CH_AUTH_KEY is read for consistency.
Tier 1 source — confidence: 80-100
"""

import ipaddress
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
logger = logging.getLogger("fetch_spamhaus")

SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
SPAMHAUS_EDROP_URL = "https://www.spamhaus.org/drop/edrop.txt"
TIMEOUT_SECONDS = 30
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2  # seconds, exponential: 2, 4, 8


def _get_auth_key() -> Optional[str]:
    """Read API key from environment variable (not required for Spamhaus public feed)."""
    return os.environ.get("ABUSE_CH_AUTH_KEY")


def _parse_drop_line(line: str) -> Optional[Dict]:
    """
    Parse a single line from Spamhaus DROP/EDROP list.

    Format: <CIDR> ; SBL<number>
    Example: 1.10.16.0/20 ; SBL256894
    """
    line = line.strip()
    # Skip comments and empty lines
    if not line or line.startswith(";"):
        return None

    # Split on semicolon to get CIDR and SBL reference
    parts = line.split(";")
    cidr = parts[0].strip()
    sbl_ref = parts[1].strip() if len(parts) > 1 else ""

    # Validate CIDR
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        logger.debug("Invalid CIDR: %s", cidr)
        return None

    return {
        "cidr": str(network),
        "sbl_ref": sbl_ref,
        "network_address": str(network.network_address),
        "prefix_len": network.prefixlen,
    }


def _fetch_list(url: str, list_name: str) -> List[Dict]:
    """Fetch and parse a single Spamhaus DROP/EDROP list with retry logic."""
    headers = {
        "User-Agent": "waf-threat-database/1.0 (https://github.com/irisvn/pub-waf)",
    }

    last_error: Optional[Exception] = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            logger.info("%s fetch attempt %d/%d", list_name, attempt, MAX_RETRIES)
            response = requests.get(url, headers=headers, timeout=TIMEOUT_SECONDS)
            response.raise_for_status()

            entries = []
            for line in response.text.splitlines():
                parsed = _parse_drop_line(line)
                if parsed:
                    entries.append(parsed)

            logger.info("%s: parsed %d CIDR entries", list_name, len(entries))
            return entries

        except requests.exceptions.Timeout:
            last_error = Exception(f"Request timed out after {TIMEOUT_SECONDS}s")
            logger.warning("%s attempt %d timed out", list_name, attempt)
        except requests.exceptions.ConnectionError as e:
            last_error = e
            logger.warning("%s attempt %d connection error: %s", list_name, attempt, e)
        except requests.exceptions.HTTPError as e:
            last_error = e
            logger.warning("%s attempt %d HTTP error: %s", list_name, attempt, e)

        if attempt < MAX_RETRIES:
            wait = RETRY_BACKOFF_BASE**attempt
            logger.info("Retrying in %ds...", wait)
            time.sleep(wait)

    logger.error(
        "%s: all %d attempts failed. Last error: %s", list_name, MAX_RETRIES, last_error
    )
    return []


def fetch(dry_run: bool = False) -> List[Dict]:
    """
    Fetch malicious IP ranges from Spamhaus DROP and EDROP lists.

    NOTE: Spamhaus DROP contains hijacked IP space and malware sources.
    Each entry represents a CIDR range, not a single IP.
    The 'ip' field contains the network address (CIDR notation).

    COMMERCIAL USE WARNING: See module docstring for license requirements.

    Returns:
        List of dicts with fields: ip, source, confidence, category
    """
    # Auth key is read but not required for Spamhaus public feed
    auth_key = _get_auth_key()
    if auth_key:
        logger.debug("ABUSE_CH_AUTH_KEY found (not required for Spamhaus public feed)")

    drop_entries = _fetch_list(SPAMHAUS_DROP_URL, "Spamhaus DROP")
    edrop_entries = _fetch_list(SPAMHAUS_EDROP_URL, "Spamhaus EDROP")

    results: List[Dict] = []

    for entry in drop_entries:
        results.append(
            {
                "ip": entry["cidr"],
                "source": "spamhaus_drop",
                "confidence": 90,
                "category": "hijacked",
                "sbl_ref": entry["sbl_ref"],
                "list": "DROP",
            }
        )

    for entry in edrop_entries:
        results.append(
            {
                "ip": entry["cidr"],
                "source": "spamhaus_edrop",
                "confidence": 85,
                "category": "hijacked",
                "sbl_ref": entry["sbl_ref"],
                "list": "EDROP",
            }
        )

    logger.info(
        "Spamhaus: total %d entries (DROP: %d, EDROP: %d)",
        len(results),
        len(drop_entries),
        len(edrop_entries),
    )
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Fetch malicious IP ranges from Spamhaus DROP/EDROP lists"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch data and print to stdout without writing files",
    )
    args = parser.parse_args()

    results = fetch(dry_run=args.dry_run)
    print(json.dumps(results, indent=2))

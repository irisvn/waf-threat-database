#!/usr/bin/env python3
"""
Fetch malicious IPs from stamparm/ipsum threat intelligence feed.

Source: https://github.com/stamparm/ipsum
Raw feed: https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt

ipsum aggregates IPs from multiple blacklists. Each IP has a score (1-8+)
indicating how many blacklists it appears in. Higher score = more confidence.

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
logger = logging.getLogger("fetch_ipsum")

IPSUM_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
TIMEOUT_SECONDS = 30
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2  # seconds, exponential: 2, 4, 8

# Minimum blacklist count to include an IP (filter noise)
MIN_BLACKLIST_COUNT = 2


def _get_auth_key() -> Optional[str]:
    """Read API key from environment variable (not used for ipsum public feed)."""
    return os.environ.get("ABUSE_CH_AUTH_KEY")


def _score_to_confidence(blacklist_count: int) -> int:
    """
    Map ipsum blacklist count to confidence score.
    ipsum is Tier 2: 40-60.

    blacklist_count 1 → 40 (low confidence, single source)
    blacklist_count 2-3 → 45
    blacklist_count 4-5 → 50
    blacklist_count 6-7 → 55
    blacklist_count 8+  → 60 (high confidence, many sources)
    """
    if blacklist_count >= 8:
        return 60
    if blacklist_count >= 6:
        return 55
    if blacklist_count >= 4:
        return 50
    if blacklist_count >= 2:
        return 45
    return 40


def _parse_ipsum_line(line: str) -> Optional[Dict]:
    """
    Parse a single line from ipsum feed.

    Format: <IP>\t<count>
    Example: 1.2.3.4\t5
    Lines starting with '#' are comments.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    parts = line.split("\t")
    if len(parts) < 2:
        # Some lines may just be IPs without count
        ip = parts[0].strip()
        count = 1
    else:
        ip = parts[0].strip()
        try:
            count = int(parts[1].strip())
        except ValueError:
            count = 1

    if not ip:
        return None

    return {"ip": ip, "blacklist_count": count}


def fetch(dry_run: bool = False) -> List[Dict]:
    """
    Fetch malicious IPs from stamparm/ipsum feed.

    Returns:
        List of dicts with fields: ip, source, confidence, category
    """
    # Auth key is read but not used for ipsum public feed
    auth_key = _get_auth_key()
    if auth_key:
        logger.debug("ABUSE_CH_AUTH_KEY found (not required for ipsum public feed)")

    headers = {
        "User-Agent": "waf-threat-database/1.0 (https://github.com/irisvn/pub-waf)",
    }

    last_error: Optional[Exception] = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            logger.info("ipsum fetch attempt %d/%d", attempt, MAX_RETRIES)
            response = requests.get(
                IPSUM_URL,
                headers=headers,
                timeout=TIMEOUT_SECONDS,
            )
            response.raise_for_status()

            results: List[Dict] = []
            skipped = 0
            for line in response.text.splitlines():
                parsed = _parse_ipsum_line(line)
                if not parsed:
                    continue

                count = parsed["blacklist_count"]
                if count < MIN_BLACKLIST_COUNT:
                    skipped += 1
                    continue

                results.append(
                    {
                        "ip": parsed["ip"],
                        "source": "ipsum",
                        "confidence": _score_to_confidence(count),
                        "category": "threat",
                        "blacklist_count": count,
                    }
                )

            logger.info(
                "ipsum: fetched %d IP entries (skipped %d with count < %d)",
                len(results),
                skipped,
                MIN_BLACKLIST_COUNT,
            )
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
        description="Fetch malicious IPs from stamparm/ipsum threat feed"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch data and print to stdout without writing files",
    )
    parser.add_argument(
        "--min-count",
        type=int,
        default=MIN_BLACKLIST_COUNT,
        help=f"Minimum blacklist count to include IP (default: {MIN_BLACKLIST_COUNT})",
    )
    args = parser.parse_args()

    results = fetch(dry_run=args.dry_run)
    print(json.dumps(results, indent=2))

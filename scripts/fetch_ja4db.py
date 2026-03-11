#!/usr/bin/env python3
"""
Fetch JA4 fingerprints from JA4DB.com API.

Fetches TLS fingerprint data from https://ja4db.com/api/download/ and merges
with custom entries from data/custom_ja4.json if it exists.

Output format: JSON array with fields: ja4, name, classification, source, notes
"""

import json
import sys
import time
import logging
from pathlib import Path
from typing import Any, Optional
from dataclasses import dataclass, asdict

import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Constants
JA4DB_API_URL = "https://ja4db.com/api/download/"
TIMEOUT_SECS = 30
MAX_RETRIES = 3
RETRY_BACKOFF = 2  # exponential backoff multiplier


@dataclass
class JA4Entry:
    """JA4 fingerprint entry."""

    ja4: str
    name: str
    classification: str  # bot|browser|malware|unknown
    source: str
    notes: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


def fetch_ja4db_api(
    timeout: int = TIMEOUT_SECS, max_retries: int = MAX_RETRIES
) -> list[dict[str, Any]]:
    """
    Fetch JA4 fingerprints from JA4DB.com API with retry logic.

    Args:
        timeout: Request timeout in seconds
        max_retries: Number of retry attempts

    Returns:
        List of JA4 entries as dictionaries

    Raises:
        Exception: If all retries fail
    """
    for attempt in range(max_retries):
        try:
            logger.info(f"Fetching JA4DB API (attempt {attempt + 1}/{max_retries})...")
            response = requests.get(JA4DB_API_URL, timeout=timeout)
            response.raise_for_status()

            data = response.json()
            logger.info(f"Successfully fetched {len(data)} entries from JA4DB")
            return data

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout on attempt {attempt + 1}/{max_retries}")
            if attempt < max_retries - 1:
                wait_time = RETRY_BACKOFF**attempt
                logger.info(f"Retrying in {wait_time}s...")
                time.sleep(wait_time)
        except requests.exceptions.RequestException as e:
            logger.warning(
                f"Request failed on attempt {attempt + 1}/{max_retries}: {e}"
            )
            if attempt < max_retries - 1:
                wait_time = RETRY_BACKOFF**attempt
                logger.info(f"Retrying in {wait_time}s...")
                time.sleep(wait_time)
        except json.JSONDecodeError as e:
            logger.warning(
                f"JSON decode error on attempt {attempt + 1}/{max_retries}: {e}"
            )
            if attempt < max_retries - 1:
                wait_time = RETRY_BACKOFF**attempt
                logger.info(f"Retrying in {wait_time}s...")
                time.sleep(wait_time)

    raise Exception(f"Failed to fetch JA4DB after {max_retries} attempts")


def parse_ja4_entries(raw_data: list[dict[str, Any]]) -> list[JA4Entry]:
    """
    Parse raw JA4DB API response into JA4Entry objects.

    The API returns entries with fields like:
    - ja4_fingerprint (or ja4_fingerprint_string for TLS)
    - application, library, device, os
    - verified, notes

    Args:
        raw_data: Raw API response (list of dicts)

    Returns:
        List of parsed JA4Entry objects
    """
    entries = []

    for item in raw_data:
        try:
            # Extract JA4 fingerprint - try multiple field names
            ja4 = None
            if item.get("ja4_fingerprint"):
                ja4 = item.get("ja4_fingerprint", "").strip()
            elif item.get("ja4_fingerprint_string"):
                # For TLS fingerprints, use the string version
                ja4_str = item.get("ja4_fingerprint_string", "").strip()
                if ja4_str:
                    # Extract just the base JA4 hash (first part before underscore)
                    ja4 = ja4_str.split("_")[0] if "_" in ja4_str else ja4_str

            # Skip if no valid JA4 found
            if not ja4:
                continue

            # Build name from application/library/device/os
            name_parts = []
            if item.get("application"):
                name_parts.append(item.get("application", "").strip())
            if item.get("library"):
                name_parts.append(item.get("library", "").strip())
            if item.get("device"):
                name_parts.append(item.get("device", "").strip())
            if item.get("os"):
                name_parts.append(item.get("os", "").strip())

            name = " / ".join(filter(None, name_parts)) or ja4

            # Determine classification based on application/library
            classification = "unknown"
            app_lower = (item.get("application") or "").lower()
            lib_lower = (item.get("library") or "").lower()
            notes_lower = (item.get("notes") or "").lower()

            if any(x in app_lower for x in ["bot", "crawler", "spider", "scanner"]):
                classification = "bot"
            elif any(x in lib_lower for x in ["bot", "crawler", "spider"]):
                classification = "bot"
            elif any(
                x in app_lower
                for x in [
                    "malware",
                    "trojan",
                    "worm",
                    "ransomware",
                    "icedid",
                    "qakbot",
                    "pikabot",
                    "darkgate",
                    "lumma",
                ]
            ):
                classification = "malware"
            elif any(
                x in app_lower
                for x in ["chrome", "firefox", "safari", "edge", "opera", "browser"]
            ):
                classification = "browser"
            elif any(
                x in lib_lower
                for x in ["chrome", "firefox", "safari", "edge", "opera", "browser"]
            ):
                classification = "browser"

            notes = item.get("notes", "").strip() if item.get("notes") else ""

            entry = JA4Entry(
                ja4=ja4,
                name=name,
                classification=classification,
                source="ja4db",
                notes=notes,
            )
            entries.append(entry)

        except Exception as e:
            logger.debug(f"Error parsing entry: {e}")
            continue

    return entries


def load_custom_entries(custom_path: Optional[Path] = None) -> list[JA4Entry]:
    """
    Load custom JA4 entries from data/custom_ja4.json if it exists.

    Args:
        custom_path: Path to custom JSON file (defaults to data/custom_ja4.json)

    Returns:
        List of custom JA4Entry objects
    """
    if custom_path is None:
        custom_path = Path(__file__).parent.parent / "data" / "custom_ja4.json"

    if not custom_path.exists():
        logger.info(f"No custom entries file found at {custom_path}")
        return []

    try:
        logger.info(f"Loading custom entries from {custom_path}")
        with open(custom_path, "r") as f:
            raw_data = json.load(f)

        if not isinstance(raw_data, list):
            logger.warning(f"Custom entries file is not a list, skipping")
            return []

        entries = parse_ja4_entries(raw_data)
        logger.info(f"Loaded {len(entries)} custom entries")
        return entries

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse custom entries JSON: {e}")
        return []
    except Exception as e:
        logger.error(f"Error loading custom entries: {e}")
        return []


def merge_entries(
    api_entries: list[JA4Entry], custom_entries: list[JA4Entry]
) -> list[JA4Entry]:
    """
    Merge API and custom entries, with custom entries taking precedence.

    Args:
        api_entries: Entries from JA4DB API
        custom_entries: Custom entries from data/custom_ja4.json

    Returns:
        Merged list of entries (custom entries override API entries with same ja4)
    """
    # Create dict keyed by ja4 for deduplication
    merged = {entry.ja4: entry for entry in api_entries}

    # Custom entries override API entries
    for entry in custom_entries:
        merged[entry.ja4] = entry

    return list(merged.values())


def main(dry_run: bool = False) -> int:
    """
    Main entry point for JA4DB fetch script.

    Args:
        dry_run: If True, print stats only without writing files

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    try:
        # Fetch from API
        raw_api_data = fetch_ja4db_api()
        api_entries = parse_ja4_entries(raw_api_data)
        logger.info(f"Parsed {len(api_entries)} entries from JA4DB API")

        # Load custom entries
        custom_entries = load_custom_entries()

        # Merge entries
        all_entries = merge_entries(api_entries, custom_entries)
        logger.info(f"Total entries after merge: {len(all_entries)}")

        # Convert to output format
        output = [entry.to_dict() for entry in all_entries]

        if dry_run:
            logger.info(f"DRY RUN: Would output {len(output)} entries")
            print(json.dumps(output, indent=2))
            return 0

        # Output to stdout as JSON
        print(json.dumps(output, indent=2))
        return 0

    except Exception as e:
        logger.error(f"Fatal error: {e}")
        print("[]", file=sys.stderr)
        return 1


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Fetch JA4 fingerprints from JA4DB.com API"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Print stats only, don't write files"
    )

    args = parser.parse_args()
    sys.exit(main(dry_run=args.dry_run))

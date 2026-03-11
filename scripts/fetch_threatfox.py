#!/usr/bin/env python3
"""
Fetch malicious IPs from abuse.ch ThreatFox API.

API docs: https://threatfox.abuse.ch/api/
Requires: ABUSE_CH_AUTH_KEY environment variable
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
logger = logging.getLogger("fetch_threatfox")

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
TIMEOUT_SECONDS = 30
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2  # seconds, exponential: 2, 4, 8


def _get_auth_key() -> Optional[str]:
    """Read API key from environment variable."""
    return os.environ.get("ABUSE_CH_AUTH_KEY")


def _parse_confidence(threat_type: str, malware_printable: str) -> int:
    """
    Assign confidence score based on threat type and malware family.
    ThreatFox is Tier 1: 80-100.
    """
    high_confidence_types = {"botnet_cc", "payload_delivery", "c2"}
    if threat_type in high_confidence_types:
        return 95
    return 80


def _parse_category(threat_type: str) -> str:
    """Map ThreatFox threat_type to normalized category."""
    mapping = {
        "botnet_cc": "c2",
        "payload_delivery": "malware",
        "c2": "c2",
        "payload": "malware",
    }
    return mapping.get(threat_type, "threat")


def _extract_ip(ioc_value: str) -> Optional[str]:
    """Extract IP from IOC value (may be 'ip:port' format)."""
    if not ioc_value:
        return None
    # Handle 'ip:port' format
    parts = ioc_value.split(":")
    ip = parts[0].strip()
    # Basic validation: must have at least 4 octets for IPv4
    if "." in ip and len(ip.split(".")) == 4:
        return ip
    # IPv6 — return as-is if it looks valid
    if ":" in ioc_value and ioc_value.startswith("["):
        # [ipv6]:port format
        ip = ioc_value.split("]")[0].lstrip("[")
        return ip
    return ip if ip else None


def fetch(dry_run: bool = False) -> List[Dict]:
    """
    Fetch malicious IPs from ThreatFox API.

    Returns:
        List of dicts with fields: ip, source, confidence, category
    """
    auth_key = _get_auth_key()
    if not auth_key:
        logger.warning(
            "ABUSE_CH_AUTH_KEY not set — proceeding without auth (rate-limited)"
        )

    payload = {
        "query": "get_iocs",
        "days": 1,
    }
    headers = {
        "Content-Type": "application/json",
        "Auth-Key": auth_key or "",
    }

    last_error: Optional[Exception] = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            logger.info("ThreatFox fetch attempt %d/%d", attempt, MAX_RETRIES)
            response = requests.post(
                THREATFOX_API_URL,
                json=payload,
                headers=headers,
                timeout=TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            data = response.json()

            query_status = data.get("query_status", "")
            if query_status == "no_results":
                logger.info("ThreatFox returned no results")
                return []
            if query_status != "ok":
                logger.error("ThreatFox API error: %s", query_status)
                return []

            results: List[Dict] = []
            iocs = data.get("data", []) or []
            for ioc in iocs:
                ioc_type = ioc.get("ioc_type", "")
                # Only process IP-based IOCs
                if ioc_type not in ("ip:port", "ip"):
                    continue

                ioc_value = ioc.get("ioc", "")
                ip = _extract_ip(ioc_value)
                if not ip:
                    continue

                threat_type = ioc.get("threat_type", "")
                malware_printable = ioc.get("malware_printable", "")

                results.append(
                    {
                        "ip": ip,
                        "source": "threatfox",
                        "confidence": _parse_confidence(threat_type, malware_printable),
                        "category": _parse_category(threat_type),
                        "tags": ioc.get("tags") or [],
                        "malware": malware_printable,
                        "first_seen": ioc.get("first_seen", ""),
                        "last_seen": ioc.get("last_seen", ""),
                    }
                )

            logger.info("ThreatFox: fetched %d IP entries", len(results))
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
    parser = argparse.ArgumentParser(description="Fetch malicious IPs from ThreatFox")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch data and print to stdout without writing files",
    )
    args = parser.parse_args()

    results = fetch(dry_run=args.dry_run)
    print(json.dumps(results, indent=2))

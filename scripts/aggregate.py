#!/usr/bin/env python3
"""
Aggregate threat intelligence data from multiple fetch scripts.

This script:
1. Calls all 6 fetch scripts (threatfox, feodo, spamhaus, ipsum, c2tracker, ja4db)
2. Deduplicates IPs, keeping max confidence score and merging sources
3. Applies tier-based scoring
4. Validates data (>10% invalid entries → reject)
5. Outputs 4 files: ip_reputation.json, ip_blocklist.txt, ja4_fingerprints.json, stats.json

Usage:
    python3 scripts/aggregate.py --dry-run
    python3 scripts/aggregate.py --output-dir data/
    python3 scripts/aggregate.py --verbose
"""

import argparse
import ipaddress
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Import fetch scripts as modules
script_dir = Path(__file__).parent
sys.path.insert(0, str(script_dir))

import fetch_threatfox
import fetch_feodo
import fetch_spamhaus
import fetch_ipsum
import fetch_c2tracker
import fetch_ja4db

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("aggregate")

# Constants
VERSION = "1.0.0"
MAX_IP_ENTRIES = 50000
MAX_JA4_ENTRIES = 1000
VALIDATION_THRESHOLD = 0.10  # 10% invalid entries threshold

# Tier scoring configuration
TIER_1_SOURCES = {"threatfox", "feodo", "spamhaus_drop", "spamhaus_edrop"}
TIER_1_MIN_CONFIDENCE = 80
TIER_1_MAX_CONFIDENCE = 100

TIER_2_SOURCES = {"ipsum", "c2tracker"}
TIER_2_MIN_CONFIDENCE = 40
TIER_2_MAX_CONFIDENCE = 60


def get_version() -> str:
    """Get current UTC ISO format timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_ip(ip_str: str) -> bool:
    """
    Validate IP address or CIDR notation.
    
    Accepts:
    - IPv4: 1.2.3.4
    - IPv4 CIDR: 1.2.3.4/24
    - IPv6: 2001:db8::1
    - IPv6 CIDR: 2001:db8::/32
    
    Returns:
        True if valid, False otherwise
    """
    if not ip_str:
        return False
    
    try:
        # Try parsing as IP network (handles both single IPs and CIDR)
        ipaddress.ip_network(ip_str, strict=False)
        return True
    except ValueError:
        return False


def validate_ja4_entry(entry: Dict[str, Any]) -> bool:
    """
    Validate JA4 fingerprint entry.
    
    Required fields: ja4, name, classification, source
    
    Returns:
        True if valid, False otherwise
    """
    required_fields = {"ja4", "name", "classification", "source"}
    
    if not all(field in entry for field in required_fields):
        return False
    
    if not entry["ja4"] or not isinstance(entry["ja4"], str):
        return False
    
    if not entry["name"] or not isinstance(entry["name"], str):
        return False
    
    if entry["classification"] not in {"bot", "browser", "malware", "unknown"}:
        return False
    
    if not entry["source"] or not isinstance(entry["source"], str):
        return False
    
    return True


def validate_ip_entry(entry: Dict[str, Any]) -> bool:
    """
    Validate IP reputation entry.
    
    Required fields: ip, confidence, sources, categories
    
    Returns:
        True if valid, False otherwise
    """
    required_fields = {"ip", "confidence", "sources", "categories"}
    
    if not all(field in entry for field in required_fields):
        return False
    
    if not validate_ip(entry["ip"]):
        return False
    
    if not isinstance(entry["confidence"], int) or entry["confidence"] < 0 or entry["confidence"] > 100:
        return False
    
    if not isinstance(entry["sources"], list) or len(entry["sources"]) == 0:
        return False
    
    if not isinstance(entry["categories"], list) or len(entry["categories"]) == 0:
        return False
    
    return True


def normalize_source(source: str) -> str:
    """Normalize source name for consistent tracking."""
    return source.lower().replace("-", "_").replace(" ", "_")


def apply_tier_scoring(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Apply tier-based confidence scoring to entries.
    
    Tier 1 (abuse.ch/Spamhaus): 80-100
    Tier 2 (ipsum/C2-Tracker): 40-60
    
    Returns:
        List of entries with adjusted confidence scores
    """
    for entry in entries:
        source = normalize_source(entry.get("source", ""))
        confidence = entry.get("confidence", 50)
        
        # Clamp confidence to tier bounds
        if source in TIER_1_SOURCES:
            entry["confidence"] = max(TIER_1_MIN_CONFIDENCE, min(TIER_1_MAX_CONFIDENCE, confidence))
        elif source in TIER_2_SOURCES:
            entry["confidence"] = max(TIER_2_MIN_CONFIDENCE, min(TIER_2_MAX_CONFIDENCE, confidence))
    
    return entries


def deduplicate_ip_entries(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate IP entries by merging sources and keeping max confidence.
    
    When same IP appears from multiple sources:
    - Keep the highest confidence score
    - Merge all sources into a single array
    - Merge all categories into a single array
    - Keep additional metadata from highest-confidence entry
    
    Returns:
        Deduplicated list of IP entries
    """
    ip_map: Dict[str, Dict[str, Any]] = {}
    
    for entry in entries:
        ip = entry.get("ip", "")
        if not ip:
            continue
        
        source = normalize_source(entry.get("source", "unknown"))
        confidence = entry.get("confidence", 50)
        category = entry.get("category", "threat")
        
        if ip not in ip_map:
            # First occurrence of this IP
            ip_map[ip] = {
                "ip": ip,
                "confidence": confidence,
                "sources": [source],
                "categories": [category] if category else [],
                "_metadata": entry,  # Keep metadata from highest-confidence source
            }
        else:
            # IP already exists - merge
            existing = ip_map[ip]
            
            # Merge sources (avoid duplicates)
            if source not in existing["sources"]:
                existing["sources"].append(source)
            
            # Merge categories (avoid duplicates)
            if category and category not in existing["categories"]:
                existing["categories"].append(category)
            
            # Update confidence if this source has higher score
            if confidence > existing["confidence"]:
                existing["confidence"] = confidence
                existing["_metadata"] = entry  # Use metadata from highest-confidence source
    
    # Remove internal metadata and build final list
    result = []
    for ip, data in ip_map.items():
        final_entry = {
            "ip": data["ip"],
            "confidence": data["confidence"],
            "sources": sorted(data["sources"]),
            "categories": sorted(data["categories"]),
        }
        
        # Add useful metadata from highest-confidence source
        metadata = data["_metadata"]
        for key in ["malware", "malware_family", "status", "country", "first_seen", "last_seen"]:
            if key in metadata and metadata[key]:
                final_entry[key] = metadata[key]
        
        result.append(final_entry)
    
    # Sort by confidence (descending) for consistent ordering
    result.sort(key=lambda x: (-x["confidence"], x["ip"]))
    
    return result


def fetch_all_ip_data(dry_run: bool = False, verbose: bool = False) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Fetch IP data from all 5 IP sources.
    
    Returns:
        Tuple of (all_entries, source_names)
    """
    all_entries = []
    sources = []
    
    fetchers = [
        ("ThreatFox", fetch_threatfox.fetch),
        ("Feodo Tracker", fetch_feodo.fetch),
        ("Spamhaus", fetch_spamhaus.fetch),
        ("ipsum", fetch_ipsum.fetch),
        ("C2-Tracker", fetch_c2tracker.fetch),
    ]
    
    for name, fetch_func in fetchers:
        try:
            logger.info("Fetching data from %s...", name)
            entries = fetch_func(dry_run=dry_run)
            
            if entries:
                logger.info("%s: fetched %d entries", name, len(entries))
                all_entries.extend(entries)
                # Extract source names from first entry
                if entries and "source" in entries[0]:
                    sources.append(normalize_source(entries[0]["source"]))
            else:
                logger.warning("%s: no entries fetched", name)
        except Exception as e:
            logger.error("%s: fetch failed with error: %s", name, e)
            if verbose:
                logger.exception("Full traceback for %s failure", name)
    
    return all_entries, sources


def fetch_ja4_data(dry_run: bool = False, verbose: bool = False) -> Tuple[List[Dict[str, Any]], str]:
    """
    Fetch JA4 fingerprint data.
    
    Returns:
        Tuple of (entries, source_name)
    """
    try:
        logger.info("Fetching JA4 fingerprints from JA4DB...")
        
        # Use the main function from fetch_ja4db
        # It returns exit code, but outputs JSON to stdout
        # We need to capture it differently
        
        # Call the fetch function directly
        import io
        from contextlib import redirect_stdout
        
        f = io.StringIO()
        with redirect_stdout(f):
            exit_code = fetch_ja4db.main(dry_run=dry_run)
        
        if exit_code == 0:
            output = f.getvalue()
            entries = json.loads(output)
            logger.info("JA4DB: fetched %d entries", len(entries))
            return entries, "ja4db"
        else:
            logger.error("JA4DB: fetch failed with exit code %d", exit_code)
            return [], "ja4db"
    except Exception as e:
        logger.error("JA4DB: fetch failed with error: %s", e)
        if verbose:
            logger.exception("Full traceback for JA4DB failure")
        return [], "ja4db"


def validate_entries(entries: List[Dict[str, Any]], validator_func) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Validate entries and separate valid from invalid.
    
    Returns:
        Tuple of (valid_entries, invalid_entries)
    """
    valid = []
    invalid = []
    
    for entry in entries:
        if validator_func(entry):
            valid.append(entry)
        else:
            invalid.append(entry)
    
    return valid, invalid


def enforce_limits(ip_entries: List[Dict[str, Any]], ja4_entries: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Enforce entry limits.
    
    - max_ip_entries: 50000
    - max_ja4_entries: 1000
    
    Returns:
        Tuple of (limited_ip_entries, limited_ja4_entries)
    """
    limited_ips = ip_entries[:MAX_IP_ENTRIES]
    limited_ja4 = ja4_entries[:MAX_JA4_ENTRIES]
    
    if len(ip_entries) > MAX_IP_ENTRIES:
        logger.warning("IP entries exceeded limit (%d > %d) - truncated to %d", 
                      len(ip_entries), MAX_IP_ENTRIES, MAX_IP_ENTRIES)
    
    if len(ja4_entries) > MAX_JA4_ENTRIES:
        logger.warning("JA4 entries exceeded limit (%d > %d) - truncated to %d",
                      len(ja4_entries), MAX_JA4_ENTRIES, MAX_JA4_ENTRIES)
    
    return limited_ips, limited_ja4


def write_ip_reputation_json(entries: List[Dict[str, Any]], sources: List[str], output_path: Path) -> None:
    """Write ip_reputation.json file."""
    output = {
        "version": VERSION,
        "generated_at": get_version(),
        "sources": sorted(sources),
        "entries": entries,
    }
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    logger.info("Written %d entries to %s", len(entries), output_path)


def write_ip_blocklist_txt(entries: List[Dict[str, Any]], output_path: Path) -> None:
    """Write ip_blocklist.txt file (sorted, deduped, one IP per line)."""
    # Extract unique IPs (already deduped from aggregation)
    ips = sorted(set(entry["ip"] for entry in entries))
    
    with open(output_path, "w", encoding="utf-8") as f:
        for ip in ips:
            f.write(ip + "\n")
    
    logger.info("Written %d IPs to %s", len(ips), output_path)


def write_ja4_fingerprints_json(entries: List[Dict[str, Any]], output_path: Path) -> None:
    """Write ja4_fingerprints.json file."""
    output = {
        "version": VERSION,
        "generated_at": get_version(),
        "entries": entries,
    }
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    logger.info("Written %d entries to %s", len(entries), output_path)


def write_stats_json(ip_count: int, ja4_count: int, sources: List[str], output_path: Path) -> None:
    """Write stats.json file."""
    output = {
        "ip_count": ip_count,
        "ja4_count": ja4_count,
        "sources": sorted(sources),
        "last_updated": get_version(),
    }
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    logger.info("Written stats to %s", output_path)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Aggregate threat intelligence data from multiple sources"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch and process data without writing output files",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Output directory for generated files (default: data/ relative to script)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging with full tracebacks",
    )
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Determine output directory
    if args.output_dir:
        output_dir = args.output_dir
    else:
        output_dir = Path(__file__).parent.parent / "data"
    
    # Ensure output directory exists
    if not args.dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)
    
    logger.info("Starting aggregation process...")
    logger.info("Output directory: %s", output_dir)
    logger.info("Dry run: %s", args.dry_run)
    
    # Fetch IP data from all sources
    logger.info("=" * 60)
    logger.info("FETCHING IP DATA")
    logger.info("=" * 60)
    
    ip_entries, ip_sources = fetch_all_ip_data(dry_run=args.dry_run, verbose=args.verbose)
    logger.info("Total IP entries fetched: %d", len(ip_entries))
    
    # Apply tier scoring
    logger.info("Applying tier-based scoring...")
    ip_entries = apply_tier_scoring(ip_entries)
    
    # Deduplicate IP entries
    logger.info("Deduplicating IP entries...")
    ip_entries = deduplicate_ip_entries(ip_entries)
    logger.info("IP entries after deduplication: %d", len(ip_entries))
    
    # Validate IP entries
    logger.info("Validating IP entries...")
    valid_ip_entries, invalid_ip_entries = validate_entries(ip_entries, validate_ip_entry)
    
    total_ip = len(ip_entries)
    invalid_ip_count = len(invalid_ip_entries)
    
    if total_ip > 0:
        invalid_ratio = invalid_ip_count / total_ip
        logger.info("IP validation: %d valid, %d invalid (%.2f%%)", 
                   len(valid_ip_entries), invalid_ip_count, invalid_ratio * 100)
        
        if invalid_ratio > VALIDATION_THRESHOLD:
            logger.error("Validation failed: %.2f%% invalid entries (threshold: %.2f%%)",
                        invalid_ratio * 100, VALIDATION_THRESHOLD * 100)
            print(f"Validation failed: >{VALIDATION_THRESHOLD*100:.0f}% invalid entries", file=sys.stderr)
            return 1
    else:
        logger.warning("No IP entries fetched - validation skipped")
        valid_ip_entries = []
    
    # Fetch JA4 data
    logger.info("=" * 60)
    logger.info("FETCHING JA4 DATA")
    logger.info("=" * 60)
    
    ja4_entries, ja4_source = fetch_ja4_data(dry_run=args.dry_run, verbose=args.verbose)
    logger.info("Total JA4 entries fetched: %d", len(ja4_entries))
    
    # Validate JA4 entries
    logger.info("Validating JA4 entries...")
    valid_ja4_entries, invalid_ja4_entries = validate_entries(ja4_entries, validate_ja4_entry)
    
    total_ja4 = len(ja4_entries)
    invalid_ja4_count = len(invalid_ja4_entries)
    
    if total_ja4 > 0:
        invalid_ratio = invalid_ja4_count / total_ja4
        logger.info("JA4 validation: %d valid, %d invalid (%.2f%%)",
                   len(valid_ja4_entries), invalid_ja4_count, invalid_ratio * 100)
        
        if invalid_ratio > VALIDATION_THRESHOLD:
            logger.error("Validation failed: %.2f%% invalid JA4 entries (threshold: %.2f%%)",
                        invalid_ratio * 100, VALIDATION_THRESHOLD * 100)
            print(f"Validation failed: >{VALIDATION_THRESHOLD*100:.0f}% invalid JA4 entries", file=sys.stderr)
            return 1
    else:
        logger.warning("No JA4 entries fetched - validation skipped")
        valid_ja4_entries = []
    
    # Enforce limits
    logger.info("Enforcing entry limits...")
    valid_ip_entries, valid_ja4_entries = enforce_limits(valid_ip_entries, valid_ja4_entries)
    
    # Combine all sources for stats
    all_sources = ip_sources + ([ja4_source] if ja4_source else [])
    
    # Write output files
    if not args.dry_run:
        logger.info("=" * 60)
        logger.info("WRITING OUTPUT FILES")
        logger.info("=" * 60)
        
        write_ip_reputation_json(
            valid_ip_entries,
            all_sources,
            output_dir / "ip_reputation.json"
        )
        
        write_ip_blocklist_txt(
            valid_ip_entries,
            output_dir / "ip_blocklist.txt"
        )
        
        write_ja4_fingerprints_json(
            valid_ja4_entries,
            output_dir / "ja4_fingerprints.json"
        )
        
        write_stats_json(
            len(valid_ip_entries),
            len(valid_ja4_entries),
            all_sources,
            output_dir / "stats.json"
        )
    else:
        logger.info("DRY RUN: No files written")
        logger.info("Would write:")
        logger.info("  - %s (%d entries)", output_dir / "ip_reputation.json", len(valid_ip_entries))
        logger.info("  - %s (%d IPs)", output_dir / "ip_blocklist.txt", len(valid_ip_entries))
        logger.info("  - %s (%d entries)", output_dir / "ja4_fingerprints.json", len(valid_ja4_entries))
        logger.info("  - %s", output_dir / "stats.json")
    
    # Summary
    logger.info("=" * 60)
    logger.info("AGGREGATION COMPLETE")
    logger.info("=" * 60)
    logger.info("IP entries: %d", len(valid_ip_entries))
    logger.info("JA4 entries: %d", len(valid_ja4_entries))
    logger.info("Sources: %s", ", ".join(sorted(all_sources)))
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Tests for output JSON schema validation.
Validates that output files match expected schema structure.
"""

import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import aggregate


# ---------------------------------------------------------------------------
# Schema definitions (expected structure)
# ---------------------------------------------------------------------------

REQUIRED_IP_REPUTATION_KEYS = {"version", "generated_at", "sources", "entries"}
REQUIRED_IP_ENTRY_KEYS = {"ip", "confidence", "sources", "categories"}
REQUIRED_JA4_FINGERPRINTS_KEYS = {"version", "generated_at", "entries"}
REQUIRED_JA4_ENTRY_KEYS = {"ja4", "name", "classification", "source"}
REQUIRED_STATS_KEYS = {"ip_count", "ja4_count", "sources", "last_updated"}

VALID_JA4_CLASSIFICATIONS = {"bot", "browser", "malware", "unknown"}


# ---------------------------------------------------------------------------
# ip_reputation.json schema tests
# ---------------------------------------------------------------------------


class TestIpReputationSchema:
    """Tests for ip_reputation.json output schema."""

    def _make_ip_entries(self, count: int = 3) -> List[Dict[str, Any]]:
        return [
            {
                "ip": f"1.2.3.{i}",
                "confidence": 80 + i,
                "sources": ["threatfox"],
                "categories": ["c2"],
            }
            for i in range(count)
        ]

    def test_write_ip_reputation_json_creates_file(self, tmp_path):
        """write_ip_reputation_json should create a valid JSON file."""
        entries = self._make_ip_entries(3)
        output_path = tmp_path / "ip_reputation.json"

        aggregate.write_ip_reputation_json(entries, ["threatfox"], output_path)

        assert output_path.exists()

    def test_ip_reputation_json_top_level_keys(self, tmp_path):
        """ip_reputation.json should have all required top-level keys."""
        entries = self._make_ip_entries(2)
        output_path = tmp_path / "ip_reputation.json"

        aggregate.write_ip_reputation_json(entries, ["threatfox", "feodo"], output_path)

        with open(output_path) as f:
            data = json.load(f)

        assert REQUIRED_IP_REPUTATION_KEYS.issubset(data.keys()), (
            f"Missing keys: {REQUIRED_IP_REPUTATION_KEYS - set(data.keys())}"
        )

    def test_ip_reputation_json_version_field(self, tmp_path):
        """version field should be a non-empty string."""
        entries = self._make_ip_entries(1)
        output_path = tmp_path / "ip_reputation.json"

        aggregate.write_ip_reputation_json(entries, ["threatfox"], output_path)

        with open(output_path) as f:
            data = json.load(f)

        assert isinstance(data["version"], str)
        assert len(data["version"]) > 0

    def test_ip_reputation_json_generated_at_format(self, tmp_path):
        """generated_at should be an ISO 8601 UTC timestamp."""
        entries = self._make_ip_entries(1)
        output_path = tmp_path / "ip_reputation.json"

        aggregate.write_ip_reputation_json(entries, ["threatfox"], output_path)

        with open(output_path) as f:
            data = json.load(f)

        generated_at = data["generated_at"]
        assert isinstance(generated_at, str)
        # Should match pattern like 2024-01-01T00:00:00Z
        assert "T" in generated_at
        assert generated_at.endswith("Z")

    def test_ip_reputation_json_sources_is_list(self, tmp_path):
        """sources field should be a list."""
        entries = self._make_ip_entries(1)
        output_path = tmp_path / "ip_reputation.json"

        aggregate.write_ip_reputation_json(entries, ["threatfox", "feodo"], output_path)

        with open(output_path) as f:
            data = json.load(f)

        assert isinstance(data["sources"], list)

    def test_ip_reputation_json_sources_sorted(self, tmp_path):
        """sources should be sorted alphabetically."""
        entries = self._make_ip_entries(1)
        output_path = tmp_path / "ip_reputation.json"

        aggregate.write_ip_reputation_json(
            entries, ["threatfox", "feodo", "ipsum"], output_path
        )

        with open(output_path) as f:
            data = json.load(f)

        assert data["sources"] == sorted(data["sources"])

    def test_ip_reputation_json_entries_is_list(self, tmp_path):
        """entries field should be a list."""
        entries = self._make_ip_entries(3)
        output_path = tmp_path / "ip_reputation.json"

        aggregate.write_ip_reputation_json(entries, ["threatfox"], output_path)

        with open(output_path) as f:
            data = json.load(f)

        assert isinstance(data["entries"], list)
        assert len(data["entries"]) == 3

    def test_ip_reputation_json_entry_schema(self, tmp_path):
        """Each entry should have required fields with correct types."""
        entries = self._make_ip_entries(2)
        output_path = tmp_path / "ip_reputation.json"

        aggregate.write_ip_reputation_json(entries, ["threatfox"], output_path)

        with open(output_path) as f:
            data = json.load(f)

        for entry in data["entries"]:
            assert REQUIRED_IP_ENTRY_KEYS.issubset(entry.keys()), (
                f"Entry missing keys: {REQUIRED_IP_ENTRY_KEYS - set(entry.keys())}"
            )
            assert isinstance(entry["ip"], str)
            assert isinstance(entry["confidence"], int)
            assert 0 <= entry["confidence"] <= 100
            assert isinstance(entry["sources"], list)
            assert len(entry["sources"]) > 0
            assert isinstance(entry["categories"], list)
            assert len(entry["categories"]) > 0

    def test_ip_reputation_json_valid_ips(self, tmp_path):
        """All IPs in entries should be valid IP addresses or CIDRs."""
        entries = [
            {
                "ip": "1.2.3.4",
                "confidence": 80,
                "sources": ["threatfox"],
                "categories": ["c2"],
            },
            {
                "ip": "10.0.0.0/8",
                "confidence": 90,
                "sources": ["spamhaus_drop"],
                "categories": ["hijacked"],
            },
        ]
        output_path = tmp_path / "ip_reputation.json"

        aggregate.write_ip_reputation_json(
            entries, ["threatfox", "spamhaus_drop"], output_path
        )

        with open(output_path) as f:
            data = json.load(f)

        for entry in data["entries"]:
            assert aggregate.validate_ip(entry["ip"]), f"Invalid IP: {entry['ip']}"

    def test_ip_reputation_json_is_valid_json(self, tmp_path):
        """Output file should be valid JSON."""
        entries = self._make_ip_entries(5)
        output_path = tmp_path / "ip_reputation.json"

        aggregate.write_ip_reputation_json(entries, ["threatfox"], output_path)

        # Should not raise
        with open(output_path) as f:
            data = json.load(f)

        assert data is not None


# ---------------------------------------------------------------------------
# ip_blocklist.txt schema tests
# ---------------------------------------------------------------------------


class TestIpBlocklistSchema:
    """Tests for ip_blocklist.txt output schema."""

    def test_write_ip_blocklist_txt_creates_file(self, tmp_path):
        """write_ip_blocklist_txt should create a text file."""
        entries = [
            {
                "ip": "1.2.3.4",
                "confidence": 80,
                "sources": ["threatfox"],
                "categories": ["c2"],
            },
        ]
        output_path = tmp_path / "ip_blocklist.txt"

        aggregate.write_ip_blocklist_txt(entries, output_path)

        assert output_path.exists()

    def test_ip_blocklist_one_ip_per_line(self, tmp_path):
        """Each line should contain exactly one IP."""
        entries = [
            {
                "ip": "1.2.3.4",
                "confidence": 80,
                "sources": ["threatfox"],
                "categories": ["c2"],
            },
            {
                "ip": "5.6.7.8",
                "confidence": 90,
                "sources": ["feodo"],
                "categories": ["malware"],
            },
            {
                "ip": "9.10.11.12",
                "confidence": 85,
                "sources": ["ipsum"],
                "categories": ["threat"],
            },
        ]
        output_path = tmp_path / "ip_blocklist.txt"

        aggregate.write_ip_blocklist_txt(entries, output_path)

        lines = output_path.read_text().strip().splitlines()
        assert len(lines) == 3

    def test_ip_blocklist_sorted(self, tmp_path):
        """IPs should be sorted alphabetically."""
        entries = [
            {
                "ip": "9.10.11.12",
                "confidence": 85,
                "sources": ["ipsum"],
                "categories": ["threat"],
            },
            {
                "ip": "1.2.3.4",
                "confidence": 80,
                "sources": ["threatfox"],
                "categories": ["c2"],
            },
            {
                "ip": "5.6.7.8",
                "confidence": 90,
                "sources": ["feodo"],
                "categories": ["malware"],
            },
        ]
        output_path = tmp_path / "ip_blocklist.txt"

        aggregate.write_ip_blocklist_txt(entries, output_path)

        lines = output_path.read_text().strip().splitlines()
        assert lines == sorted(lines)

    def test_ip_blocklist_no_duplicates(self, tmp_path):
        """Duplicate IPs should appear only once."""
        entries = [
            {
                "ip": "1.2.3.4",
                "confidence": 80,
                "sources": ["threatfox"],
                "categories": ["c2"],
            },
            {
                "ip": "1.2.3.4",
                "confidence": 90,
                "sources": ["feodo"],
                "categories": ["malware"],
            },
        ]
        output_path = tmp_path / "ip_blocklist.txt"

        aggregate.write_ip_blocklist_txt(entries, output_path)

        lines = output_path.read_text().strip().splitlines()
        assert len(lines) == 1
        assert lines[0] == "1.2.3.4"

    def test_ip_blocklist_valid_ips_only(self, tmp_path):
        """All lines should be valid IPs or CIDRs."""
        entries = [
            {
                "ip": "1.2.3.4",
                "confidence": 80,
                "sources": ["threatfox"],
                "categories": ["c2"],
            },
            {
                "ip": "10.0.0.0/8",
                "confidence": 90,
                "sources": ["spamhaus_drop"],
                "categories": ["hijacked"],
            },
        ]
        output_path = tmp_path / "ip_blocklist.txt"

        aggregate.write_ip_blocklist_txt(entries, output_path)

        lines = output_path.read_text().strip().splitlines()
        for line in lines:
            assert aggregate.validate_ip(line.strip()), (
                f"Invalid IP in blocklist: {line}"
            )

    def test_ip_blocklist_empty_entries(self, tmp_path):
        """Empty entries should produce empty file."""
        output_path = tmp_path / "ip_blocklist.txt"

        aggregate.write_ip_blocklist_txt([], output_path)

        content = output_path.read_text()
        assert content.strip() == ""


# ---------------------------------------------------------------------------
# ja4_fingerprints.json schema tests
# ---------------------------------------------------------------------------


class TestJa4FingerprintsSchema:
    """Tests for ja4_fingerprints.json output schema."""

    def _make_ja4_entries(self, count: int = 3) -> List[Dict[str, Any]]:
        return [
            {
                "ja4": f"t13d1516h2_abc{i}_def{i}",
                "name": f"App {i}",
                "classification": "browser",
                "source": "ja4db",
                "notes": "",
            }
            for i in range(count)
        ]

    def test_write_ja4_fingerprints_json_creates_file(self, tmp_path):
        """write_ja4_fingerprints_json should create a valid JSON file."""
        entries = self._make_ja4_entries(2)
        output_path = tmp_path / "ja4_fingerprints.json"

        aggregate.write_ja4_fingerprints_json(entries, output_path)

        assert output_path.exists()

    def test_ja4_fingerprints_json_top_level_keys(self, tmp_path):
        """ja4_fingerprints.json should have all required top-level keys."""
        entries = self._make_ja4_entries(2)
        output_path = tmp_path / "ja4_fingerprints.json"

        aggregate.write_ja4_fingerprints_json(entries, output_path)

        with open(output_path) as f:
            data = json.load(f)

        assert REQUIRED_JA4_FINGERPRINTS_KEYS.issubset(data.keys())

    def test_ja4_fingerprints_json_entries_schema(self, tmp_path):
        """Each JA4 entry should have required fields."""
        entries = self._make_ja4_entries(3)
        output_path = tmp_path / "ja4_fingerprints.json"

        aggregate.write_ja4_fingerprints_json(entries, output_path)

        with open(output_path) as f:
            data = json.load(f)

        for entry in data["entries"]:
            assert REQUIRED_JA4_ENTRY_KEYS.issubset(entry.keys()), (
                f"JA4 entry missing keys: {REQUIRED_JA4_ENTRY_KEYS - set(entry.keys())}"
            )
            assert isinstance(entry["ja4"], str)
            assert len(entry["ja4"]) > 0
            assert isinstance(entry["name"], str)
            assert entry["classification"] in VALID_JA4_CLASSIFICATIONS
            assert isinstance(entry["source"], str)

    def test_ja4_fingerprints_json_version_field(self, tmp_path):
        """version field should be a non-empty string."""
        entries = self._make_ja4_entries(1)
        output_path = tmp_path / "ja4_fingerprints.json"

        aggregate.write_ja4_fingerprints_json(entries, output_path)

        with open(output_path) as f:
            data = json.load(f)

        assert isinstance(data["version"], str)
        assert len(data["version"]) > 0

    def test_ja4_fingerprints_json_is_valid_json(self, tmp_path):
        """Output file should be valid JSON."""
        entries = self._make_ja4_entries(5)
        output_path = tmp_path / "ja4_fingerprints.json"

        aggregate.write_ja4_fingerprints_json(entries, output_path)

        with open(output_path) as f:
            data = json.load(f)

        assert data is not None
        assert isinstance(data["entries"], list)


# ---------------------------------------------------------------------------
# stats.json schema tests
# ---------------------------------------------------------------------------


class TestStatsSchema:
    """Tests for stats.json output schema."""

    def test_write_stats_json_creates_file(self, tmp_path):
        """write_stats_json should create a valid JSON file."""
        output_path = tmp_path / "stats.json"

        aggregate.write_stats_json(1000, 50, ["threatfox", "feodo"], output_path)

        assert output_path.exists()

    def test_stats_json_top_level_keys(self, tmp_path):
        """stats.json should have all required top-level keys."""
        output_path = tmp_path / "stats.json"

        aggregate.write_stats_json(1000, 50, ["threatfox", "feodo"], output_path)

        with open(output_path) as f:
            data = json.load(f)

        assert REQUIRED_STATS_KEYS.issubset(data.keys())

    def test_stats_json_ip_count_is_int(self, tmp_path):
        """ip_count should be an integer."""
        output_path = tmp_path / "stats.json"

        aggregate.write_stats_json(1234, 56, ["threatfox"], output_path)

        with open(output_path) as f:
            data = json.load(f)

        assert isinstance(data["ip_count"], int)
        assert data["ip_count"] == 1234

    def test_stats_json_ja4_count_is_int(self, tmp_path):
        """ja4_count should be an integer."""
        output_path = tmp_path / "stats.json"

        aggregate.write_stats_json(100, 42, ["ja4db"], output_path)

        with open(output_path) as f:
            data = json.load(f)

        assert isinstance(data["ja4_count"], int)
        assert data["ja4_count"] == 42

    def test_stats_json_sources_sorted(self, tmp_path):
        """sources should be sorted alphabetically."""
        output_path = tmp_path / "stats.json"

        aggregate.write_stats_json(
            100, 10, ["threatfox", "feodo", "ipsum", "c2tracker"], output_path
        )

        with open(output_path) as f:
            data = json.load(f)

        assert data["sources"] == sorted(data["sources"])

    def test_stats_json_last_updated_format(self, tmp_path):
        """last_updated should be an ISO 8601 UTC timestamp."""
        output_path = tmp_path / "stats.json"

        aggregate.write_stats_json(100, 10, ["threatfox"], output_path)

        with open(output_path) as f:
            data = json.load(f)

        last_updated = data["last_updated"]
        assert isinstance(last_updated, str)
        assert "T" in last_updated
        assert last_updated.endswith("Z")

    def test_stats_json_is_valid_json(self, tmp_path):
        """Output file should be valid JSON."""
        output_path = tmp_path / "stats.json"

        aggregate.write_stats_json(500, 25, ["threatfox", "feodo"], output_path)

        with open(output_path) as f:
            data = json.load(f)

        assert data is not None


# ---------------------------------------------------------------------------
# Existing data files schema validation
# ---------------------------------------------------------------------------


class TestExistingDataFiles:
    """Validate that existing data files in data/ match expected schema."""

    DATA_DIR = Path(__file__).parent.parent / "data"

    def test_ip_reputation_json_exists(self):
        """data/ip_reputation.json should exist."""
        assert (self.DATA_DIR / "ip_reputation.json").exists(), (
            "data/ip_reputation.json not found"
        )

    def test_ip_reputation_json_schema(self):
        """data/ip_reputation.json should match expected schema."""
        path = self.DATA_DIR / "ip_reputation.json"
        if not path.exists():
            pytest.skip("data/ip_reputation.json not found")

        with open(path) as f:
            data = json.load(f)

        assert REQUIRED_IP_REPUTATION_KEYS.issubset(data.keys())
        assert isinstance(data["version"], str)
        assert isinstance(data["sources"], list)
        assert isinstance(data["entries"], list)

    def test_ip_reputation_json_entries_valid(self):
        """All entries in data/ip_reputation.json should pass validation."""
        path = self.DATA_DIR / "ip_reputation.json"
        if not path.exists():
            pytest.skip("data/ip_reputation.json not found")

        with open(path) as f:
            data = json.load(f)

        entries = data.get("entries", [])
        if not entries:
            pytest.skip("No entries in ip_reputation.json")

        # Sample first 100 entries for speed
        sample = entries[:100]
        invalid_count = 0
        for entry in sample:
            if not aggregate.validate_ip_entry(entry):
                invalid_count += 1

        invalid_ratio = invalid_count / len(sample)
        assert invalid_ratio <= aggregate.VALIDATION_THRESHOLD, (
            f"Too many invalid entries: {invalid_ratio:.1%} (threshold: {aggregate.VALIDATION_THRESHOLD:.1%})"
        )

    def test_ja4_fingerprints_json_exists(self):
        """data/ja4_fingerprints.json should exist."""
        assert (self.DATA_DIR / "ja4_fingerprints.json").exists(), (
            "data/ja4_fingerprints.json not found"
        )

    def test_ja4_fingerprints_json_schema(self):
        """data/ja4_fingerprints.json should match expected schema."""
        path = self.DATA_DIR / "ja4_fingerprints.json"
        if not path.exists():
            pytest.skip("data/ja4_fingerprints.json not found")

        with open(path) as f:
            data = json.load(f)

        assert REQUIRED_JA4_FINGERPRINTS_KEYS.issubset(data.keys())
        assert isinstance(data["version"], str)
        assert isinstance(data["entries"], list)

    def test_ja4_fingerprints_entries_valid(self):
        """All entries in data/ja4_fingerprints.json should pass validation."""
        path = self.DATA_DIR / "ja4_fingerprints.json"
        if not path.exists():
            pytest.skip("data/ja4_fingerprints.json not found")

        with open(path) as f:
            data = json.load(f)

        entries = data.get("entries", [])
        if not entries:
            pytest.skip("No entries in ja4_fingerprints.json")

        # Sample first 50 entries for speed
        sample = entries[:50]
        invalid_count = 0
        for entry in sample:
            if not aggregate.validate_ja4_entry(entry):
                invalid_count += 1

        invalid_ratio = invalid_count / len(sample)
        assert invalid_ratio <= aggregate.VALIDATION_THRESHOLD, (
            f"Too many invalid JA4 entries: {invalid_ratio:.1%}"
        )

    def test_stats_json_exists(self):
        """data/stats.json should exist."""
        assert (self.DATA_DIR / "stats.json").exists(), "data/stats.json not found"

    def test_stats_json_schema(self):
        """data/stats.json should match expected schema."""
        path = self.DATA_DIR / "stats.json"
        if not path.exists():
            pytest.skip("data/stats.json not found")

        with open(path) as f:
            data = json.load(f)

        assert REQUIRED_STATS_KEYS.issubset(data.keys())
        assert isinstance(data["ip_count"], int)
        assert isinstance(data["ja4_count"], int)
        assert isinstance(data["sources"], list)
        assert isinstance(data["last_updated"], str)

    def test_ip_blocklist_txt_exists(self):
        """data/ip_blocklist.txt should exist."""
        assert (self.DATA_DIR / "ip_blocklist.txt").exists(), (
            "data/ip_blocklist.txt not found"
        )

    def test_ip_blocklist_txt_format(self):
        """data/ip_blocklist.txt should have one IP per line."""
        path = self.DATA_DIR / "ip_blocklist.txt"
        if not path.exists():
            pytest.skip("data/ip_blocklist.txt not found")

        lines = path.read_text().strip().splitlines()
        if not lines:
            pytest.skip("ip_blocklist.txt is empty")

        # Sample first 50 lines
        sample = lines[:50]
        for line in sample:
            line = line.strip()
            if line:
                assert aggregate.validate_ip(line), f"Invalid IP in blocklist: {line}"

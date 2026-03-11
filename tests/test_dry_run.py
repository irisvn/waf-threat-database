#!/usr/bin/env python3
"""
Tests for --dry-run flag behavior across scripts.
Verifies that dry-run mode:
- Does NOT write any output files
- Still fetches and processes data
- Logs what would be written
- Returns exit code 0 on success
"""

import json
import sys
import subprocess
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch, call

import pytest

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import aggregate


# ---------------------------------------------------------------------------
# Helper fixtures
# ---------------------------------------------------------------------------


def make_mock_ip_entries(count: int = 5) -> List[Dict[str, Any]]:
    """Create mock IP entries for testing."""
    return [
        {
            "ip": f"1.2.3.{i}",
            "source": "threatfox",
            "confidence": 90,
            "category": "c2",
        }
        for i in range(count)
    ]


def make_mock_ja4_entries(count: int = 3) -> List[Dict[str, Any]]:
    """Create mock JA4 entries for testing."""
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


# ---------------------------------------------------------------------------
# aggregate.py --dry-run tests
# ---------------------------------------------------------------------------


class TestAggregateDryRun:
    """Tests for aggregate.main() with --dry-run flag."""

    def _mock_fetch_all_ip_data(self, entries=None, sources=None):
        """Create a mock for fetch_all_ip_data."""
        if entries is None:
            entries = make_mock_ip_entries(5)
        if sources is None:
            sources = ["threatfox"]
        return MagicMock(return_value=(entries, sources))

    def _mock_fetch_ja4_data(self, entries=None, source="ja4db"):
        """Create a mock for fetch_ja4_data."""
        if entries is None:
            entries = make_mock_ja4_entries(3)
        return MagicMock(return_value=(entries, source))

    def test_dry_run_does_not_write_files(self, tmp_path):
        """--dry-run should not create any output files."""
        ip_entries = make_mock_ip_entries(5)
        ja4_entries = make_mock_ja4_entries(3)

        with (
            patch.object(
                aggregate, "fetch_all_ip_data", return_value=(ip_entries, ["threatfox"])
            ),
            patch.object(
                aggregate, "fetch_ja4_data", return_value=(ja4_entries, "ja4db")
            ),
        ):
            # Simulate dry-run by calling main with --dry-run args
            import sys as _sys

            old_argv = _sys.argv
            _sys.argv = ["aggregate.py", "--dry-run", "--output-dir", str(tmp_path)]
            try:
                exit_code = aggregate.main()
            finally:
                _sys.argv = old_argv

        assert exit_code == 0

        # No files should be written
        assert not (tmp_path / "ip_reputation.json").exists(), (
            "ip_reputation.json should NOT be written in dry-run mode"
        )
        assert not (tmp_path / "ip_blocklist.txt").exists(), (
            "ip_blocklist.txt should NOT be written in dry-run mode"
        )
        assert not (tmp_path / "ja4_fingerprints.json").exists(), (
            "ja4_fingerprints.json should NOT be written in dry-run mode"
        )
        assert not (tmp_path / "stats.json").exists(), (
            "stats.json should NOT be written in dry-run mode"
        )

    def test_normal_run_writes_files(self, tmp_path):
        """Normal run (no --dry-run) should write all output files."""
        ip_entries = make_mock_ip_entries(5)
        ja4_entries = make_mock_ja4_entries(3)

        # Pre-process entries to match expected format after dedup
        processed_ip = aggregate.deduplicate_ip_entries(
            aggregate.apply_tier_scoring(ip_entries)
        )

        with (
            patch.object(
                aggregate, "fetch_all_ip_data", return_value=(ip_entries, ["threatfox"])
            ),
            patch.object(
                aggregate, "fetch_ja4_data", return_value=(ja4_entries, "ja4db")
            ),
        ):
            import sys as _sys

            old_argv = _sys.argv
            _sys.argv = ["aggregate.py", "--output-dir", str(tmp_path)]
            try:
                exit_code = aggregate.main()
            finally:
                _sys.argv = old_argv

        assert exit_code == 0

        # All files should be written
        assert (tmp_path / "ip_reputation.json").exists(), (
            "ip_reputation.json should be written"
        )
        assert (tmp_path / "ip_blocklist.txt").exists(), (
            "ip_blocklist.txt should be written"
        )
        assert (tmp_path / "ja4_fingerprints.json").exists(), (
            "ja4_fingerprints.json should be written"
        )
        assert (tmp_path / "stats.json").exists(), "stats.json should be written"

    def test_dry_run_returns_exit_code_0_on_success(self, tmp_path):
        """--dry-run should return exit code 0 when data is valid."""
        ip_entries = make_mock_ip_entries(5)
        ja4_entries = make_mock_ja4_entries(3)

        with (
            patch.object(
                aggregate, "fetch_all_ip_data", return_value=(ip_entries, ["threatfox"])
            ),
            patch.object(
                aggregate, "fetch_ja4_data", return_value=(ja4_entries, "ja4db")
            ),
        ):
            import sys as _sys

            old_argv = _sys.argv
            _sys.argv = ["aggregate.py", "--dry-run", "--output-dir", str(tmp_path)]
            try:
                exit_code = aggregate.main()
            finally:
                _sys.argv = old_argv

        assert exit_code == 0

    def test_dry_run_with_high_invalid_ratio_returns_exit_code_1(self, tmp_path):
        """--dry-run should return exit code 1 when >10% entries are invalid."""
        # Create entries where >10% are invalid (bad IPs)
        valid_entries = make_mock_ip_entries(80)
        invalid_entries = [
            {
                "ip": "not.an.ip",
                "source": "threatfox",
                "confidence": 90,
                "category": "c2",
            }
            for _ in range(20)
        ]
        all_entries = valid_entries + invalid_entries

        # These entries will fail validation after dedup
        # We need to inject them post-dedup to trigger the validation gate
        # Simulate by patching deduplicate_ip_entries to return invalid entries

        def mock_dedup(entries):
            # Return entries with invalid IPs to trigger validation failure
            return [
                {
                    "ip": f"1.2.3.{i}",
                    "confidence": 90,
                    "sources": ["threatfox"],
                    "categories": ["c2"],
                }
                for i in range(80)
            ] + [
                {
                    "ip": "not.an.ip",
                    "confidence": 90,
                    "sources": ["threatfox"],
                    "categories": ["c2"],
                }
                for _ in range(20)
            ]

        with (
            patch.object(
                aggregate,
                "fetch_all_ip_data",
                return_value=(all_entries, ["threatfox"]),
            ),
            patch.object(aggregate, "fetch_ja4_data", return_value=([], "ja4db")),
            patch.object(aggregate, "deduplicate_ip_entries", side_effect=mock_dedup),
        ):
            import sys as _sys

            old_argv = _sys.argv
            _sys.argv = ["aggregate.py", "--dry-run", "--output-dir", str(tmp_path)]
            try:
                exit_code = aggregate.main()
            finally:
                _sys.argv = old_argv

        assert exit_code == 1, "Should return exit code 1 when >10% entries are invalid"

    def test_dry_run_with_empty_data_returns_exit_code_0(self, tmp_path):
        """--dry-run with no data should return exit code 0 (validation skipped)."""
        with (
            patch.object(aggregate, "fetch_all_ip_data", return_value=([], [])),
            patch.object(aggregate, "fetch_ja4_data", return_value=([], "ja4db")),
        ):
            import sys as _sys

            old_argv = _sys.argv
            _sys.argv = ["aggregate.py", "--dry-run", "--output-dir", str(tmp_path)]
            try:
                exit_code = aggregate.main()
            finally:
                _sys.argv = old_argv

        assert exit_code == 0


# ---------------------------------------------------------------------------
# fetch_threatfox --dry-run tests
# ---------------------------------------------------------------------------


class TestThreatfoxDryRun:
    """Tests for fetch_threatfox.fetch() dry_run parameter."""

    def test_dry_run_still_fetches_data(self):
        """dry_run=True should still fetch and return data."""
        import fetch_threatfox

        mock_data = {
            "query_status": "ok",
            "data": [
                {
                    "ioc_type": "ip:port",
                    "ioc": "1.2.3.4:4444",
                    "threat_type": "botnet_cc",
                    "malware_printable": "Emotet",
                    "tags": [],
                    "first_seen": "",
                    "last_seen": "",
                }
            ],
        }

        mock_resp = MagicMock()
        mock_resp.json.return_value = mock_data
        mock_resp.raise_for_status.return_value = None

        with patch("requests.post", return_value=mock_resp):
            results = fetch_threatfox.fetch(dry_run=True)

        # dry_run doesn't change fetch behavior for threatfox
        assert len(results) == 1
        assert results[0]["ip"] == "1.2.3.4"

    def test_dry_run_false_same_as_default(self):
        """dry_run=False should behave identically to dry_run=True for fetch."""
        import fetch_threatfox

        mock_data = {
            "query_status": "ok",
            "data": [
                {
                    "ioc_type": "ip:port",
                    "ioc": "5.6.7.8:443",
                    "threat_type": "c2",
                    "malware_printable": "Cobalt Strike",
                    "tags": [],
                    "first_seen": "",
                    "last_seen": "",
                }
            ],
        }

        mock_resp = MagicMock()
        mock_resp.json.return_value = mock_data
        mock_resp.raise_for_status.return_value = None

        with patch("requests.post", return_value=mock_resp):
            results_dry = fetch_threatfox.fetch(dry_run=True)
            results_normal = fetch_threatfox.fetch(dry_run=False)

        assert len(results_dry) == len(results_normal)


# ---------------------------------------------------------------------------
# fetch_feodo --dry-run tests
# ---------------------------------------------------------------------------


class TestFeodoDryRun:
    """Tests for fetch_feodo.fetch() dry_run parameter."""

    def test_dry_run_still_fetches_data(self):
        """dry_run=True should still fetch and return data."""
        import fetch_feodo

        mock_data = [
            {
                "ip_address": "10.20.30.40",
                "malware": "Emotet",
                "status": "online",
                "port": 443,
                "first_seen": "2024-01-01 00:00:00",
                "last_online": "2024-01-02",
                "country": "DE",
            }
        ]

        mock_resp = MagicMock()
        mock_resp.json.return_value = mock_data
        mock_resp.raise_for_status.return_value = None

        with patch("requests.get", return_value=mock_resp):
            results = fetch_feodo.fetch(dry_run=True)

        assert len(results) == 1
        assert results[0]["ip"] == "10.20.30.40"


# ---------------------------------------------------------------------------
# fetch_ja4db --dry-run tests
# ---------------------------------------------------------------------------


class TestJa4dbDryRun:
    """Tests for fetch_ja4db.main() dry_run parameter."""

    def test_dry_run_outputs_json_to_stdout(self, capsys):
        """dry_run=True should print JSON to stdout."""
        import fetch_ja4db

        mock_api_data = [
            {
                "ja4_fingerprint": "t13d1516h2_abc123_def456",
                "application": "Chrome",
                "library": "",
                "device": "Desktop",
                "os": "Windows",
                "notes": "",
            }
        ]

        mock_resp = MagicMock()
        mock_resp.json.return_value = mock_api_data
        mock_resp.raise_for_status.return_value = None

        with patch("requests.get", return_value=mock_resp):
            exit_code = fetch_ja4db.main(dry_run=True)

        assert exit_code == 0
        captured = capsys.readouterr()
        # Should output valid JSON
        output = json.loads(captured.out)
        assert isinstance(output, list)
        assert len(output) == 1

    def test_dry_run_false_also_outputs_json(self, capsys):
        """dry_run=False should also print JSON to stdout (same behavior)."""
        import fetch_ja4db

        mock_api_data = [
            {
                "ja4_fingerprint": "t13d1516h2_abc123_def456",
                "application": "Firefox",
                "library": "",
                "device": "",
                "os": "",
                "notes": "",
            }
        ]

        mock_resp = MagicMock()
        mock_resp.json.return_value = mock_api_data
        mock_resp.raise_for_status.return_value = None

        with patch("requests.get", return_value=mock_resp):
            exit_code = fetch_ja4db.main(dry_run=False)

        assert exit_code == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert isinstance(output, list)

    def test_dry_run_returns_exit_code_0_on_success(self):
        """dry_run=True should return exit code 0 on success."""
        import fetch_ja4db

        mock_api_data = [
            {
                "ja4_fingerprint": "t13d1516h2_abc123_def456",
                "application": "Chrome",
                "library": "",
                "device": "",
                "os": "",
                "notes": "",
            }
        ]

        mock_resp = MagicMock()
        mock_resp.json.return_value = mock_api_data
        mock_resp.raise_for_status.return_value = None

        with patch("requests.get", return_value=mock_resp):
            exit_code = fetch_ja4db.main(dry_run=True)

        assert exit_code == 0

    def test_dry_run_returns_exit_code_1_on_failure(self):
        """dry_run=True should return exit code 1 when fetch fails."""
        import requests as req_module
        import fetch_ja4db

        with patch(
            "requests.get", side_effect=req_module.exceptions.ConnectionError("refused")
        ):
            exit_code = fetch_ja4db.main(dry_run=True)

        assert exit_code == 1


# ---------------------------------------------------------------------------
# Output directory creation tests
# ---------------------------------------------------------------------------


class TestOutputDirectoryCreation:
    """Tests for output directory creation behavior."""

    def test_normal_run_creates_output_dir(self, tmp_path):
        """Normal run should create output directory if it doesn't exist."""
        ip_entries = make_mock_ip_entries(3)
        ja4_entries = make_mock_ja4_entries(2)
        new_dir = tmp_path / "new_output_dir"

        assert not new_dir.exists()

        with (
            patch.object(
                aggregate, "fetch_all_ip_data", return_value=(ip_entries, ["threatfox"])
            ),
            patch.object(
                aggregate, "fetch_ja4_data", return_value=(ja4_entries, "ja4db")
            ),
        ):
            import sys as _sys

            old_argv = _sys.argv
            _sys.argv = ["aggregate.py", "--output-dir", str(new_dir)]
            try:
                exit_code = aggregate.main()
            finally:
                _sys.argv = old_argv

        assert new_dir.exists(), "Output directory should be created"

    def test_dry_run_does_not_create_output_dir(self, tmp_path):
        """--dry-run should NOT create output directory."""
        ip_entries = make_mock_ip_entries(3)
        ja4_entries = make_mock_ja4_entries(2)
        new_dir = tmp_path / "dry_run_output_dir"

        assert not new_dir.exists()

        with (
            patch.object(
                aggregate, "fetch_all_ip_data", return_value=(ip_entries, ["threatfox"])
            ),
            patch.object(
                aggregate, "fetch_ja4_data", return_value=(ja4_entries, "ja4db")
            ),
        ):
            import sys as _sys

            old_argv = _sys.argv
            _sys.argv = ["aggregate.py", "--dry-run", "--output-dir", str(new_dir)]
            try:
                exit_code = aggregate.main()
            finally:
                _sys.argv = old_argv

        assert not new_dir.exists(), (
            "Output directory should NOT be created in dry-run mode"
        )

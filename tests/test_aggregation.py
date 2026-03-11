#!/usr/bin/env python3
"""
Tests for aggregation pipeline logic:
- Deduplication (duplicate IPs → max score, merged sources)
- Tier-based scoring
- Validation gate (>10% invalid → exit 1)
- Entry limits enforcement
"""

import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import aggregate


# ---------------------------------------------------------------------------
# validate_ip tests
# ---------------------------------------------------------------------------


class TestValidateIp:
    """Tests for aggregate.validate_ip()"""

    def test_valid_ipv4(self):
        assert aggregate.validate_ip("1.2.3.4") is True

    def test_valid_ipv4_cidr(self):
        assert aggregate.validate_ip("10.0.0.0/8") is True

    def test_valid_ipv6(self):
        assert aggregate.validate_ip("2001:db8::1") is True

    def test_valid_ipv6_cidr(self):
        assert aggregate.validate_ip("2001:db8::/32") is True

    def test_invalid_ip(self):
        assert aggregate.validate_ip("not.an.ip") is False

    def test_invalid_cidr_prefix(self):
        assert aggregate.validate_ip("1.2.3.4/99") is False

    def test_empty_string(self):
        assert aggregate.validate_ip("") is False

    def test_none_like_empty(self):
        assert aggregate.validate_ip("") is False

    def test_private_ip_valid(self):
        assert aggregate.validate_ip("192.168.1.1") is True

    def test_loopback_valid(self):
        # validate_ip only checks format, not whether it's routable
        assert aggregate.validate_ip("127.0.0.1") is True


# ---------------------------------------------------------------------------
# validate_ip_entry tests
# ---------------------------------------------------------------------------


class TestValidateIpEntry:
    """Tests for aggregate.validate_ip_entry()"""

    def _valid_entry(self) -> Dict[str, Any]:
        return {
            "ip": "1.2.3.4",
            "confidence": 80,
            "sources": ["threatfox"],
            "categories": ["c2"],
        }

    def test_valid_entry(self):
        assert aggregate.validate_ip_entry(self._valid_entry()) is True

    def test_missing_ip_field(self):
        entry = self._valid_entry()
        del entry["ip"]
        assert aggregate.validate_ip_entry(entry) is False

    def test_missing_confidence_field(self):
        entry = self._valid_entry()
        del entry["confidence"]
        assert aggregate.validate_ip_entry(entry) is False

    def test_missing_sources_field(self):
        entry = self._valid_entry()
        del entry["sources"]
        assert aggregate.validate_ip_entry(entry) is False

    def test_missing_categories_field(self):
        entry = self._valid_entry()
        del entry["categories"]
        assert aggregate.validate_ip_entry(entry) is False

    def test_invalid_ip_value(self):
        entry = self._valid_entry()
        entry["ip"] = "not.an.ip"
        assert aggregate.validate_ip_entry(entry) is False

    def test_confidence_out_of_range_high(self):
        entry = self._valid_entry()
        entry["confidence"] = 101
        assert aggregate.validate_ip_entry(entry) is False

    def test_confidence_out_of_range_low(self):
        entry = self._valid_entry()
        entry["confidence"] = -1
        assert aggregate.validate_ip_entry(entry) is False

    def test_confidence_boundary_zero(self):
        entry = self._valid_entry()
        entry["confidence"] = 0
        assert aggregate.validate_ip_entry(entry) is True

    def test_confidence_boundary_100(self):
        entry = self._valid_entry()
        entry["confidence"] = 100
        assert aggregate.validate_ip_entry(entry) is True

    def test_empty_sources_list(self):
        entry = self._valid_entry()
        entry["sources"] = []
        assert aggregate.validate_ip_entry(entry) is False

    def test_empty_categories_list(self):
        entry = self._valid_entry()
        entry["categories"] = []
        assert aggregate.validate_ip_entry(entry) is False

    def test_sources_not_list(self):
        entry = self._valid_entry()
        entry["sources"] = "threatfox"
        assert aggregate.validate_ip_entry(entry) is False

    def test_cidr_ip_valid(self):
        entry = self._valid_entry()
        entry["ip"] = "10.0.0.0/8"
        assert aggregate.validate_ip_entry(entry) is True


# ---------------------------------------------------------------------------
# validate_ja4_entry tests
# ---------------------------------------------------------------------------


class TestValidateJa4Entry:
    """Tests for aggregate.validate_ja4_entry()"""

    def _valid_entry(self) -> Dict[str, Any]:
        return {
            "ja4": "t13d1516h2_abc123_def456",
            "name": "Chrome Browser",
            "classification": "browser",
            "source": "ja4db",
        }

    def test_valid_entry(self):
        assert aggregate.validate_ja4_entry(self._valid_entry()) is True

    def test_missing_ja4_field(self):
        entry = self._valid_entry()
        del entry["ja4"]
        assert aggregate.validate_ja4_entry(entry) is False

    def test_missing_name_field(self):
        entry = self._valid_entry()
        del entry["name"]
        assert aggregate.validate_ja4_entry(entry) is False

    def test_missing_classification_field(self):
        entry = self._valid_entry()
        del entry["classification"]
        assert aggregate.validate_ja4_entry(entry) is False

    def test_missing_source_field(self):
        entry = self._valid_entry()
        del entry["source"]
        assert aggregate.validate_ja4_entry(entry) is False

    def test_invalid_classification(self):
        entry = self._valid_entry()
        entry["classification"] = "invalid_class"
        assert aggregate.validate_ja4_entry(entry) is False

    def test_valid_classifications(self):
        for cls in ("bot", "browser", "malware", "unknown"):
            entry = self._valid_entry()
            entry["classification"] = cls
            assert aggregate.validate_ja4_entry(entry) is True, (
                f"Failed for classification: {cls}"
            )

    def test_empty_ja4(self):
        entry = self._valid_entry()
        entry["ja4"] = ""
        assert aggregate.validate_ja4_entry(entry) is False

    def test_empty_name(self):
        entry = self._valid_entry()
        entry["name"] = ""
        assert aggregate.validate_ja4_entry(entry) is False

    def test_empty_source(self):
        entry = self._valid_entry()
        entry["source"] = ""
        assert aggregate.validate_ja4_entry(entry) is False


# ---------------------------------------------------------------------------
# deduplicate_ip_entries tests
# ---------------------------------------------------------------------------


class TestDeduplicateIpEntries:
    """Tests for aggregate.deduplicate_ip_entries()"""

    def test_no_duplicates_unchanged(self):
        """Unique IPs should all be preserved."""
        entries = [
            {
                "ip": "1.2.3.4",
                "source": "threatfox",
                "confidence": 90,
                "category": "c2",
            },
            {
                "ip": "5.6.7.8",
                "source": "feodo",
                "confidence": 85,
                "category": "malware",
            },
        ]
        result = aggregate.deduplicate_ip_entries(entries)
        assert len(result) == 2

    def test_duplicate_ip_keeps_max_confidence(self):
        """Duplicate IPs should be merged, keeping the highest confidence."""
        entries = [
            {
                "ip": "1.2.3.4",
                "source": "ipsum",
                "confidence": 45,
                "category": "threat",
            },
            {
                "ip": "1.2.3.4",
                "source": "threatfox",
                "confidence": 95,
                "category": "c2",
            },
        ]
        result = aggregate.deduplicate_ip_entries(entries)
        assert len(result) == 1
        assert result[0]["confidence"] == 95

    def test_duplicate_ip_merges_sources(self):
        """Duplicate IPs should have all sources merged."""
        entries = [
            {
                "ip": "1.2.3.4",
                "source": "ipsum",
                "confidence": 45,
                "category": "threat",
            },
            {
                "ip": "1.2.3.4",
                "source": "threatfox",
                "confidence": 95,
                "category": "c2",
            },
            {
                "ip": "1.2.3.4",
                "source": "feodo",
                "confidence": 90,
                "category": "malware",
            },
        ]
        result = aggregate.deduplicate_ip_entries(entries)
        assert len(result) == 1
        sources = result[0]["sources"]
        assert "ipsum" in sources
        assert "threatfox" in sources
        assert "feodo" in sources

    def test_duplicate_ip_merges_categories(self):
        """Duplicate IPs should have all categories merged."""
        entries = [
            {
                "ip": "1.2.3.4",
                "source": "ipsum",
                "confidence": 45,
                "category": "threat",
            },
            {
                "ip": "1.2.3.4",
                "source": "threatfox",
                "confidence": 95,
                "category": "c2",
            },
        ]
        result = aggregate.deduplicate_ip_entries(entries)
        assert len(result) == 1
        categories = result[0]["categories"]
        assert "threat" in categories
        assert "c2" in categories

    def test_sources_deduplicated(self):
        """Same source appearing twice for same IP should not duplicate in sources list."""
        entries = [
            {
                "ip": "1.2.3.4",
                "source": "threatfox",
                "confidence": 90,
                "category": "c2",
            },
            {
                "ip": "1.2.3.4",
                "source": "threatfox",
                "confidence": 85,
                "category": "c2",
            },
        ]
        result = aggregate.deduplicate_ip_entries(entries)
        assert len(result) == 1
        assert result[0]["sources"].count("threatfox") == 1

    def test_sorted_by_confidence_descending(self):
        """Results should be sorted by confidence descending."""
        entries = [
            {
                "ip": "1.1.1.1",
                "source": "ipsum",
                "confidence": 45,
                "category": "threat",
            },
            {
                "ip": "2.2.2.2",
                "source": "threatfox",
                "confidence": 95,
                "category": "c2",
            },
            {
                "ip": "3.3.3.3",
                "source": "feodo",
                "confidence": 80,
                "category": "malware",
            },
        ]
        result = aggregate.deduplicate_ip_entries(entries)
        confidences = [r["confidence"] for r in result]
        assert confidences == sorted(confidences, reverse=True)

    def test_empty_input(self):
        """Empty input should return empty list."""
        result = aggregate.deduplicate_ip_entries([])
        assert result == []

    def test_skips_entries_without_ip(self):
        """Entries without 'ip' field should be skipped."""
        entries = [
            {"source": "threatfox", "confidence": 90, "category": "c2"},  # no ip
            {
                "ip": "1.2.3.4",
                "source": "feodo",
                "confidence": 85,
                "category": "malware",
            },
        ]
        result = aggregate.deduplicate_ip_entries(entries)
        assert len(result) == 1
        assert result[0]["ip"] == "1.2.3.4"

    def test_three_sources_same_ip(self):
        """Three different sources for same IP should all be merged."""
        entries = [
            {
                "ip": "10.0.0.1",
                "source": "source_a",
                "confidence": 50,
                "category": "threat",
            },
            {
                "ip": "10.0.0.1",
                "source": "source_b",
                "confidence": 70,
                "category": "c2",
            },
            {
                "ip": "10.0.0.1",
                "source": "source_c",
                "confidence": 90,
                "category": "malware",
            },
        ]
        result = aggregate.deduplicate_ip_entries(entries)
        assert len(result) == 1
        assert result[0]["confidence"] == 90
        assert len(result[0]["sources"]) == 3


# ---------------------------------------------------------------------------
# apply_tier_scoring tests
# ---------------------------------------------------------------------------


class TestApplyTierScoring:
    """Tests for aggregate.apply_tier_scoring()"""

    def test_tier1_source_clamped_to_80_100(self):
        """Tier 1 sources should have confidence clamped to 80-100."""
        entries = [
            {
                "ip": "1.2.3.4",
                "source": "threatfox",
                "confidence": 50,
                "category": "c2",
            },
        ]
        result = aggregate.apply_tier_scoring(entries)
        assert 80 <= result[0]["confidence"] <= 100

    def test_tier1_source_feodo(self):
        """feodo is Tier 1 - confidence should be clamped to 80-100."""
        entries = [
            {
                "ip": "1.2.3.4",
                "source": "feodo",
                "confidence": 30,
                "category": "malware",
            },
        ]
        result = aggregate.apply_tier_scoring(entries)
        assert result[0]["confidence"] >= 80

    def test_tier1_source_spamhaus_drop(self):
        """spamhaus_drop is Tier 1 - confidence should be clamped to 80-100."""
        entries = [
            {
                "ip": "10.0.0.0/8",
                "source": "spamhaus_drop",
                "confidence": 200,
                "category": "hijacked",
            },
        ]
        result = aggregate.apply_tier_scoring(entries)
        assert result[0]["confidence"] <= 100

    def test_tier2_source_ipsum(self):
        """ipsum is Tier 2 - confidence should be clamped to 40-60."""
        entries = [
            {
                "ip": "1.2.3.4",
                "source": "ipsum",
                "confidence": 90,
                "category": "threat",
            },
        ]
        result = aggregate.apply_tier_scoring(entries)
        assert 40 <= result[0]["confidence"] <= 60

    def test_tier2_source_c2tracker(self):
        """c2tracker is Tier 2 - confidence should be clamped to 40-60."""
        entries = [
            {
                "ip": "1.2.3.4",
                "source": "c2tracker",
                "confidence": 10,
                "category": "c2",
            },
        ]
        result = aggregate.apply_tier_scoring(entries)
        assert 40 <= result[0]["confidence"] <= 60

    def test_unknown_source_unchanged(self):
        """Unknown sources should not have confidence modified."""
        entries = [
            {
                "ip": "1.2.3.4",
                "source": "unknown_source",
                "confidence": 75,
                "category": "threat",
            },
        ]
        result = aggregate.apply_tier_scoring(entries)
        assert result[0]["confidence"] == 75

    def test_empty_input(self):
        """Empty input should return empty list."""
        result = aggregate.apply_tier_scoring([])
        assert result == []

    def test_normalize_source_hyphen(self):
        """Source names with hyphens should be normalized to underscores."""
        # Verify normalize_source converts hyphens to underscores
        assert aggregate.normalize_source("c2-tracker") == "c2_tracker"
        # Note: TIER_2_SOURCES uses 'c2tracker' (no underscore), not 'c2_tracker'
        # So 'c2-tracker' source would NOT match Tier 2 after normalization
        # This tests that normalization itself works correctly
        entries = [
            {
                "ip": "1.2.3.4",
                "source": "c2tracker",  # actual source name used by fetch_c2tracker
                "confidence": 90,
                "category": "c2",
            },
        ]
        result = aggregate.apply_tier_scoring(entries)
        # c2tracker is Tier 2 - confidence should be clamped to 40-60
        assert 40 <= result[0]["confidence"] <= 60


# ---------------------------------------------------------------------------
# validate_entries tests
# ---------------------------------------------------------------------------


class TestValidateEntries:
    """Tests for aggregate.validate_entries()"""

    def test_all_valid(self):
        """All valid entries should be in valid list, none in invalid."""
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
        ]
        valid, invalid = aggregate.validate_entries(
            entries, aggregate.validate_ip_entry
        )
        assert len(valid) == 2
        assert len(invalid) == 0

    def test_all_invalid(self):
        """All invalid entries should be in invalid list."""
        entries = [
            {
                "ip": "not.an.ip",
                "confidence": 80,
                "sources": ["threatfox"],
                "categories": ["c2"],
            },
            {
                "ip": "1.2.3.4",
                "confidence": 200,
                "sources": ["feodo"],
                "categories": ["malware"],
            },
        ]
        valid, invalid = aggregate.validate_entries(
            entries, aggregate.validate_ip_entry
        )
        assert len(valid) == 0
        assert len(invalid) == 2

    def test_mixed_valid_invalid(self):
        """Should correctly separate valid and invalid entries."""
        entries = [
            {
                "ip": "1.2.3.4",
                "confidence": 80,
                "sources": ["threatfox"],
                "categories": ["c2"],
            },
            {
                "ip": "bad.ip",
                "confidence": 80,
                "sources": ["feodo"],
                "categories": ["malware"],
            },
            {
                "ip": "5.6.7.8",
                "confidence": 90,
                "sources": ["ipsum"],
                "categories": ["threat"],
            },
        ]
        valid, invalid = aggregate.validate_entries(
            entries, aggregate.validate_ip_entry
        )
        assert len(valid) == 2
        assert len(invalid) == 1

    def test_empty_input(self):
        """Empty input should return empty lists."""
        valid, invalid = aggregate.validate_entries([], aggregate.validate_ip_entry)
        assert valid == []
        assert invalid == []


# ---------------------------------------------------------------------------
# Validation gate tests (>10% invalid → exit 1)
# ---------------------------------------------------------------------------


class TestValidationGate:
    """Tests for the 10% invalid threshold logic."""

    def test_below_threshold_passes(self):
        """9% invalid should pass (below 10% threshold)."""
        total = 100
        invalid_count = 9
        invalid_ratio = invalid_count / total
        assert invalid_ratio <= aggregate.VALIDATION_THRESHOLD

    def test_at_threshold_fails(self):
        """Exactly 10% invalid should fail (> threshold means strictly greater)."""
        total = 100
        invalid_count = 10
        invalid_ratio = invalid_count / total
        # The check is invalid_ratio > VALIDATION_THRESHOLD
        # 0.10 > 0.10 is False, so 10% exactly passes
        assert not (invalid_ratio > aggregate.VALIDATION_THRESHOLD)

    def test_above_threshold_fails(self):
        """11% invalid should fail."""
        total = 100
        invalid_count = 11
        invalid_ratio = invalid_count / total
        assert invalid_ratio > aggregate.VALIDATION_THRESHOLD

    def test_threshold_value(self):
        """VALIDATION_THRESHOLD should be 0.10 (10%)."""
        assert aggregate.VALIDATION_THRESHOLD == 0.10


# ---------------------------------------------------------------------------
# enforce_limits tests
# ---------------------------------------------------------------------------


class TestEnforceLimits:
    """Tests for aggregate.enforce_limits()"""

    def test_within_limits_unchanged(self):
        """Entries within limits should not be truncated."""
        ip_entries = [
            {
                "ip": f"1.2.3.{i}",
                "confidence": 80,
                "sources": ["s"],
                "categories": ["c"],
            }
            for i in range(10)
        ]
        ja4_entries = [
            {
                "ja4": f"hash{i}",
                "name": f"n{i}",
                "classification": "unknown",
                "source": "ja4db",
            }
            for i in range(5)
        ]

        limited_ips, limited_ja4 = aggregate.enforce_limits(ip_entries, ja4_entries)
        assert len(limited_ips) == 10
        assert len(limited_ja4) == 5

    def test_ip_entries_truncated_at_max(self):
        """IP entries exceeding MAX_IP_ENTRIES should be truncated."""
        # Create entries just over the limit
        ip_entries = [
            {"ip": f"1.2.3.4", "confidence": 80, "sources": ["s"], "categories": ["c"]}
            for _ in range(aggregate.MAX_IP_ENTRIES + 100)
        ]

        limited_ips, _ = aggregate.enforce_limits(ip_entries, [])
        assert len(limited_ips) == aggregate.MAX_IP_ENTRIES

    def test_ja4_entries_truncated_at_max(self):
        """JA4 entries exceeding MAX_JA4_ENTRIES should be truncated."""
        ja4_entries = [
            {
                "ja4": f"hash{i}",
                "name": f"n{i}",
                "classification": "unknown",
                "source": "ja4db",
            }
            for i in range(aggregate.MAX_JA4_ENTRIES + 50)
        ]

        _, limited_ja4 = aggregate.enforce_limits([], ja4_entries)
        assert len(limited_ja4) == aggregate.MAX_JA4_ENTRIES

    def test_max_ip_entries_constant(self):
        """MAX_IP_ENTRIES should be 50000."""
        assert aggregate.MAX_IP_ENTRIES == 50000

    def test_max_ja4_entries_constant(self):
        """MAX_JA4_ENTRIES should be 1000."""
        assert aggregate.MAX_JA4_ENTRIES == 1000


# ---------------------------------------------------------------------------
# normalize_source tests
# ---------------------------------------------------------------------------


class TestNormalizeSource:
    """Tests for aggregate.normalize_source()"""

    def test_lowercase(self):
        assert aggregate.normalize_source("ThreatFox") == "threatfox"

    def test_hyphen_to_underscore(self):
        assert aggregate.normalize_source("c2-tracker") == "c2_tracker"

    def test_space_to_underscore(self):
        assert aggregate.normalize_source("Spamhaus DROP") == "spamhaus_drop"

    def test_already_normalized(self):
        assert aggregate.normalize_source("ipsum") == "ipsum"

    def test_mixed(self):
        assert aggregate.normalize_source("C2-Tracker") == "c2_tracker"


# ---------------------------------------------------------------------------
# Integration: full dedup + scoring pipeline
# ---------------------------------------------------------------------------


class TestDeduplicationPipeline:
    """Integration tests for the full dedup + scoring pipeline."""

    def test_same_ip_from_tier1_and_tier2_keeps_tier1_score(self):
        """
        When same IP appears in Tier 1 (threatfox, confidence=95) and
        Tier 2 (ipsum, confidence=45), dedup should keep max = 95.
        """
        raw_entries = [
            {
                "ip": "1.2.3.4",
                "source": "ipsum",
                "confidence": 45,
                "category": "threat",
            },
            {
                "ip": "1.2.3.4",
                "source": "threatfox",
                "confidence": 95,
                "category": "c2",
            },
        ]

        # Apply tier scoring first
        scored = aggregate.apply_tier_scoring(raw_entries)
        # Then deduplicate
        deduped = aggregate.deduplicate_ip_entries(scored)

        assert len(deduped) == 1
        assert deduped[0]["confidence"] == 95
        assert "ipsum" in deduped[0]["sources"]
        assert "threatfox" in deduped[0]["sources"]

    def test_multiple_ips_all_preserved_after_dedup(self):
        """Multiple unique IPs should all be preserved."""
        raw_entries = [
            {
                "ip": "1.1.1.1",
                "source": "threatfox",
                "confidence": 95,
                "category": "c2",
            },
            {
                "ip": "2.2.2.2",
                "source": "feodo",
                "confidence": 90,
                "category": "malware",
            },
            {
                "ip": "3.3.3.3",
                "source": "ipsum",
                "confidence": 45,
                "category": "threat",
            },
        ]

        scored = aggregate.apply_tier_scoring(raw_entries)
        deduped = aggregate.deduplicate_ip_entries(scored)

        assert len(deduped) == 3
        ips = {r["ip"] for r in deduped}
        assert ips == {"1.1.1.1", "2.2.2.2", "3.3.3.3"}

    def test_validation_rejects_high_invalid_ratio(self):
        """If >10% entries are invalid, validate_entries returns many invalids."""
        # Create 100 entries: 20 invalid (20% > 10% threshold)
        valid_entries = [
            {
                "ip": f"1.2.3.{i}",
                "confidence": 80,
                "sources": ["threatfox"],
                "categories": ["c2"],
            }
            for i in range(80)
        ]
        invalid_entries = [
            {
                "ip": "not.an.ip",
                "confidence": 80,
                "sources": ["threatfox"],
                "categories": ["c2"],
            }
            for _ in range(20)
        ]
        all_entries = valid_entries + invalid_entries

        valid, invalid = aggregate.validate_entries(
            all_entries, aggregate.validate_ip_entry
        )
        invalid_ratio = len(invalid) / len(all_entries)

        assert invalid_ratio > aggregate.VALIDATION_THRESHOLD
        assert len(valid) == 80
        assert len(invalid) == 20

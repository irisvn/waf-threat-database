#!/usr/bin/env python3
"""
Tests for all fetch scripts using mock HTTP responses.
No external API calls are made.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))


# ---------------------------------------------------------------------------
# fetch_threatfox tests
# ---------------------------------------------------------------------------


class TestFetchThreatfox:
    """Tests for fetch_threatfox.fetch()"""

    def _make_response(self, data: dict) -> MagicMock:
        mock_resp = MagicMock()
        mock_resp.json.return_value = data
        mock_resp.raise_for_status.return_value = None
        return mock_resp

    def test_fetch_returns_ip_entries(self):
        """Should parse ip:port IOCs and return list of dicts."""
        import fetch_threatfox

        mock_data = {
            "query_status": "ok",
            "data": [
                {
                    "ioc_type": "ip:port",
                    "ioc": "1.2.3.4:4444",
                    "threat_type": "botnet_cc",
                    "malware_printable": "Emotet",
                    "tags": ["emotet"],
                    "first_seen": "2024-01-01 00:00:00",
                    "last_seen": "2024-01-02 00:00:00",
                },
                {
                    "ioc_type": "ip:port",
                    "ioc": "5.6.7.8:443",
                    "threat_type": "c2",
                    "malware_printable": "Cobalt Strike",
                    "tags": [],
                    "first_seen": "2024-01-01 00:00:00",
                    "last_seen": None,
                },
            ],
        }

        with patch("requests.post", return_value=self._make_response(mock_data)):
            results = fetch_threatfox.fetch()

        assert len(results) == 2
        assert results[0]["ip"] == "1.2.3.4"
        assert results[0]["source"] == "threatfox"
        assert results[0]["confidence"] >= 80
        assert results[0]["category"] in ("c2", "malware", "threat")

    def test_fetch_skips_non_ip_iocs(self):
        """Should skip domain and URL IOCs."""
        import fetch_threatfox

        mock_data = {
            "query_status": "ok",
            "data": [
                {
                    "ioc_type": "domain",
                    "ioc": "evil.example.com",
                    "threat_type": "c2",
                    "malware_printable": "Malware",
                    "tags": [],
                    "first_seen": "",
                    "last_seen": "",
                },
                {
                    "ioc_type": "ip:port",
                    "ioc": "9.10.11.12:80",
                    "threat_type": "botnet_cc",
                    "malware_printable": "TrickBot",
                    "tags": [],
                    "first_seen": "",
                    "last_seen": "",
                },
            ],
        }

        with patch("requests.post", return_value=self._make_response(mock_data)):
            results = fetch_threatfox.fetch()

        assert len(results) == 1
        assert results[0]["ip"] == "9.10.11.12"

    def test_fetch_returns_empty_on_no_results(self):
        """Should return empty list when API returns no_results."""
        import fetch_threatfox

        mock_data = {"query_status": "no_results"}

        with patch("requests.post", return_value=self._make_response(mock_data)):
            results = fetch_threatfox.fetch()

        assert results == []

    def test_fetch_returns_empty_on_api_error(self):
        """Should return empty list on API error status."""
        import fetch_threatfox

        mock_data = {"query_status": "error", "data": None}

        with patch("requests.post", return_value=self._make_response(mock_data)):
            results = fetch_threatfox.fetch()

        assert results == []

    def test_fetch_returns_empty_on_connection_error(self):
        """Should return empty list when all retries fail."""
        import requests as req_module
        import fetch_threatfox

        with patch(
            "requests.post",
            side_effect=req_module.exceptions.ConnectionError("refused"),
        ):
            results = fetch_threatfox.fetch()

        assert results == []

    def test_confidence_botnet_cc(self):
        """botnet_cc threat type should get confidence 95."""
        import fetch_threatfox

        assert fetch_threatfox._parse_confidence("botnet_cc", "") == 95

    def test_confidence_default(self):
        """Unknown threat type should get confidence 80."""
        import fetch_threatfox

        assert fetch_threatfox._parse_confidence("unknown_type", "") == 80

    def test_extract_ip_from_ip_port(self):
        """Should extract IP from 'ip:port' format."""
        import fetch_threatfox

        assert fetch_threatfox._extract_ip("1.2.3.4:4444") == "1.2.3.4"

    def test_extract_ip_plain(self):
        """Should return plain IP as-is."""
        import fetch_threatfox

        result = fetch_threatfox._extract_ip("192.168.1.1")
        assert result == "192.168.1.1"

    def test_parse_category_mapping(self):
        """Should map threat types to correct categories."""
        import fetch_threatfox

        assert fetch_threatfox._parse_category("botnet_cc") == "c2"
        assert fetch_threatfox._parse_category("payload_delivery") == "malware"
        assert fetch_threatfox._parse_category("unknown") == "threat"


# ---------------------------------------------------------------------------
# fetch_feodo tests
# ---------------------------------------------------------------------------


class TestFetchFeodo:
    """Tests for fetch_feodo.fetch()"""

    def _make_response(self, data) -> MagicMock:
        mock_resp = MagicMock()
        mock_resp.json.return_value = data
        mock_resp.raise_for_status.return_value = None
        return mock_resp

    def test_fetch_returns_ip_entries(self):
        """Should parse Feodo JSON blocklist and return entries."""
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
            },
            {
                "ip_address": "50.60.70.80",
                "malware": "QakBot",
                "status": "offline",
                "port": 8080,
                "first_seen": "2023-12-01 00:00:00",
                "last_online": "2024-01-01",
                "country": "US",
            },
        ]

        with patch("requests.get", return_value=self._make_response(mock_data)):
            results = fetch_feodo.fetch()

        assert len(results) == 2
        assert results[0]["ip"] == "10.20.30.40"
        assert results[0]["source"] == "feodo"
        assert results[0]["confidence"] >= 80
        assert "malware" in results[0]

    def test_fetch_skips_empty_ip(self):
        """Should skip entries with empty ip_address."""
        import fetch_feodo

        mock_data = [
            {"ip_address": "", "malware": "Emotet", "status": "online"},
            {"ip_address": "1.2.3.4", "malware": "TrickBot", "status": "online"},
        ]

        with patch("requests.get", return_value=self._make_response(mock_data)):
            results = fetch_feodo.fetch()

        assert len(results) == 1
        assert results[0]["ip"] == "1.2.3.4"

    def test_fetch_returns_empty_on_invalid_format(self):
        """Should return empty list when response is not a list."""
        import fetch_feodo

        mock_data = {"error": "invalid"}

        with patch("requests.get", return_value=self._make_response(mock_data)):
            results = fetch_feodo.fetch()

        assert results == []

    def test_confidence_online_status(self):
        """Online C2 should get confidence 95."""
        import fetch_feodo

        assert fetch_feodo._parse_confidence("Emotet", "online") == 95

    def test_confidence_high_confidence_malware(self):
        """Known high-confidence malware should get confidence 90."""
        import fetch_feodo

        assert fetch_feodo._parse_confidence("TrickBot", "offline") == 90

    def test_confidence_default(self):
        """Unknown malware offline should get confidence 80."""
        import fetch_feodo

        assert fetch_feodo._parse_confidence("UnknownMalware", "offline") == 80

    def test_parse_category_c2_family(self):
        """Known C2 families should map to 'c2' category."""
        import fetch_feodo

        assert fetch_feodo._parse_category("Emotet") == "c2"
        assert fetch_feodo._parse_category("Cobalt Strike") == "c2"

    def test_parse_category_default(self):
        """Unknown malware should map to 'malware' category."""
        import fetch_feodo

        assert fetch_feodo._parse_category("UnknownMalware") == "malware"


# ---------------------------------------------------------------------------
# fetch_spamhaus tests
# ---------------------------------------------------------------------------


class TestFetchSpamhaus:
    """Tests for fetch_spamhaus.fetch()"""

    def _make_text_response(self, text: str) -> MagicMock:
        mock_resp = MagicMock()
        mock_resp.text = text
        mock_resp.raise_for_status.return_value = None
        return mock_resp

    def test_fetch_returns_cidr_entries(self):
        """Should parse DROP/EDROP lists and return CIDR entries."""
        import fetch_spamhaus

        drop_text = (
            "; Spamhaus DROP List\n1.10.16.0/20 ; SBL256894\n2.56.0.0/14 ; SBL303905\n"
        )
        edrop_text = "; Spamhaus EDROP List\n5.8.0.0/21 ; SBL123456\n"

        with patch("requests.get") as mock_get:
            mock_get.side_effect = [
                self._make_text_response(drop_text),
                self._make_text_response(edrop_text),
            ]
            results = fetch_spamhaus.fetch()

        assert len(results) == 3
        ips = [r["ip"] for r in results]
        assert "1.10.16.0/20" in ips
        assert "2.56.0.0/14" in ips
        assert "5.8.0.0/21" in ips

    def test_fetch_source_names(self):
        """DROP entries should have source 'spamhaus_drop', EDROP 'spamhaus_edrop'."""
        import fetch_spamhaus

        drop_text = "1.10.16.0/20 ; SBL256894\n"
        edrop_text = "5.8.0.0/21 ; SBL123456\n"

        with patch("requests.get") as mock_get:
            mock_get.side_effect = [
                self._make_text_response(drop_text),
                self._make_text_response(edrop_text),
            ]
            results = fetch_spamhaus.fetch()

        sources = {r["source"] for r in results}
        assert "spamhaus_drop" in sources
        assert "spamhaus_edrop" in sources

    def test_parse_drop_line_valid(self):
        """Should parse valid CIDR line."""
        import fetch_spamhaus

        result = fetch_spamhaus._parse_drop_line("1.10.16.0/20 ; SBL256894")
        assert result is not None
        assert result["cidr"] == "1.10.16.0/20"
        assert result["sbl_ref"] == "SBL256894"

    def test_parse_drop_line_comment(self):
        """Should return None for comment lines."""
        import fetch_spamhaus

        assert fetch_spamhaus._parse_drop_line("; This is a comment") is None

    def test_parse_drop_line_empty(self):
        """Should return None for empty lines."""
        import fetch_spamhaus

        assert fetch_spamhaus._parse_drop_line("") is None

    def test_parse_drop_line_invalid_cidr(self):
        """Should return None for invalid CIDR."""
        import fetch_spamhaus

        assert fetch_spamhaus._parse_drop_line("not.a.valid.cidr/99 ; SBL000") is None

    def test_confidence_values(self):
        """DROP should have confidence 90, EDROP 85."""
        import fetch_spamhaus

        drop_text = "1.10.16.0/20 ; SBL256894\n"
        edrop_text = "5.8.0.0/21 ; SBL123456\n"

        with patch("requests.get") as mock_get:
            mock_get.side_effect = [
                self._make_text_response(drop_text),
                self._make_text_response(edrop_text),
            ]
            results = fetch_spamhaus.fetch()

        drop_entry = next(r for r in results if r["source"] == "spamhaus_drop")
        edrop_entry = next(r for r in results if r["source"] == "spamhaus_edrop")
        assert drop_entry["confidence"] == 90
        assert edrop_entry["confidence"] == 85


# ---------------------------------------------------------------------------
# fetch_ipsum tests
# ---------------------------------------------------------------------------


class TestFetchIpsum:
    """Tests for fetch_ipsum.fetch()"""

    def _make_text_response(self, text: str) -> MagicMock:
        mock_resp = MagicMock()
        mock_resp.text = text
        mock_resp.raise_for_status.return_value = None
        return mock_resp

    def test_fetch_returns_entries_above_min_count(self):
        """Should only return IPs with blacklist_count >= MIN_BLACKLIST_COUNT (2)."""
        import fetch_ipsum

        ipsum_text = (
            "# ipsum feed\n"
            "1.2.3.4\t1\n"  # below threshold - skip
            "5.6.7.8\t2\n"  # at threshold - include
            "9.10.11.12\t5\n"  # above threshold - include
        )

        with patch("requests.get", return_value=self._make_text_response(ipsum_text)):
            results = fetch_ipsum.fetch()

        ips = [r["ip"] for r in results]
        assert "1.2.3.4" not in ips
        assert "5.6.7.8" in ips
        assert "9.10.11.12" in ips

    def test_fetch_source_is_ipsum(self):
        """All entries should have source 'ipsum'."""
        import fetch_ipsum

        ipsum_text = "5.6.7.8\t3\n"

        with patch("requests.get", return_value=self._make_text_response(ipsum_text)):
            results = fetch_ipsum.fetch()

        assert all(r["source"] == "ipsum" for r in results)

    def test_score_to_confidence_mapping(self):
        """Should map blacklist counts to correct confidence tiers."""
        import fetch_ipsum

        assert fetch_ipsum._score_to_confidence(1) == 40
        assert fetch_ipsum._score_to_confidence(2) == 45
        assert fetch_ipsum._score_to_confidence(4) == 50
        assert fetch_ipsum._score_to_confidence(6) == 55
        assert fetch_ipsum._score_to_confidence(8) == 60
        assert fetch_ipsum._score_to_confidence(10) == 60

    def test_parse_ipsum_line_valid(self):
        """Should parse valid IP\tcount line."""
        import fetch_ipsum

        result = fetch_ipsum._parse_ipsum_line("1.2.3.4\t5")
        assert result is not None
        assert result["ip"] == "1.2.3.4"
        assert result["blacklist_count"] == 5

    def test_parse_ipsum_line_comment(self):
        """Should return None for comment lines."""
        import fetch_ipsum

        assert fetch_ipsum._parse_ipsum_line("# comment") is None

    def test_parse_ipsum_line_empty(self):
        """Should return None for empty lines."""
        import fetch_ipsum

        assert fetch_ipsum._parse_ipsum_line("") is None

    def test_confidence_tier2_range(self):
        """All ipsum confidence scores should be in Tier 2 range (40-60)."""
        import fetch_ipsum

        ipsum_text = "\n".join(f"10.0.0.{i}\t{i}" for i in range(1, 12))

        with patch("requests.get", return_value=self._make_text_response(ipsum_text)):
            results = fetch_ipsum.fetch()

        for r in results:
            assert 40 <= r["confidence"] <= 60, (
                f"Confidence {r['confidence']} out of Tier 2 range"
            )


# ---------------------------------------------------------------------------
# fetch_c2tracker tests
# ---------------------------------------------------------------------------


class TestFetchC2Tracker:
    """Tests for fetch_c2tracker.fetch()"""

    def _make_text_response(self, text: str) -> MagicMock:
        mock_resp = MagicMock()
        mock_resp.text = text
        mock_resp.raise_for_status.return_value = None
        return mock_resp

    def test_fetch_returns_c2_entries(self):
        """Should return entries with source 'c2tracker' and category 'c2'."""
        import fetch_c2tracker

        family_text = "1.2.3.4\n5.6.7.8\n"
        all_text = "1.2.3.4\n9.10.11.12\n"

        with patch("requests.get", return_value=self._make_text_response(family_text)):
            # All calls return same text for simplicity
            results = fetch_c2tracker.fetch()

        assert all(r["source"] == "c2tracker" for r in results)
        assert all(r["category"] == "c2" for r in results)

    def test_fetch_deduplicates_ips(self):
        """Same IP from multiple family lists should appear only once."""
        import fetch_c2tracker

        # Patch _fetch_text_list to return controlled data
        call_count = [0]
        family_keys = list(fetch_c2tracker.C2TRACKER_FAMILY_URLS.keys())

        def mock_fetch_text(url, label):
            call_count[0] += 1
            if "all" in label.lower():
                return ["1.2.3.4", "5.6.7.8"]
            # First family returns 1.2.3.4, rest return empty
            if call_count[0] == 1:
                return ["1.2.3.4"]
            return []

        with patch.object(
            fetch_c2tracker, "_fetch_text_list", side_effect=mock_fetch_text
        ):
            results = fetch_c2tracker.fetch()

        ips = [r["ip"] for r in results]
        # 1.2.3.4 should appear only once
        assert ips.count("1.2.3.4") == 1

    def test_known_family_gets_higher_confidence(self):
        """IPs with known family attribution should get confidence 55."""
        import fetch_c2tracker

        def mock_fetch_text(url, label):
            if "cobalt_strike" in label.lower():
                return ["1.2.3.4"]
            if "all" in label.lower():
                return []
            return []

        with patch.object(
            fetch_c2tracker, "_fetch_text_list", side_effect=mock_fetch_text
        ):
            results = fetch_c2tracker.fetch()

        cobalt_entry = next((r for r in results if r["ip"] == "1.2.3.4"), None)
        assert cobalt_entry is not None
        assert cobalt_entry["confidence"] == 55
        assert cobalt_entry["malware_family"] == "cobalt_strike"

    def test_unknown_family_gets_lower_confidence(self):
        """IPs only in all.txt (no family) should get confidence 45."""
        import fetch_c2tracker

        def mock_fetch_text(url, label):
            if "all" in label.lower():
                return ["9.9.9.9"]
            return []

        with patch.object(
            fetch_c2tracker, "_fetch_text_list", side_effect=mock_fetch_text
        ):
            results = fetch_c2tracker.fetch()

        unknown_entry = next((r for r in results if r["ip"] == "9.9.9.9"), None)
        assert unknown_entry is not None
        assert unknown_entry["confidence"] == 45
        assert unknown_entry["malware_family"] == "unknown"

    def test_fetch_text_list_skips_comments(self):
        """_fetch_text_list should skip comment lines."""
        import fetch_c2tracker

        text = "# comment\n1.2.3.4\n# another comment\n5.6.7.8\n"
        mock_resp = MagicMock()
        mock_resp.text = text
        mock_resp.raise_for_status.return_value = None

        with patch("requests.get", return_value=mock_resp):
            ips = fetch_c2tracker._fetch_text_list("http://example.com", "test")

        assert "1.2.3.4" in ips
        assert "5.6.7.8" in ips
        assert "# comment" not in ips


# ---------------------------------------------------------------------------
# fetch_ja4db tests
# ---------------------------------------------------------------------------


class TestFetchJa4db:
    """Tests for fetch_ja4db functions."""

    def _make_response(self, data) -> MagicMock:
        mock_resp = MagicMock()
        mock_resp.json.return_value = data
        mock_resp.raise_for_status.return_value = None
        return mock_resp

    def test_parse_ja4_entries_browser(self):
        """Should classify Chrome as 'browser'."""
        import fetch_ja4db

        raw_data = [
            {
                "ja4_fingerprint": "t13d1516h2_abc123_def456",
                "application": "Chrome",
                "library": "",
                "device": "Desktop",
                "os": "Windows",
                "notes": "",
            }
        ]

        entries = fetch_ja4db.parse_ja4_entries(raw_data)
        assert len(entries) == 1
        assert entries[0].classification == "browser"
        assert entries[0].source == "ja4db"

    def test_parse_ja4_entries_bot(self):
        """Should classify bot/crawler as 'bot'."""
        import fetch_ja4db

        raw_data = [
            {
                "ja4_fingerprint": "t13d1516h2_bot123_def456",
                "application": "Googlebot",
                "library": "",
                "device": "",
                "os": "",
                "notes": "",
            }
        ]

        entries = fetch_ja4db.parse_ja4_entries(raw_data)
        assert len(entries) == 1
        assert entries[0].classification == "bot"

    def test_parse_ja4_entries_malware(self):
        """Should classify malware as 'malware'."""
        import fetch_ja4db

        raw_data = [
            {
                "ja4_fingerprint": "t13d1516h2_mal123_def456",
                "application": "IcedID malware",
                "library": "",
                "device": "",
                "os": "",
                "notes": "",
            }
        ]

        entries = fetch_ja4db.parse_ja4_entries(raw_data)
        assert len(entries) == 1
        assert entries[0].classification == "malware"

    def test_parse_ja4_entries_skips_missing_fingerprint(self):
        """Should skip entries without ja4_fingerprint."""
        import fetch_ja4db

        raw_data = [
            {
                "ja4_fingerprint": "",
                "application": "Unknown",
                "library": "",
                "device": "",
                "os": "",
                "notes": "",
            }
        ]

        entries = fetch_ja4db.parse_ja4_entries(raw_data)
        assert len(entries) == 0

    def test_merge_entries_custom_overrides_api(self):
        """Custom entries should override API entries with same ja4."""
        import fetch_ja4db

        api_entry = fetch_ja4db.JA4Entry(
            ja4="t13d1516h2_abc123_def456",
            name="API Name",
            classification="unknown",
            source="ja4db",
            notes="",
        )
        custom_entry = fetch_ja4db.JA4Entry(
            ja4="t13d1516h2_abc123_def456",
            name="Custom Name",
            classification="malware",
            source="custom",
            notes="custom note",
        )

        merged = fetch_ja4db.merge_entries([api_entry], [custom_entry])
        assert len(merged) == 1
        assert merged[0].name == "Custom Name"
        assert merged[0].classification == "malware"

    def test_fetch_ja4db_api_success(self):
        """Should return parsed data on successful API call."""
        import fetch_ja4db

        mock_data = [
            {
                "ja4_fingerprint": "t13d1516h2_abc123_def456",
                "application": "Chrome",
                "library": "",
                "device": "",
                "os": "",
                "notes": "",
            }
        ]

        with patch("requests.get", return_value=self._make_response(mock_data)):
            result = fetch_ja4db.fetch_ja4db_api()

        assert result == mock_data

    def test_fetch_ja4db_api_retries_on_timeout(self):
        """Should retry on timeout and eventually raise."""
        import requests as req_module
        import fetch_ja4db

        with patch("requests.get", side_effect=req_module.exceptions.Timeout()):
            with pytest.raises(Exception, match="Failed to fetch JA4DB"):
                fetch_ja4db.fetch_ja4db_api(max_retries=2)

    def test_load_custom_entries_missing_file(self, tmp_path):
        """Should return empty list when custom file doesn't exist."""
        import fetch_ja4db

        missing_path = tmp_path / "nonexistent.json"
        entries = fetch_ja4db.load_custom_entries(custom_path=missing_path)
        assert entries == []

    def test_load_custom_entries_valid_file(self, tmp_path):
        """Should load and parse custom entries from JSON file."""
        import fetch_ja4db

        custom_data = [
            {
                "ja4_fingerprint": "t13d1516h2_custom_abc123",
                "application": "CustomApp",
                "library": "",
                "device": "",
                "os": "",
                "notes": "custom entry",
            }
        ]
        custom_file = tmp_path / "custom_ja4.json"
        custom_file.write_text(json.dumps(custom_data))

        entries = fetch_ja4db.load_custom_entries(custom_path=custom_file)
        assert len(entries) == 1
        assert entries[0].ja4 == "t13d1516h2_custom_abc123"

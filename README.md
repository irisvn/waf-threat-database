# waf-threat-database

A centralized threat intelligence database aggregating malicious IPs, domains, and C2 infrastructure from multiple authoritative sources. Designed for Web Application Firewall (WAF) rule generation and threat detection.

## Purpose

This repository provides automated collection and aggregation of threat intelligence data from public sources, enabling security teams to maintain up-to-date threat feeds for WAF configuration and threat detection systems.

## Data Sources

The database aggregates threat intelligence from the following sources:

1. **ThreatFox** - Malware C2 infrastructure tracking
2. **Feodo Tracker** - Botnet C2 and malware tracking
3. **Spamhaus DROP** - Hijacked IP ranges and malware sources
4. **ipsum** - Threat intelligence aggregation platform
5. **C2-Tracker** - Command and control server tracking
6. **JA4DB** - TLS fingerprinting database for malicious traffic

## Output Formats

Data is exported in two formats:

- **JSON** (`data/*.json`) - Structured format with metadata, timestamps, and source attribution
- **Plain Text** (`data/*.txt`) - Simple newline-delimited format for direct WAF rule ingestion

## Update Cadence

Threat data is automatically fetched and aggregated **daily at 2:00 AM UTC**.

## Directory Structure

```
waf-threat-database/
├── scripts/          # Python fetch and aggregation scripts
├── data/             # Output files (JSON and plain text)
├── tests/            # Unit and integration tests
├── .github/workflows/ # GitHub Actions CI/CD pipelines
├── requirements.txt  # Python dependencies
├── README.md         # This file
└── .gitignore        # Git ignore rules
```

## How to Consume

### Direct Download
Download the latest threat data files from the `data/` directory:
- `data/malicious-ips.json` - Structured IP threat data
- `data/malicious-ips.txt` - Plain text IP list
- `data/malicious-domains.json` - Structured domain threat data
- `data/malicious-domains.txt` - Plain text domain list

### Integration
Import the JSON files into your WAF configuration system or use the plain text files for direct rule generation.

### Programmatic Access
Clone this repository and use the aggregation scripts to fetch fresh data:

```bash
pip install -r requirements.txt
python scripts/fetch_threats.py
```

## Contributing

Contributions are welcome. Please ensure all changes include appropriate tests and documentation.

## License

This project is licensed under the MIT License.

"""Shared ETL configuration: paths and settings read from the repo-root .env.

Every loader imports from here, so paths and connection settings live in one
place. Nothing secret is hard-coded: values come from environment variables
(loaded from <repo>/.env if it exists).
"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(REPO_ROOT / ".env")

# Downloaded source files (gitignored). Contract: loaders use config.RAW_DIR.
RAW_DIR = Path(os.getenv("TL_RAW_DIR", REPO_ROOT / "data" / "raw"))

MYSQL_HOST = os.getenv("MYSQL_HOST", "127.0.0.1")
MYSQL_PORT = int(os.getenv("MYSQL_PORT", "3307"))
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "threatlattice")
# The ETL creates and replaces data, so it uses root. The web app never does.
MYSQL_USER = os.getenv("ETL_MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("ETL_MYSQL_PASSWORD", os.getenv("MYSQL_ROOT_PASSWORD", ""))

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://127.0.0.1:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "")

# NVD yearly feeds to download/load by default.
NVD_YEARS = [int(y) for y in os.getenv("TL_NVD_YEARS", "2024,2025,2026").split(",")]

# Source files: name in RAW_DIR -> official download URL.
SOURCES: dict[str, str] = {
    "cwec_latest.xml.zip": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
    "capec_latest.xml": "https://capec.mitre.org/data/xml/capec_latest.xml",
    "enterprise-attack.json": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "known_exploited_vulnerabilities.json": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    **{
        f"nvdcve-2.0-{y}.json.gz": f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{y}.json.gz"
        for y in NVD_YEARS
    },
}

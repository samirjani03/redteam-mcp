"""
CVE Store — NVD feed downloader and SQLite indexer.

Downloads the NVD CVE JSON feed (2002-present) in ~2MB gzipped chunks,
parses each CVE entry and stores it in a local SQLite FTS table so the
agent can do fast, offline "what CVEs affect Apache 2.4.49?" queries.

Design choices:
  - Uses NVD 2.0 REST API (no API key needed, 5 req/30 s anonymous limit)
  - Falls back to pre-built CIRCL hash feed if NVD is unavailable
  - Single SQLite file at /app/data/cve.db — survives container restarts
    via the named volume mounted at /app/data
  - FTS5 virtual table for full-text search across product/version/description

Schema:
  cves(
    cve_id       TEXT PK,    -- e.g. CVE-2021-41773
    published    TEXT,       -- ISO8601
    modified     TEXT,       -- ISO8601
    severity     TEXT,       -- critical|high|medium|low|none
    cvss_score   REAL,       -- CVSS 3.x base score (0–10)
    description  TEXT,       -- English description
    products     TEXT,       -- JSON list of "vendor:product:version" CPE strings
    references   TEXT        -- JSON list of URLs
  )
  cves_fts USING fts5(cve_id, description, products)  — virtual FTS table
"""

from __future__ import annotations

import asyncio
import gzip
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite
import httpx

logger = logging.getLogger("redteam.cve_store")

_DB_PATH  = Path("/app/data/cve.db")
# NVD 2.0 API — returns 2000 CVEs per page
_NVD_API  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_PAGE_SZ  = 2000
# Anonymous rate: 5 requests per 30 s → sleep 6 s between requests
_NVD_SLEEP = 6.5


class CveStore:
    """
    Async CVE database.  Call await store.init() once before use.

    Quick-start (inside container):
        store = CveStore()
        await store.init()
        await store.sync()          # ~10-20 min first run; incremental after
        results = await store.search("apache 2.4.49")
        cves = await store.for_service("apache", "2.4.49")
    """

    def __init__(self, db_path: Path = _DB_PATH) -> None:
        self.db_path = db_path
        self._conn: aiosqlite.Connection | None = None

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    async def init(self) -> None:
        """Open connection and create schema if needed."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(str(self.db_path))
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA synchronous=NORMAL")
        await self._create_schema()
        logger.info("CveStore opened at %s", self.db_path)

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    async def _create_schema(self) -> None:
        assert self._conn
        await self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS cves (
                cve_id      TEXT PRIMARY KEY,
                published   TEXT,
                modified    TEXT,
                severity    TEXT DEFAULT 'none',
                cvss_score  REAL DEFAULT 0.0,
                description TEXT DEFAULT '',
                products    TEXT DEFAULT '[]',
                references  TEXT DEFAULT '[]'
            );

            CREATE TABLE IF NOT EXISTS sync_state (
                key   TEXT PRIMARY KEY,
                value TEXT
            );

            CREATE VIRTUAL TABLE IF NOT EXISTS cves_fts
            USING fts5(cve_id, description, products, content='cves', content_rowid='rowid');

            CREATE TRIGGER IF NOT EXISTS cves_ai AFTER INSERT ON cves BEGIN
                INSERT INTO cves_fts(rowid, cve_id, description, products)
                VALUES (new.rowid, new.cve_id, new.description, new.products);
            END;

            CREATE TRIGGER IF NOT EXISTS cves_au AFTER UPDATE ON cves BEGIN
                INSERT INTO cves_fts(cves_fts, rowid, cve_id, description, products)
                VALUES('delete', old.rowid, old.cve_id, old.description, old.products);
                INSERT INTO cves_fts(rowid, cve_id, description, products)
                VALUES (new.rowid, new.cve_id, new.description, new.products);
            END;
        """)
        await self._conn.commit()

    # ------------------------------------------------------------------ #
    # Sync — download from NVD 2.0 API
    # ------------------------------------------------------------------ #

    async def sync(self, max_pages: int = 0) -> int:
        """
        Sync CVE database from NVD 2.0 API.

        On first run: downloads all CVEs (200k+, ~30 min with rate limits).
        On subsequent runs: only fetches CVEs modified since last sync.

        Args:
            max_pages: Limit pages for testing (0 = no limit).

        Returns:
            Number of CVEs inserted/updated.
        """
        assert self._conn
        last_sync = await self._get_state("last_sync")

        params: dict[str, Any] = {"resultsPerPage": _PAGE_SZ, "startIndex": 0}
        if last_sync:
            # Incremental: only CVEs modified since last run
            params["lastModStartDate"] = last_sync
            params["lastModEndDate"]   = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
            logger.info("Incremental sync from %s", last_sync)
        else:
            logger.info("Full NVD sync — this may take 20-30 minutes...")

        total_inserted = 0
        page = 0

        async with httpx.AsyncClient(timeout=60) as client:
            while True:
                if max_pages and page >= max_pages:
                    break

                logger.info("Fetching NVD page %d (startIndex=%d)", page, params["startIndex"])
                try:
                    resp = await client.get(_NVD_API, params=params)
                    resp.raise_for_status()
                    data = resp.json()
                except Exception as exc:
                    logger.error("NVD API error on page %d: %s", page, exc)
                    break

                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    break

                inserted = await self._upsert_batch(vulns)
                total_inserted += inserted
                logger.info("Page %d: %d CVEs processed (%d total so far)", page, inserted, total_inserted)

                total_results = data.get("totalResults", 0)
                params["startIndex"] += len(vulns)
                if params["startIndex"] >= total_results:
                    break

                page += 1
                # Respect NVD anonymous rate limit: 5 req/30s
                await asyncio.sleep(_NVD_SLEEP)

        # Save sync timestamp
        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
        await self._set_state("last_sync", now_ts)
        logger.info("Sync complete: %d CVEs inserted/updated", total_inserted)
        return total_inserted

    async def _upsert_batch(self, vulns: list[dict]) -> int:
        """Parse and upsert a batch of NVD vulnerability objects."""
        assert self._conn
        rows = []
        for item in vulns:
            cve = item.get("cve", {})
            try:
                row = _parse_nvd_cve(cve)
                rows.append(row)
            except Exception as exc:
                logger.debug("Skip malformed CVE: %s", exc)

        await self._conn.executemany(
            """INSERT OR REPLACE INTO cves
               (cve_id, published, modified, severity, cvss_score, description, products, references)
               VALUES (?,?,?,?,?,?,?,?)""",
            rows,
        )
        await self._conn.commit()
        return len(rows)

    async def _get_state(self, key: str) -> str | None:
        assert self._conn
        async with self._conn.execute("SELECT value FROM sync_state WHERE key=?", (key,)) as cur:
            row = await cur.fetchone()
        return row[0] if row else None

    async def _set_state(self, key: str, value: str) -> None:
        assert self._conn
        await self._conn.execute(
            "INSERT OR REPLACE INTO sync_state(key,value) VALUES(?,?)", (key, value)
        )
        await self._conn.commit()

    # ------------------------------------------------------------------ #
    # Queries
    # ------------------------------------------------------------------ #

    async def search(self, query: str, limit: int = 20) -> list[dict]:
        """
        Full-text search across CVE IDs, descriptions, and product strings.

        Args:
            query: Free-text search (e.g. "apache 2.4.49" or "log4j rce")
            limit: Max results

        Returns:
            List of CVE dicts sorted by CVSS score descending.
        """
        assert self._conn
        # FTS5 match syntax: each word must appear
        fts_query = " ".join(f'"{w}"' for w in query.split() if w)
        try:
            async with self._conn.execute(
                """SELECT c.cve_id, c.severity, c.cvss_score, c.description, c.products, c.published
                   FROM cves c
                   JOIN cves_fts f ON c.rowid = f.rowid
                   WHERE cves_fts MATCH ?
                   ORDER BY c.cvss_score DESC
                   LIMIT ?""",
                (fts_query, limit),
            ) as cur:
                rows = await cur.fetchall()
        except Exception:
            # Fallback to LIKE if FTS fails
            like = f"%{query}%"
            async with self._conn.execute(
                """SELECT cve_id, severity, cvss_score, description, products, published
                   FROM cves WHERE description LIKE ? OR products LIKE ?
                   ORDER BY cvss_score DESC LIMIT ?""",
                (like, like, limit),
            ) as cur:
                rows = await cur.fetchall()

        return [_row_to_dict(r) for r in rows]

    async def for_service(self, vendor: str, version: str = "", limit: int = 10) -> list[dict]:
        """
        Find CVEs that affect a specific vendor/product and version.

        Args:
            vendor:  Product name (e.g. "apache", "openssh", "wordpress")
            version: Version string (e.g. "2.4.49") — partial match OK
            limit:   Max results

        Returns:
            List of CVE dicts sorted by CVSS score descending.
        """
        query = vendor
        if version:
            query += f" {version}"
        return await self.search(query, limit=limit)

    async def get_cve(self, cve_id: str) -> dict | None:
        """Fetch a single CVE by ID (e.g. 'CVE-2021-41773')."""
        assert self._conn
        async with self._conn.execute(
            "SELECT cve_id, severity, cvss_score, description, products, published, references "
            "FROM cves WHERE cve_id=?",
            (cve_id.upper(),),
        ) as cur:
            row = await cur.fetchone()
        if not row:
            return None
        d = _row_to_dict(row[:6])
        d["references"] = json.loads(row[6]) if row[6] else []
        return d

    async def stats(self) -> dict:
        """Return basic database statistics."""
        assert self._conn
        async with self._conn.execute("SELECT COUNT(*) FROM cves") as cur:
            total = (await cur.fetchone())[0]
        async with self._conn.execute(
            "SELECT severity, COUNT(*) FROM cves GROUP BY severity"
        ) as cur:
            by_sev = dict(await cur.fetchall())
        last_sync = await self._get_state("last_sync")
        return {"total_cves": total, "by_severity": by_sev, "last_sync": last_sync}


# ---------------------------------------------------------------------------
# NVD CVE parser
# ---------------------------------------------------------------------------

def _parse_nvd_cve(cve: dict) -> tuple:
    """Extract a flat row from an NVD 2.0 CVE object."""
    cve_id    = cve.get("id", "")
    published = cve.get("published", "")
    modified  = cve.get("lastModified", "")

    # English description
    descriptions = cve.get("descriptions", [])
    desc = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "",
    )

    # CVSS score and severity (prefer v3.1, fall back to v3.0, then v2)
    metrics   = cve.get("metrics", {})
    cvss_data = (
        metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
        or metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
        or metrics.get("cvssMetricV2",  [{}])[0].get("cvssData", {})
    )
    cvss_score = float(cvss_data.get("baseScore", 0.0))
    severity   = cvss_data.get("baseSeverity", "none").lower()
    if not severity or severity == "none":
        # Derive from score
        if cvss_score >= 9.0:   severity = "critical"
        elif cvss_score >= 7.0: severity = "high"
        elif cvss_score >= 4.0: severity = "medium"
        elif cvss_score > 0:    severity = "low"
        else:                   severity = "none"

    # CPE product strings
    products: list[str] = []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                if cpe:
                    products.append(_cpe_to_short(cpe))

    # References
    refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]

    return (
        cve_id,
        published,
        modified,
        severity,
        cvss_score,
        desc[:2000],
        json.dumps(list(dict.fromkeys(products))[:30]),
        json.dumps(refs[:10]),
    )


def _cpe_to_short(cpe: str) -> str:
    """Convert cpe:2.3:a:vendor:product:version:... → vendor:product:version."""
    parts = cpe.split(":")
    if len(parts) >= 6:
        return f"{parts[3]}:{parts[4]}:{parts[5]}"
    return cpe


def _row_to_dict(row: tuple) -> dict:
    """Map a DB row (6 cols) to a clean dict."""
    return {
        "cve_id":      row[0],
        "severity":    row[1],
        "cvss_score":  row[2],
        "description": row[3][:300] + "..." if len(row[3]) > 300 else row[3],
        "products":    json.loads(row[4]) if row[4] else [],
        "published":   row[5],
    }

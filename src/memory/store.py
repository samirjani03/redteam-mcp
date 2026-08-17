"""
SQLite-backed memory store for scan results.

Persists every tool execution so findings survive past a single
conversation session. Also provides query methods the LLM can call
via future MCP tools (search_findings, get_attack_surface).

Schema
------
sessions   — one row per agent run (goal, model, timestamp)
scans      — one tool result per row (linked to session)
findings   — individual typed findings extracted from scans
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

from parsers.base import ScanResult, Finding, Port, Subdomain

logger = logging.getLogger("redteam.memory")

# Default DB location inside the container — can be overridden
_DEFAULT_DB = Path("/app/data/redteam.db")


class MemoryStore:
    """
    Async SQLite store.  Call await store.init() once before use.

    Usage:
        store = MemoryStore()
        await store.init()
        session_id = await store.create_session(goal, model)
        await store.save_scan(goal, scan_result, session_id)
        findings = await store.search_findings(query="apache")
    """

    def __init__(self, db_path: str | Path = _DEFAULT_DB) -> None:
        self.db_path = Path(db_path)
        self._conn: aiosqlite.Connection | None = None

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    async def init(self) -> None:
        """Create tables if they don't exist and open the connection."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(str(self.db_path))
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._create_tables()
        logger.info("MemoryStore initialised at %s", self.db_path)

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    async def _create_tables(self) -> None:
        assert self._conn
        await self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                goal      TEXT    NOT NULL,
                model     TEXT    NOT NULL,
                created   TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scans (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER REFERENCES sessions(id),
                tool       TEXT    NOT NULL,
                target     TEXT    NOT NULL,
                timestamp  TEXT    NOT NULL,
                returncode INTEGER DEFAULT 0,
                raw_stdout TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id  INTEGER REFERENCES scans(id),
                target   TEXT,
                kind     TEXT    NOT NULL,  -- 'port' | 'subdomain' | 'vuln'
                severity TEXT    DEFAULT '',
                title    TEXT    NOT NULL,
                detail   TEXT    DEFAULT '',
                url      TEXT    DEFAULT ''
            );
        """)
        await self._conn.commit()

    # ------------------------------------------------------------------ #
    # Write
    # ------------------------------------------------------------------ #

    async def create_session(self, goal: str, model: str) -> int:
        """Insert a new session row and return its id."""
        assert self._conn
        ts = datetime.now(timezone.utc).isoformat()
        cur = await self._conn.execute(
            "INSERT INTO sessions (goal, model, created) VALUES (?, ?, ?)",
            (goal, model, ts),
        )
        await self._conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    async def save_scan(
        self,
        goal: str,
        scan: ScanResult,
        session_id: int | None = None,
    ) -> int:
        """Persist a ScanResult and all its extracted findings. Returns scan id."""
        assert self._conn

        cur = await self._conn.execute(
            "INSERT INTO scans (session_id, tool, target, timestamp, returncode, raw_stdout) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                session_id,
                scan.tool,
                scan.target,
                scan.timestamp.isoformat(),
                scan.returncode,
                scan.raw_stdout[:50_000],   # cap stored raw output
            ),
        )
        scan_id: int = cur.lastrowid  # type: ignore[assignment]

        # Ports
        for p in scan.ports:
            await self._conn.execute(
                "INSERT INTO findings (scan_id, target, kind, title, detail) VALUES (?, ?, ?, ?, ?)",
                (scan_id, scan.target, "port", str(p), p.version),
            )
        # Subdomains
        for s in scan.subdomains:
            await self._conn.execute(
                "INSERT INTO findings (scan_id, target, kind, title, detail) VALUES (?, ?, ?, ?, ?)",
                (scan_id, scan.target, "subdomain", s.host, s.ip),
            )
        # Vulnerabilities
        for f in scan.findings:
            await self._conn.execute(
                "INSERT INTO findings (scan_id, target, kind, severity, title, detail, url) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, scan.target, "vuln", f.severity, f.title, f.description, f.url),
            )

        await self._conn.commit()
        return scan_id

    # ------------------------------------------------------------------ #
    # Read
    # ------------------------------------------------------------------ #

    async def search_findings(self, query: str, limit: int = 50) -> list[dict]:
        """
        Full-text search across findings titles and details.
        Returns a list of dicts suitable for returning to the LLM.
        """
        assert self._conn
        like = f"%{query}%"
        async with self._conn.execute(
            "SELECT kind, severity, title, detail, url, target "
            "FROM findings WHERE title LIKE ? OR detail LIKE ? LIMIT ?",
            (like, like, limit),
        ) as cur:
            rows = await cur.fetchall()

        return [
            {"kind": r[0], "severity": r[1], "title": r[2],
             "detail": r[3], "url": r[4], "target": r[5]}
            for r in rows
        ]

    async def get_attack_surface(self, target: str) -> dict:
        """
        Retrieve all known findings for a specific target.
        Returns a structured dict summarising ports, subs, and vulns.
        """
        assert self._conn

        async with self._conn.execute(
            "SELECT kind, severity, title, detail, url FROM findings WHERE target LIKE ?",
            (f"%{target}%",),
        ) as cur:
            rows = await cur.fetchall()

        surface: dict = {"target": target, "ports": [], "subdomains": [], "vulns": []}
        for kind, severity, title, detail, url in rows:
            if kind == "port":
                surface["ports"].append({"port": title, "detail": detail})
            elif kind == "subdomain":
                surface["subdomains"].append({"host": title, "ip": detail})
            elif kind == "vuln":
                surface["vulns"].append(
                    {"severity": severity, "title": title, "url": url}
                )
        return surface

    async def recent_sessions(self, limit: int = 10) -> list[dict]:
        """Return the N most recent sessions."""
        assert self._conn
        async with self._conn.execute(
            "SELECT id, goal, model, created FROM sessions ORDER BY id DESC LIMIT ?",
            (limit,),
        ) as cur:
            rows = await cur.fetchall()
        return [{"id": r[0], "goal": r[1], "model": r[2], "created": r[3]} for r in rows]

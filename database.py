"""
database.py — All database operations for ThreatLens.

Uses SQLite for local development.
Swap DATABASE_URL to PostgreSQL for production — zero code changes needed.

Why SQLite first:
  - Zero setup, zero dependencies
  - Works in Colab, locally, and Railway
  - Holds millions of articles easily
  - One file = easy backup (just download threatlens.db)
"""

import json
import hashlib
import sqlite3
import datetime
from typing import Optional

from config import DATABASE_URL, DB_TYPE


# ── Connection ────────────────────────────────────────────────────────────────

def get_connection() -> sqlite3.Connection:
    """
    Returns a database connection.
    Sets row_factory so queries return dicts instead of tuples.

    row_factory = sqlite3.Row makes each row behave like a dict:
      row["title"] instead of row[2]
    """
    conn = sqlite3.connect(DATABASE_URL)
    conn.row_factory = sqlite3.Row

    # Enable WAL mode — allows reads while writing
    # Important when the scheduler writes and the API reads simultaneously
    conn.execute("PRAGMA journal_mode=WAL")

    # Foreign key enforcement (SQLite has this off by default)
    conn.execute("PRAGMA foreign_keys=ON")

    return conn


# ── Schema ────────────────────────────────────────────────────────────────────

def init_database() -> None:
    """
    Creates all tables and indexes.
    Safe to call multiple times — CREATE IF NOT EXISTS prevents duplication.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # ── sources ──────────────────────────────────────────────
    # One row per RSS feed / monitoring source
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sources (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT NOT NULL,
            url          TEXT NOT NULL UNIQUE,
            type         TEXT,                       -- vendor_research, government, news, etc
            tier         INTEGER DEFAULT 2,          -- 1=high quality, 2=good, 3=volume
            tags         TEXT DEFAULT '[]',          -- JSON array of topic tags
            active       INTEGER DEFAULT 1,          -- 0 = disabled
            last_fetched TEXT,                       -- ISO datetime
            fetch_count  INTEGER DEFAULT 0,
            error_count  INTEGER DEFAULT 0,          -- consecutive errors → auto-disable
            created_at   TEXT DEFAULT (datetime('now'))
        )
    """)

    # ── articles ──────────────────────────────────────────────
    # One row per article discovered from feeds
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS articles (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id     INTEGER REFERENCES sources(id),
            url           TEXT NOT NULL UNIQUE,
            title         TEXT,
            published_at  TEXT,
            discovered_at TEXT DEFAULT (datetime('now')),

            -- Raw content
            raw_text      TEXT,
            text_length   INTEGER DEFAULT 0,
            content_hash  TEXT UNIQUE,               -- SHA256 of content (dedup)

            -- Processing pipeline status
            -- pending    → scraped, waiting for AI
            -- processing → currently being analyzed (lock)
            -- processed  → AI analysis complete
            -- failed     → AI analysis failed
            -- skipped    → too short / not relevant
            status        TEXT DEFAULT 'pending',
            processed_at  TEXT,
            error_message TEXT,
            retry_count   INTEGER DEFAULT 0
        )
    """)

    # ── intelligence ──────────────────────────────────────────
    # AI-extracted structured intelligence per article
    # Key fields are indexed columns for fast filtering
    # Full JSON blob stored for complete access
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS intelligence (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            article_id        INTEGER UNIQUE REFERENCES articles(id),
            report_type       TEXT,                  -- malware_analysis, campaign_report, etc
            risk_level        TEXT,                  -- Critical, High, Medium, Low
            confidence        TEXT,                  -- High, Medium, Low
            threat_actor      TEXT,                  -- primary threat actor name
            malware_families  TEXT DEFAULT '[]',     -- JSON array of malware names
            targeted_sectors  TEXT DEFAULT '[]',     -- JSON array
            targeted_countries TEXT DEFAULT '[]',    -- JSON array
            ioc_count         INTEGER DEFAULT 0,
            ttp_count         INTEGER DEFAULT 0,
            executive_summary TEXT,
            analyst_notes     TEXT,
            tags              TEXT DEFAULT '[]',     -- JSON array
            full_json         TEXT,                  -- complete AI extraction output
            created_at        TEXT DEFAULT (datetime('now'))
        )
    """)

    # ── iocs ──────────────────────────────────────────────────
    # Deduplicated IOC database across ALL articles
    # Same IOC appearing in 5 reports = 1 row, seen_count = 5
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            type        TEXT NOT NULL,               -- ip, domain, url, hash_md5, hash_sha256, email
            value       TEXT NOT NULL,
            context     TEXT,                        -- how was this IOC used?
            first_seen  TEXT DEFAULT (datetime('now')),
            last_seen   TEXT DEFAULT (datetime('now')),
            seen_count  INTEGER DEFAULT 1,           -- number of reports mentioning this
            UNIQUE(type, value)
        )
    """)

    # ── ioc_sightings ─────────────────────────────────────────
    # Links each IOC to every article it appeared in
    # Many-to-many: one IOC can appear in many articles
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ioc_sightings (
            ioc_id      INTEGER REFERENCES iocs(id),
            article_id  INTEGER REFERENCES articles(id),
            PRIMARY KEY (ioc_id, article_id)
        )
    """)

    # ── Indexes ───────────────────────────────────────────────
    # Indexes = pre-sorted lookup tables = much faster queries
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_articles_status       ON articles(status)",
        "CREATE INDEX IF NOT EXISTS idx_articles_source       ON articles(source_id)",
        "CREATE INDEX IF NOT EXISTS idx_articles_discovered   ON articles(discovered_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_intelligence_risk     ON intelligence(risk_level)",
        "CREATE INDEX IF NOT EXISTS idx_intelligence_type     ON intelligence(report_type)",
        "CREATE INDEX IF NOT EXISTS idx_intelligence_actor    ON intelligence(threat_actor)",
        "CREATE INDEX IF NOT EXISTS idx_iocs_value            ON iocs(value)",
        "CREATE INDEX IF NOT EXISTS idx_iocs_type             ON iocs(type)",
        "CREATE INDEX IF NOT EXISTS idx_iocs_seen_count       ON iocs(seen_count DESC)",
    ]
    for idx in indexes:
        cursor.execute(idx)

    conn.commit()
    conn.close()


# ── Sources ───────────────────────────────────────────────────────────────────

def sync_sources(sources: list[dict]) -> int:
    """
    Syncs source list into DB.
    Inserts new sources, ignores existing ones (preserves fetch history).
    Returns count of newly added sources.
    """
    conn = get_connection()
    cursor = conn.cursor()
    added = 0

    for s in sources:
        cursor.execute("""
            INSERT OR IGNORE INTO sources (name, url, type, tier, tags)
            VALUES (?, ?, ?, ?, ?)
        """, (
            s["name"], s["url"], s["type"],
            s["tier"], json.dumps(s.get("tags", []))
        ))
        if cursor.rowcount == 1:
            added += 1

    conn.commit()
    conn.close()
    return added


def get_active_sources(tier: Optional[int] = None) -> list[dict]:
    """
    Returns all active sources as list of dicts.
    Optionally filter by tier.
    """
    conn = get_connection()
    cursor = conn.cursor()

    if tier:
        cursor.execute(
            "SELECT * FROM sources WHERE active=1 AND tier=? ORDER BY tier, name",
            (tier,)
        )
    else:
        cursor.execute(
            "SELECT * FROM sources WHERE active=1 ORDER BY tier, name"
        )

    # dict(row) converts sqlite3.Row to a plain Python dict
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def update_source_fetch(source_id: int, error: bool = False) -> None:
    """Updates last_fetched timestamp and error/success count."""
    conn = get_connection()
    if error:
        conn.execute(
            "UPDATE sources SET error_count = error_count + 1 WHERE id = ?",
            (source_id,)
        )
        # Auto-disable sources with 5+ consecutive errors
        conn.execute(
            "UPDATE sources SET active = 0 WHERE id = ? AND error_count >= 5",
            (source_id,)
        )
    else:
        conn.execute("""
            UPDATE sources
            SET last_fetched = datetime('now'),
                fetch_count  = fetch_count + 1,
                error_count  = 0
            WHERE id = ?
        """, (source_id,))
    conn.commit()
    conn.close()


# ── Articles ──────────────────────────────────────────────────────────────────

def compute_hash(text: str) -> str:
    """SHA256 fingerprint of text. Same content = same hash."""
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def article_exists(url: str, content_hash: str) -> bool:
    """Returns True if article already in DB (by URL or content hash)."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM articles WHERE url = ?", (url,))
    if cursor.fetchone():
        conn.close()
        return True

    cursor.execute("SELECT id FROM articles WHERE content_hash = ?", (content_hash,))
    exists = cursor.fetchone() is not None
    conn.close()
    return exists


def save_article(source_id: int, url: str, title: str,
                 published_at: Optional[str], text: str) -> int:
    """
    Saves a new article to DB.
    Returns the new article ID, or -1 if it's a duplicate.
    """
    content_hash = compute_hash(text)
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO articles
                (source_id, url, title, published_at, raw_text, text_length, content_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (source_id, url, title, published_at, text, len(text), content_hash))
        conn.commit()
        article_id = cursor.lastrowid
        conn.close()
        return article_id
    except sqlite3.IntegrityError:
        conn.close()
        return -1


def get_pending_articles(limit: int = 20) -> list[dict]:
    """
    Returns pending articles ordered by source tier (Tier 1 first).
    These are articles that need AI processing.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT a.id, a.url, a.title, a.raw_text, s.tier, s.name AS source_name
        FROM articles a
        JOIN sources s ON a.source_id = s.id
        WHERE a.status = 'pending'
        ORDER BY s.tier ASC, a.discovered_at DESC
        LIMIT ?
    """, (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def update_article_status(article_id: int, status: str,
                           error_message: Optional[str] = None) -> None:
    """Updates article processing status."""
    conn = get_connection()
    if status == "processed":
        conn.execute("""
            UPDATE articles
            SET status = 'processed', processed_at = datetime('now')
            WHERE id = ?
        """, (article_id,))
    elif status == "failed":
        conn.execute("""
            UPDATE articles
            SET status = 'failed',
                error_message = ?,
                retry_count = retry_count + 1
            WHERE id = ?
        """, (error_message, article_id))
    else:
        conn.execute(
            "UPDATE articles SET status = ? WHERE id = ?",
            (status, article_id)
        )
    conn.commit()
    conn.close()


def get_articles(limit: int = 50, offset: int = 0,
                 status: str = "processed",
                 risk_level: Optional[str] = None,
                 report_type: Optional[str] = None,
                 search: Optional[str] = None) -> list[dict]:
    """
    Flexible article query used by the API.
    Supports filtering by status, risk, type, and keyword search.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Build query dynamically based on what filters are provided
    where = ["a.status = ?"]
    params = [status]

    if risk_level:
        where.append("i.risk_level = ?")
        params.append(risk_level)
    if report_type:
        where.append("i.report_type = ?")
        params.append(report_type)
    if search:
        where.append("(a.title LIKE ? OR i.executive_summary LIKE ? OR i.threat_actor LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

    where_clause = " AND ".join(where)

    cursor.execute(f"""
        SELECT
            a.id, a.url, a.title, a.published_at, a.discovered_at,
            a.text_length, s.name AS source_name, s.tier,
            i.report_type, i.risk_level, i.confidence,
            i.threat_actor, i.malware_families, i.ioc_count, i.ttp_count,
            i.executive_summary, i.tags
        FROM articles a
        JOIN sources s ON a.source_id = s.id
        LEFT JOIN intelligence i ON a.id = i.article_id
        WHERE {where_clause}
        ORDER BY a.discovered_at DESC
        LIMIT ? OFFSET ?
    """, params + [limit, offset])

    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_article_full(article_id: int) -> Optional[dict]:
    """Returns complete article with full AI JSON."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT a.*, s.name AS source_name, s.tier, s.type AS source_type,
               i.full_json, i.report_type, i.risk_level, i.confidence,
               i.threat_actor, i.executive_summary, i.analyst_notes
        FROM articles a
        JOIN sources s ON a.source_id = s.id
        LEFT JOIN intelligence i ON a.id = i.article_id
        WHERE a.id = ?
    """, (article_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    result = dict(row)
    if result.get("full_json"):
        result["intelligence"] = json.loads(result["full_json"])
    return result


# ── Intelligence ──────────────────────────────────────────────────────────────

def save_intelligence(article_id: int, result: dict) -> None:
    """
    Saves AI extraction output.
    Also extracts and stores IOCs in the deduplicated iocs table.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Extract indexed fields from the full JSON
    actor  = result.get("threat_actor", {})
    actor_name = actor.get("name", "") if isinstance(actor, dict) else str(actor)

    malware = [
        m.get("name", "") for m in result.get("malware_tools", [])
        if isinstance(m, dict)
    ]

    # Count IOCs
    infra = result.get("infrastructure", {})
    ioc_count = (
        len(infra.get("ips",     [])) +
        len(infra.get("domains", [])) +
        len(infra.get("urls",    [])) +
        len(result.get("file_hashes", []))
    )

    cursor.execute("""
        INSERT OR REPLACE INTO intelligence
            (article_id, report_type, risk_level, confidence, threat_actor,
             malware_families, ioc_count, ttp_count, executive_summary,
             analyst_notes, tags, full_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        article_id,
        result.get("report_type", ""),
        result.get("risk_level", ""),
        result.get("confidence_level", ""),
        actor_name,
        json.dumps(malware),
        ioc_count,
        len(result.get("techniques", [])),
        result.get("executive_summary", ""),
        result.get("analyst_notes", ""),
        json.dumps(result.get("tags", [])),
        json.dumps(result)
    ))

    # ── Save IOCs ─────────────────────────────────────────────
    def upsert_ioc(ioc_type: str, value: str, context: str = "") -> Optional[int]:
        """
        Insert IOC if new, update last_seen + seen_count if existing.
        Returns the IOC's database ID.
        """
        if not value or len(value) < 4:
            return None
        cursor.execute("""
            INSERT INTO iocs (type, value, context)
            VALUES (?, ?, ?)
            ON CONFLICT(type, value) DO UPDATE SET
                last_seen  = datetime('now'),
                seen_count = seen_count + 1
        """, (ioc_type, value.strip(), context))

        cursor.execute(
            "SELECT id FROM iocs WHERE type=? AND value=?",
            (ioc_type, value.strip())
        )
        row = cursor.fetchone()
        return row[0] if row else None

    def link_ioc(ioc_id: Optional[int]) -> None:
        """Links an IOC to this article (many-to-many)."""
        if ioc_id:
            cursor.execute("""
                INSERT OR IGNORE INTO ioc_sightings (ioc_id, article_id)
                VALUES (?, ?)
            """, (ioc_id, article_id))

    # Process each IOC type
    for ip in infra.get("ips", []):
        if isinstance(ip, dict):
            ioc_id = upsert_ioc("ip", ip.get("value", ""), ip.get("context", ""))
            link_ioc(ioc_id)

    for domain in infra.get("domains", []):
        if isinstance(domain, dict):
            ioc_id = upsert_ioc("domain", domain.get("value", ""), domain.get("context", ""))
            link_ioc(ioc_id)

    for url_ioc in infra.get("urls", []):
        if isinstance(url_ioc, dict):
            ioc_id = upsert_ioc("url", url_ioc.get("value", ""), url_ioc.get("context", ""))
            link_ioc(ioc_id)

    for h in result.get("file_hashes", []):
        if isinstance(h, dict) and h.get("value"):
            ioc_type = f"hash_{h.get('hash_type', 'unknown').lower()}"
            ioc_id = upsert_ioc(ioc_type, h["value"], h.get("associated_file", ""))
            link_ioc(ioc_id)

    conn.commit()
    conn.close()


# ── IOC Queries ───────────────────────────────────────────────────────────────

def search_iocs(query: str, ioc_type: Optional[str] = None,
                limit: int = 50) -> list[dict]:
    """Search IOC database by value."""
    conn = get_connection()
    cursor = conn.cursor()

    if ioc_type:
        cursor.execute("""
            SELECT * FROM iocs
            WHERE value LIKE ? AND type = ?
            ORDER BY seen_count DESC LIMIT ?
        """, (f"%{query}%", ioc_type, limit))
    else:
        cursor.execute("""
            SELECT * FROM iocs
            WHERE value LIKE ?
            ORDER BY seen_count DESC LIMIT ?
        """, (f"%{query}%", limit))

    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_ioc_articles(ioc_value: str) -> list[dict]:
    """Returns all articles that mention a specific IOC."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT a.id, a.title, a.url, a.discovered_at, i.risk_level
        FROM ioc_sightings s
        JOIN iocs io ON s.ioc_id = io.id
        JOIN articles a ON s.article_id = a.id
        LEFT JOIN intelligence i ON a.id = i.article_id
        WHERE io.value = ?
        ORDER BY a.discovered_at DESC
    """, (ioc_value,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


# ── Statistics ────────────────────────────────────────────────────────────────

def get_stats() -> dict:
    """Returns dashboard statistics."""
    conn = get_connection()
    cursor = conn.cursor()

    def count(query: str, params: tuple = ()) -> int:
        cursor.execute(query, params)
        row = cursor.fetchone()
        return row[0] if row else 0

    stats = {
        "articles": {
            "total":      count("SELECT COUNT(*) FROM articles"),
            "processed":  count("SELECT COUNT(*) FROM articles WHERE status='processed'"),
            "pending":    count("SELECT COUNT(*) FROM articles WHERE status='pending'"),
            "failed":     count("SELECT COUNT(*) FROM articles WHERE status='failed'"),
        },
        "intelligence": {
            "critical":   count("SELECT COUNT(*) FROM intelligence WHERE risk_level='Critical'"),
            "high":       count("SELECT COUNT(*) FROM intelligence WHERE risk_level='High'"),
            "medium":     count("SELECT COUNT(*) FROM intelligence WHERE risk_level='Medium'"),
            "low":        count("SELECT COUNT(*) FROM intelligence WHERE risk_level='Low'"),
        },
        "iocs": {
            "total":      count("SELECT COUNT(*) FROM iocs"),
            "ips":        count("SELECT COUNT(*) FROM iocs WHERE type='ip'"),
            "domains":    count("SELECT COUNT(*) FROM iocs WHERE type='domain'"),
            "hashes":     count("SELECT COUNT(*) FROM iocs WHERE type LIKE 'hash_%'"),
        },
        "sources": {
            "total":      count("SELECT COUNT(*) FROM sources"),
            "active":     count("SELECT COUNT(*) FROM sources WHERE active=1"),
            "tier1":      count("SELECT COUNT(*) FROM sources WHERE tier=1 AND active=1"),
        }
    }
    conn.close()
    return stats

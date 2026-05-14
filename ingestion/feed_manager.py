"""
ingestion/feed_manager.py — Fetches RSS/Atom feeds and stores new articles.

Flow per source:
  1. Parse the RSS/Atom feed (feedparser handles both formats)
  2. For each entry: check if URL already exists in DB
  3. If new: scrape the full article text
  4. Apply length filters
  5. Save to database

Deduplication happens at two levels:
  - URL check  → have we seen this URL before?
  - Hash check → even different URL, same content = skip
"""

import time
import datetime
import feedparser
from typing import Optional

import database as db
from ingestion.scraper import scrape_url
from config import (
    MAX_ARTICLES_PER_FEED,
    MIN_ARTICLE_LENGTH,
    MAX_ARTICLE_LENGTH,
    DELAY_BETWEEN_REQUESTS,
)


def fetch_feed(source: dict) -> dict:
    """
    Fetches one RSS/Atom feed and saves new articles to the database.

    Args:
        source: dict from database (id, name, url, tier, etc)

    Returns:
        stats dict: {found, new, skipped, failed}
    """
    stats = {"found": 0, "new": 0, "skipped": 0, "failed": 0}

    # feedparser.parse() handles both RSS 2.0 and Atom 1.0
    # It's very tolerant of malformed XML (bozo mode)
    feed = feedparser.parse(source["url"])

    # bozo = True means malformed XML but feedparser still tried
    # If bozo AND no entries — completely broken feed, skip it
    if feed.bozo and not feed.entries:
        db.update_source_fetch(source["id"], error=True)
        return stats

    # Limit entries per run to prevent flooding on first-time fetch
    entries = feed.entries[:MAX_ARTICLES_PER_FEED]
    stats["found"] = len(entries)

    for entry in entries:

        # ── Extract metadata from feed entry ─────────────────
        url = getattr(entry, "link", "").strip()
        if not url:
            stats["skipped"] += 1
            continue

        title = getattr(entry, "title", "Untitled")

        # Parse publication date
        # published_parsed = time.struct_time tuple if available
        published_at = None
        if hasattr(entry, "published_parsed") and entry.published_parsed:
            try:
                published_at = datetime.datetime(
                    *entry.published_parsed[:6]
                ).isoformat()
            except Exception:
                published_at = getattr(entry, "published", None)

        # ── Quick URL check before scraping ──────────────────
        # Avoid HTTP request if we already have this article
        if _url_exists(url):
            stats["skipped"] += 1
            continue

        # ── Scrape full article ───────────────────────────────
        text = scrape_url(url)

        if not text:
            stats["failed"] += 1
            continue

        # ── Length filter ─────────────────────────────────────
        if len(text) < MIN_ARTICLE_LENGTH:
            # Too short: paywalled, stub, or just navigation
            stats["skipped"] += 1
            continue

        # Truncate very long articles to save DB space
        if len(text) > MAX_ARTICLE_LENGTH:
            text = text[:MAX_ARTICLE_LENGTH]

        # ── Save to database ──────────────────────────────────
        article_id = db.save_article(
            source_id    = source["id"],
            url          = url,
            title        = title,
            published_at = published_at,
            text         = text
        )

        if article_id > 0:
            stats["new"] += 1
        else:
            # save_article returns -1 on duplicate (content hash match)
            stats["skipped"] += 1

        # Polite delay between scraping individual articles
        time.sleep(DELAY_BETWEEN_REQUESTS * 0.3)

    # ── Update source fetch timestamp ─────────────────────────
    db.update_source_fetch(source["id"], error=False)

    return stats


def run_ingestion(tier_filter: Optional[int] = None) -> dict:
    """
    Runs full ingestion cycle across all active sources.

    Args:
        tier_filter: if set, only fetch that tier (1, 2, or 3)
                     None = fetch all tiers

    Returns:
        Aggregated stats across all sources
    """
    sources = db.get_active_sources(tier=tier_filter)

    if not sources:
        return {"error": "No active sources found"}

    total = {"found": 0, "new": 0, "skipped": 0, "failed": 0, "source_errors": 0}
    results = []

    for source in sources:
        try:
            stats = fetch_feed(source)
            results.append({
                "source": source["name"],
                "tier":   source["tier"],
                "stats":  stats,
                "error":  None
            })
            for key in ["found", "new", "skipped", "failed"]:
                total[key] += stats.get(key, 0)

        except Exception as e:
            db.update_source_fetch(source["id"], error=True)
            results.append({
                "source": source["name"],
                "tier":   source["tier"],
                "stats":  {},
                "error":  str(e)
            })
            total["source_errors"] += 1

        # Polite delay between sources
        time.sleep(DELAY_BETWEEN_REQUESTS)

    total["results"] = results
    return total


def _url_exists(url: str) -> bool:
    """Quick DB check — is this URL already stored?"""
    import sqlite3
    from config import DATABASE_URL
    try:
        conn = sqlite3.connect(DATABASE_URL)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM articles WHERE url = ?", (url,))
        exists = cursor.fetchone() is not None
        conn.close()
        return exists
    except Exception:
        return False

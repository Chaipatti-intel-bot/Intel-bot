"""
api/routes.py — All REST API endpoints for ThreatLens.

Endpoints:
  GET  /health                  → service health check
  GET  /stats                   → dashboard statistics
  GET  /articles                → list articles (with filters)
  GET  /articles/{id}           → get one full article + intelligence
  GET  /iocs                    → search IOC database
  GET  /iocs/{value}/articles   → which articles mention this IOC
  POST /ingest/run              → trigger manual ingestion
  POST /process/run             → trigger manual AI processing
  POST /analyze/url             → analyze a specific URL on demand
"""

import json
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel

import database as db
from ingestion.feed_manager import run_ingestion
from processing.pipeline    import run_processing, analyze_article
from ingestion.scraper      import scrape_url
from ingestion.sources      import SOURCES

router = APIRouter()


# ── Health ────────────────────────────────────────────────────────────────────

@router.get("/health")
def health_check():
    """
    Simple health check.
    Returns 200 OK if the service is running.
    Used by Railway and monitoring tools to verify the app is up.
    """
    stats = db.get_stats()
    return {
        "status":   "ok",
        "articles": stats["articles"]["total"],
        "iocs":     stats["iocs"]["total"],
    }


# ── Stats ─────────────────────────────────────────────────────────────────────

@router.get("/stats")
def get_stats():
    """
    Returns dashboard statistics.
    Used by the frontend to populate the overview page.
    """
    return db.get_stats()


# ── Articles ──────────────────────────────────────────────────────────────────

@router.get("/articles")
def list_articles(
    limit:       int           = Query(default=50,  ge=1, le=200),
    offset:      int           = Query(default=0,   ge=0),
    risk_level:  Optional[str] = Query(default=None),
    report_type: Optional[str] = Query(default=None),
    search:      Optional[str] = Query(default=None),
):
    """
    Returns processed articles with optional filters.

    Query parameters:
      limit       → number of results (1-200, default 50)
      offset      → pagination offset (default 0)
      risk_level  → filter by: Critical, High, Medium, Low
      report_type → filter by: malware_analysis, campaign_report, etc
      search      → keyword search in title, summary, threat actor

    Example:
      GET /articles?risk_level=Critical&limit=10
      GET /articles?search=APT29&report_type=campaign_report
    """
    articles = db.get_articles(
        limit       = limit,
        offset      = offset,
        risk_level  = risk_level,
        report_type = report_type,
        search      = search,
    )

    # Parse JSON array fields for clean response
    for a in articles:
        for field in ["malware_families", "tags"]:
            if isinstance(a.get(field), str):
                try:
                    a[field] = json.loads(a[field])
                except Exception:
                    a[field] = []

    return {
        "count":    len(articles),
        "offset":   offset,
        "articles": articles
    }


@router.get("/articles/{article_id}")
def get_article(article_id: int):
    """
    Returns complete article with full AI intelligence output.

    Response includes:
      - Article metadata (url, title, source, dates)
      - Full intelligence JSON (all IOCs, TTPs, attack flow, etc)
    """
    article = db.get_article_full(article_id)
    if not article:
        raise HTTPException(status_code=404, detail=f"Article {article_id} not found")

    # Parse full_json if it's a string
    if isinstance(article.get("full_json"), str):
        try:
            article["intelligence"] = json.loads(article["full_json"])
        except Exception:
            pass
        del article["full_json"]

    return article


# ── IOCs ──────────────────────────────────────────────────────────────────────

@router.get("/iocs")
def search_iocs(
    q:    str           = Query(..., min_length=2, description="IOC value to search"),
    type: Optional[str] = Query(default=None, description="ip, domain, hash_sha256, etc"),
    limit: int          = Query(default=50, ge=1, le=200),
):
    """
    Searches the deduplicated IOC database.

    Examples:
      GET /iocs?q=185.220          → search IPs starting with 185.220
      GET /iocs?q=.onion           → all onion domains
      GET /iocs?q=APT&type=domain  → domains related to APT
      GET /iocs?q=3a9f2b           → search by hash fragment
    """
    results = db.search_iocs(q, ioc_type=type, limit=limit)
    return {"count": len(results), "iocs": results}


@router.get("/iocs/{ioc_value}/articles")
def get_ioc_articles(ioc_value: str):
    """
    Returns all articles that mention a specific IOC value.
    Useful for pivoting — "which reports mention this IP?"
    """
    articles = db.get_ioc_articles(ioc_value)
    if not articles:
        raise HTTPException(
            status_code=404,
            detail=f"No articles found mentioning IOC: {ioc_value}"
        )
    return {"ioc": ioc_value, "count": len(articles), "articles": articles}


# ── Trigger Endpoints ─────────────────────────────────────────────────────────

@router.post("/ingest/run")
def trigger_ingestion(
    background_tasks: BackgroundTasks,
    tier: Optional[int] = Query(default=None, description="1, 2, or 3 — None for all"),
):
    """
    Manually triggers feed ingestion.
    Runs in the background so the API responds immediately.

    Use this to:
      - Force a refresh without waiting for the scheduler
      - Test specific tiers
      - Debug feed issues

    Example:
      POST /ingest/run          → fetch all tiers
      POST /ingest/run?tier=1   → fetch Tier 1 only (fastest)
    """
    background_tasks.add_task(run_ingestion, tier_filter=tier)
    return {
        "status":  "started",
        "message": f"Ingestion started in background (tier={tier or 'all'})"
    }


@router.post("/process/run")
def trigger_processing(
    background_tasks: BackgroundTasks,
    limit: int = Query(default=20, ge=1, le=100),
):
    """
    Manually triggers AI processing of pending articles.
    Runs in the background.

    Example:
      POST /process/run         → process up to 20 articles
      POST /process/run?limit=5 → process up to 5 articles
    """
    background_tasks.add_task(run_processing, limit=limit)
    return {
        "status":  "started",
        "message": f"AI processing started in background (limit={limit})"
    }


# ── On-Demand Analysis ────────────────────────────────────────────────────────

class AnalyzeURLRequest(BaseModel):
    """Request body for on-demand URL analysis."""
    url: str


@router.post("/analyze/url")
def analyze_url(request: AnalyzeURLRequest):
    """
    Analyzes a specific URL on demand (synchronous — waits for result).
    Does NOT store in database — returns result directly.

    Use this to:
      - Test the pipeline on a specific article
      - Analyze a URL that isn't in any feed
      - Demo the product

    Example:
      POST /analyze/url
      Body: {"url": "https://unit42.paloaltonetworks.com/some-report/"}
    """
    url = request.url.strip()

    # Scrape the URL
    text = scrape_url(url)
    if not text:
        raise HTTPException(
            status_code=422,
            detail=f"Could not extract text from: {url}"
        )

    if len(text) < 200:
        raise HTTPException(
            status_code=422,
            detail="Extracted text too short — may be paywalled or blocked"
        )

    # Run analysis without saving to DB (article_id = -1 signals this)
    from processing.pipeline import triage_report, extract_intelligence, _clean_json
    import json, re

    triage = triage_report(text)
    raw    = extract_intelligence(text, triage)

    if not raw:
        raise HTTPException(status_code=500, detail="AI analysis returned no result")

    try:
        result = json.loads(_clean_json(raw))
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if not match:
            raise HTTPException(status_code=500, detail="Could not parse AI response")
        result = json.loads(match.group())

    result["_source_url"] = url
    result["_triage"]     = triage

    return result


# ── Sources ───────────────────────────────────────────────────────────────────

@router.get("/sources")
def list_sources(tier: Optional[int] = Query(default=None)):
    """
    Returns configured monitoring sources.
    Optionally filter by tier.
    """
    sources = db.get_active_sources(tier=tier)
    return {"count": len(sources), "sources": sources}

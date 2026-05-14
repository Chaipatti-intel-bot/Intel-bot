"""
main.py — ThreatLens FastAPI application entry point.

This is the file that starts everything:
  1. Creates the FastAPI app
  2. Initializes the database
  3. Syncs sources
  4. Starts the background scheduler
  5. Registers all API routes

How to run:
  Locally:  uvicorn main:app --reload --port 8000
  Colab:    use the Colab cell at the bottom of this file
  Railway:  automatically runs this file (set start command in railway.toml)
"""

import asyncio
import threading
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import database as db
from api.routes import router
from ingestion.sources      import SOURCES
from ingestion.feed_manager import run_ingestion
from processing.pipeline    import run_processing
from config import (
    validate_config,
    INGESTION_INTERVAL_SECONDS,
    PROCESSING_INTERVAL_SECONDS,
    RUN_ON_STARTUP,
    MAX_PROCESS_PER_RUN,
    API_HOST,
    API_PORT,
)


# ── Background Scheduler ──────────────────────────────────────────────────────

def _scheduler_loop():
    """
    Runs ingestion and processing on a fixed schedule in a background thread.

    Why a thread and not asyncio?
    feedparser and requests are blocking (synchronous) libraries.
    Running them in asyncio would block the entire event loop.
    A separate thread lets them run without affecting API responsiveness.

    Schedule:
      - Ingestion:  every INGESTION_INTERVAL_SECONDS  (default: 6 hours)
      - Processing: every PROCESSING_INTERVAL_SECONDS (default: 1 hour)
    """
    last_ingestion  = 0  # Unix timestamp of last ingestion
    last_processing = 0  # Unix timestamp of last processing

    print("[scheduler] Starting background scheduler")

    while True:
        now = time.time()

        # ── Ingestion check ───────────────────────────────────
        if now - last_ingestion >= INGESTION_INTERVAL_SECONDS:
            print(f"[scheduler] Running ingestion (interval={INGESTION_INTERVAL_SECONDS}s)")
            try:
                stats = run_ingestion()
                new_articles = stats.get("new", 0)
                print(f"[scheduler] Ingestion complete — {new_articles} new articles")
            except Exception as e:
                print(f"[scheduler] Ingestion error: {e}")
            last_ingestion = time.time()

        # ── Processing check ──────────────────────────────────
        if now - last_processing >= PROCESSING_INTERVAL_SECONDS:
            print(f"[scheduler] Running AI processing (limit={MAX_PROCESS_PER_RUN})")
            try:
                stats = run_processing(limit=MAX_PROCESS_PER_RUN)
                print(f"[scheduler] Processing complete — {stats}")
            except Exception as e:
                print(f"[scheduler] Processing error: {e}")
            last_processing = time.time()

        # Sleep 60 seconds between schedule checks
        # This means schedule accuracy is ±60 seconds — acceptable
        time.sleep(60)


# ── App Startup / Shutdown ────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan — runs on startup and shutdown.
    asynccontextmanager splits it: code before yield = startup, after = shutdown.
    """

    # ── Startup ───────────────────────────────────────────────
    print("=" * 50)
    print("[startup] ThreatLens starting...")

    # Validate config
    errors = validate_config()
    for err in errors:
        print(f"[startup] ⚠️  {err}")

    # Initialize database (creates tables if they don't exist)
    print("[startup] Initializing database...")
    db.init_database()

    # Sync sources from sources.py into database
    print("[startup] Syncing sources...")
    added = db.sync_sources(SOURCES)
    print(f"[startup] Sources synced ({added} new)")

    # Run initial ingestion on startup if configured
    if RUN_ON_STARTUP:
        print("[startup] Running initial ingestion (Tier 1 only)...")
        try:
            # Run in a thread to not block startup
            t = threading.Thread(
                target=run_ingestion,
                kwargs={"tier_filter": 1},
                daemon=True
            )
            t.start()
        except Exception as e:
            print(f"[startup] Initial ingestion error: {e}")

    # Start background scheduler in a daemon thread
    # daemon=True means the thread dies when the main program exits
    scheduler_thread = threading.Thread(
        target=_scheduler_loop,
        daemon=True,
        name="scheduler"
    )
    scheduler_thread.start()
    print("[startup] Background scheduler started")

    # Print current DB stats
    stats = db.get_stats()
    print(f"[startup] DB: {stats['articles']['total']} articles, {stats['iocs']['total']} IOCs")
    print("[startup] ✅ ThreatLens ready!")
    print("=" * 50)

    yield  # App runs here

    # ── Shutdown ──────────────────────────────────────────────
    print("[shutdown] ThreatLens shutting down...")


# ── FastAPI App ───────────────────────────────────────────────────────────────

app = FastAPI(
    title       = "ThreatLens API",
    description = "AI-powered Threat Intelligence Platform",
    version     = "0.1.0",
    lifespan    = lifespan,  # connects our startup/shutdown logic
)

# CORS middleware — allows browsers to call the API from any origin
# In production: replace "*" with your actual frontend domain
app.add_middleware(
    CORSMiddleware,
    allow_origins     = ["*"],
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# Register all routes from api/routes.py
# prefix="/api/v1" means all routes become /api/v1/health, /api/v1/articles, etc
app.include_router(router, prefix="/api/v1")


# ── Root endpoint ─────────────────────────────────────────────────────────────

@app.get("/")
def root():
    """Root endpoint — confirms the API is running."""
    return {
        "service": "ThreatLens",
        "version": "0.1.0",
        "docs":    "/docs",        # FastAPI auto-generated Swagger UI
        "api":     "/api/v1",
    }


# ── Run directly ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    """
    Run with: python main.py
    Or:       uvicorn main:app --reload --host 0.0.0.0 --port 8000
    """
    import uvicorn
    uvicorn.run(
        "main:app",
        host    = API_HOST,
        port    = API_PORT,
        reload  = False,   # set True for local development
        workers = 1,       # 1 worker for SQLite (SQLite doesn't support multi-process writes)
    )

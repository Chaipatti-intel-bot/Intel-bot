"""
config.py — All ThreatLens settings in one place.

How environment variables work:
  - In Colab:   set them with os.environ["KEY"] = "value" before importing this
  - In Railway: set them in Railway dashboard → Variables tab
  - Locally:    create a .env file (never commit this to GitHub)

Every setting has a sensible default so the app runs without configuration.
"""

import os


# ── Database ──────────────────────────────────────────────────────────────────
# SQLite for local/Colab development
# Swap to PostgreSQL URL for production: postgresql://user:pass@host/dbname
DATABASE_URL = os.getenv("DATABASE_URL", "threatlens.db")

# Tells the app which DB driver to use
# "sqlite" or "postgresql"
DB_TYPE = "postgresql" if DATABASE_URL.startswith("postgresql") else "sqlite"


# ── AI / LLM ──────────────────────────────────────────────────────────────────
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL   = os.getenv("GROQ_MODEL",   "llama-3.3-70b-versatile")

# How many tokens the AI can return per call
# Higher = more detailed output but slower and costs more tokens
TRIAGE_MAX_TOKENS     = 600
EXTRACTION_MAX_TOKENS = 2500

# Temperature = randomness (0 = deterministic, 1 = creative)
# For security analysis we want 0.1 — precise and consistent
AI_TEMPERATURE = 0.1


# ── Ingestion ─────────────────────────────────────────────────────────────────
# Max articles to fetch per source per ingestion run
# Prevents flooding the DB on the first run when everything is "new"
MAX_ARTICLES_PER_FEED = int(os.getenv("MAX_ARTICLES_PER_FEED", "10"))

# Article length filter
# Too short = paywalled stub or navigation page
# Too long = not actually an article
MIN_ARTICLE_LENGTH = int(os.getenv("MIN_ARTICLE_LENGTH", "500"))
MAX_ARTICLE_LENGTH = int(os.getenv("MAX_ARTICLE_LENGTH", "80000"))

# HTTP request timeout in seconds
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "15"))

# Polite delay between scraping requests (seconds)
# Prevents us from hammering servers and getting IP blocked
DELAY_BETWEEN_REQUESTS = float(os.getenv("DELAY_BETWEEN_REQUESTS", "1.0"))


# ── AI Processing ─────────────────────────────────────────────────────────────
# Max articles to AI-process per scheduled run
# Groq free tier: 100k tokens/day — each article uses ~3-5k tokens
# So 20 articles/run * 4k tokens = 80k tokens — safe for free tier
MAX_PROCESS_PER_RUN = int(os.getenv("MAX_PROCESS_PER_RUN", "20"))

# Text chunk size for large articles (characters)
# ~22000 chars ≈ 5500 tokens — stays within Groq context window
CHUNK_SIZE    = int(os.getenv("CHUNK_SIZE",    "22000"))
CHUNK_OVERLAP = int(os.getenv("CHUNK_OVERLAP", "1200"))

# How many chars to use for triage phase (just the beginning of the article)
TRIAGE_CHARS = int(os.getenv("TRIAGE_CHARS", "14000"))


# ── Scheduler ─────────────────────────────────────────────────────────────────
# How often to run ingestion (seconds)
# 21600 = 6 hours — good balance of freshness vs API calls
INGESTION_INTERVAL_SECONDS = int(os.getenv("INGESTION_INTERVAL_SECONDS", "21600"))

# How often to run AI processing (seconds)
# 3600 = 1 hour — processes new articles shortly after ingestion
PROCESSING_INTERVAL_SECONDS = int(os.getenv("PROCESSING_INTERVAL_SECONDS", "3600"))

# Run ingestion immediately on startup?
RUN_ON_STARTUP = os.getenv("RUN_ON_STARTUP", "true").lower() == "true"


# ── API ───────────────────────────────────────────────────────────────────────
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("PORT", "8000"))  # Railway uses PORT env var

# API key for protecting endpoints (optional for now)
API_KEY = os.getenv("API_KEY", "")  # empty = no auth required


# ── Notifications (Phase 2) ───────────────────────────────────────────────────
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
SMTP_HOST         = os.getenv("SMTP_HOST", "")
SMTP_PORT         = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER         = os.getenv("SMTP_USER", "")
SMTP_PASS         = os.getenv("SMTP_PASS", "")

# Only notify for these risk levels
NOTIFY_RISK_LEVELS = ["Critical", "High"]


# ── Validation ────────────────────────────────────────────────────────────────
def validate_config() -> list[str]:
    """
    Checks required settings are present.
    Returns list of error messages (empty = all good).
    """
    errors = []
    if not GROQ_API_KEY:
        errors.append("GROQ_API_KEY is not set — AI processing will fail")
    return errors

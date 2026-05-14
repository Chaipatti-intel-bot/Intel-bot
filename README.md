# Intel-Bot

AI-powered Threat Intelligence Platform.
Ingests 35+ security feeds, extracts structured intelligence automatically.

## Project Structure

```
threatlens/
├── main.py                  ← FastAPI app entry point
├── config.py                ← all settings (env vars)
├── database.py              ← all DB operations (SQLite / PostgreSQL)
├── requirements.txt
├── railway.toml             ← Railway deployment config
├── run_in_colab.ipynb       ← run in Google Colab
│
├── ingestion/
│   ├── sources.py           ← 35+ curated security sources
│   ├── feed_manager.py      ← RSS/Atom feed fetching
│   └── scraper.py           ← article text extraction
│
├── processing/
│   └── pipeline.py          ← two-phase AI extraction
│
└── api/
    └── routes.py            ← REST API endpoints
```

## Quick Start (Local)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set environment variables
export GROQ_API_KEY=your_key_here

# 3. Run the server
uvicorn main:app --reload --port 8000

# 4. Open API docs
open http://localhost:8000/docs
```

## Quick Start (Colab)

1. Upload all files to Colab
2. Open `run_in_colab.ipynb`
3. Run cells top to bottom

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/v1/health | Health check |
| GET | /api/v1/stats | Dashboard statistics |
| GET | /api/v1/articles | List articles (filterable) |
| GET | /api/v1/articles/{id} | Full article + intelligence |
| GET | /api/v1/iocs?q= | Search IOC database |
| POST | /api/v1/ingest/run | Trigger ingestion |
| POST | /api/v1/process/run | Trigger AI processing |
| POST | /api/v1/analyze/url | Analyze URL on demand |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| GROQ_API_KEY | required | Groq API key |
| DATABASE_URL | threatlens.db | SQLite path or PostgreSQL URL |
| MAX_PROCESS_PER_RUN | 20 | Articles per AI processing run |
| INGESTION_INTERVAL_SECONDS | 21600 | 6 hours |
| RUN_ON_STARTUP | true | Ingest on first boot |

## Deploy to Railway

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login and deploy
railway login
railway init
railway up
```

Set `GROQ_API_KEY` in Railway dashboard → Variables tab.

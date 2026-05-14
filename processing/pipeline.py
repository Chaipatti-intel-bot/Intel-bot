"""
processing/pipeline.py — Two-phase AI intelligence extraction pipeline.

Phase 1: Triage
  - Reads the first ~14k chars of the article
  - Understands report type, structure, motive, temporal context
  - Fast and cheap (600 tokens max)

Phase 2: Extraction
  - Uses triage context to build a tailored prompt
  - Extracts all structured intelligence
  - Handles chunking for large articles
  - Merges multi-chunk results

This is the core of ThreatLens — ported from the notebook
and refactored into a proper module.
"""

import re
import json
import time
from typing import Optional
from groq import Groq

import database as db
from config import (
    GROQ_API_KEY,
    GROQ_MODEL,
    TRIAGE_MAX_TOKENS,
    EXTRACTION_MAX_TOKENS,
    AI_TEMPERATURE,
    CHUNK_SIZE,
    CHUNK_OVERLAP,
    TRIAGE_CHARS,
    MAX_PROCESS_PER_RUN,
)

# Initialize Groq client once at module level
# This avoids recreating the connection on every call
_client: Optional[Groq] = None

def get_client() -> Groq:
    """Returns the Groq client, initializing it once."""
    global _client
    if _client is None:
        if not GROQ_API_KEY:
            raise ValueError("GROQ_API_KEY is not set in config/environment")
        _client = Groq(api_key=GROQ_API_KEY)
    return _client


# ── Prompts ───────────────────────────────────────────────────────────────────

TRIAGE_PROMPT = """
You are a Cyber Threat Intelligence analyst performing an initial read-through.
Your ONLY job right now is to understand the report's PURPOSE and STRUCTURE.

Return a JSON object with EXACTLY these fields:
{
  "REPORT_TYPE": "<malware_analysis|campaign_report|threat_actor_profile|incident_report|cve_advisory|news_article|research_paper|mixed>",
  "NARRATIVE_STRUCTURE": "<one sentence: how is the report organized>",
  "TEMPORAL_CONTEXT": {
    "historical_background": "<what past activity the author references as context>",
    "current_primary_findings": "<what is actually NEW being reported>",
    "primary_timeframe": "<approximate date range of main findings>"
  },
  "REPORT_MOTIVE": "<one sentence: what is the author communicating and why>",
  "KEY_SUBJECTS": {
    "threat_actors": [],
    "malware_families": [],
    "campaigns": [],
    "cves": [],
    "victims_or_targets": []
  },
  "ANALYST_NOTE": "<flag anything unusual about structure, contradictions, or gaps>"
}
Return STRICT JSON only. No explanation outside the JSON.
"""


def build_extraction_prompt(triage: dict) -> str:
    """
    Builds a tailored extraction prompt using triage findings.

    This is the key innovation — instead of one generic prompt,
    we tell the AI exactly what it's about to read.
    """
    report_type = triage.get("REPORT_TYPE", "mixed")
    temporal    = triage.get("TEMPORAL_CONTEXT", {})

    context_block = f"""
=== PRE-ASSESSED REPORT CONTEXT ===
Report Type        : {report_type}
Narrative Structure: {triage.get('NARRATIVE_STRUCTURE', 'Unknown')}
Report Motive      : {triage.get('REPORT_MOTIVE', 'Unknown')}
Historical Context : {temporal.get('historical_background', 'None identified')}
Current Findings   : {temporal.get('current_primary_findings', 'Unknown')}
Primary Timeframe  : {temporal.get('primary_timeframe', 'Unknown')}
Analyst Note       : {triage.get('ANALYST_NOTE', 'None')}
===================================

CRITICAL INSTRUCTIONS:
- Fields marked [CURRENT] = only findings from the CURRENT/NEW activity
- Fields marked [ALL] = both historical and current, clearly labelled
- Do NOT mix historical context into current campaign/malware fields
- If report is about a known actor with new activity, separate old vs new
"""

    schema = """
{
  "report_type": "<identified type>",
  "narrative_summary": "<2-3 sentences: what happened, who did it, what was the impact>",

  "temporal_scope": {
    "historical_period": "<dates of background/context>",
    "current_campaign_period": "<dates of new/primary findings>"
  },

  "threat_actor": {
    "name": "<primary name>",
    "aliases": [],
    "nation_state_attribution": "<country or Unknown>",
    "motivation": "<financial|espionage|hacktivism|disruption|unknown>",
    "sophistication": "<low|medium|high|nation-state>",
    "historical_note": "[ALL] <summary of prior known activity>"
  },

  "malware_tools": [
    {
      "name": "<malware name>",
      "type": "<ransomware|rat|loader|backdoor|stealer|wiper|dropper|other>",
      "is_new_or_updated": true,
      "capabilities": [],
      "language_or_platform": "<C++|Go|Python|.NET|etc>",
      "notable_technical_detail": "<key technical finding>"
    }
  ],

  "targeted_industries": [],
  "targeted_countries": [],

  "attack_flow": [
    {
      "step": 1,
      "phase": "<Initial Access|Execution|Persistence|Privilege Escalation|Defense Evasion|Credential Access|Discovery|Lateral Movement|Collection|Exfiltration|Impact>",
      "description": "<what happened at this step>",
      "technique_id": "<MITRE ATT&CK T-number or empty string>"
    }
  ],

  "techniques": [
    {
      "technique_id": "<T-number>",
      "name": "<technique name>",
      "tactic": "<tactic name>",
      "notes": "<how specifically used in this attack>"
    }
  ],

  "infrastructure": {
    "ips":     [{"value": "<ip>", "context": "<c2|staging|victim|unknown>"}],
    "domains": [{"value": "<domain>", "context": "<c2|phishing|delivery|unknown>"}],
    "urls":    [{"value": "<url>", "context": "<download|c2|phishing>"}],
    "asns":    []
  },

  "file_hashes": [
    {
      "hash_type": "<md5|sha1|sha256>",
      "value": "<hash value>",
      "associated_file": "<filename if known>"
    }
  ],

  "cves": [
    {
      "id": "<CVE-YYYY-NNNNN>",
      "description": "<brief description>",
      "exploitation_status": "<exploited-in-wild|poc-available|theoretical>"
    }
  ],

  "executive_summary": "<3-5 sentences for a CISO: what happened, who is at risk, recommended action>",
  "analyst_notes": "<technical observations, uncertainties, attribution confidence caveats>",

  "risk_level": "<Critical|High|Medium|Low>",
  "confidence_level": "<High|Medium|Low>",
  "tags": ["<keyword tags for filtering>"],

  "detection_opportunities": [
    {
      "method": "<behavioral|network|endpoint|log-based>",
      "description": "<what to detect>",
      "data_source": "<SIEM|EDR|Firewall|DNS|etc>"
    }
  ]
}
"""

    return f"""You are a senior Cyber Threat Intelligence analyst.
{context_block}

Extract ALL available intelligence from this report.
Return STRICT JSON only matching this schema exactly:
{schema}

Rules:
- Use null for genuinely missing data. NEVER fabricate IOCs or TTPs.
- For techniques: only include those explicitly described, map to MITRE ATT&CK where possible.
- attack_flow must be chronologically ordered.
- executive_summary must be useful to a CISO with no technical background.
"""


# ── Text Chunking ─────────────────────────────────────────────────────────────

def chunk_text(text: str) -> list[str]:
    """
    Splits large text into overlapping chunks.

    Splitting strategy (priority order):
    1. Paragraph boundary (\n\n)
    2. Sentence boundary (. )
    3. Word boundary (space)
    4. Hard cut (last resort)

    Overlap ensures context is not lost at boundaries.
    """
    if len(text) <= CHUNK_SIZE:
        return [text]

    chunks = []
    start  = 0

    while start < len(text):
        end = start + CHUNK_SIZE

        if end >= len(text):
            chunks.append(text[start:])
            break

        # Try paragraph break first (best split point)
        split_at = text.rfind("\n\n", start, end)

        # If no paragraph break or it's in the first half, try sentence
        if split_at == -1 or split_at <= start + CHUNK_SIZE // 2:
            split_at = text.rfind(". ", start, end)

        # If no sentence, try word boundary
        if split_at == -1 or split_at <= start + CHUNK_SIZE // 2:
            split_at = text.rfind(" ", start, end)

        # Last resort: hard cut
        if split_at == -1:
            split_at = end

        chunks.append(text[start:split_at + 1])
        # Back up by overlap to preserve context
        start = max(start + 1, split_at + 1 - CHUNK_OVERLAP)

    return chunks


# ── API Call ──────────────────────────────────────────────────────────────────

def _call_api(messages: list, max_tokens: int) -> str:
    """
    Makes one API call with exponential backoff retry.

    Retry logic:
    - Attempt 0 fails → wait 1 second, try again
    - Attempt 1 fails → wait 2 seconds, try again
    - Attempt 2 fails → raise exception (let caller handle)
    """
    client = get_client()

    for attempt in range(3):
        try:
            resp = client.chat.completions.create(
                model       = GROQ_MODEL,
                messages    = messages,
                temperature = AI_TEMPERATURE,
                max_tokens  = max_tokens,
            )
            return resp.choices[0].message.content

        except Exception as exc:
            if attempt == 2:
                raise
            wait = 2 ** attempt
            time.sleep(wait)


def _clean_json(text: str) -> str:
    """Strips markdown code fences that AI sometimes wraps JSON in."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$",          "", text)
    return text.strip()


# ── Phase 1: Triage ───────────────────────────────────────────────────────────

def triage_report(text: str) -> dict:
    """
    Phase 1: Understand what the report is about.
    Uses only the first TRIAGE_CHARS characters (intro is most informative).

    Returns triage dict, or safe defaults on failure.
    """
    triage_text = text[:TRIAGE_CHARS]

    raw = _call_api(
        messages=[
            {"role": "system", "content": TRIAGE_PROMPT},
            {"role": "user",   "content": f"Assess this report:\n\n{triage_text}"}
        ],
        max_tokens=TRIAGE_MAX_TOKENS
    )

    try:
        return json.loads(_clean_json(raw))
    except json.JSONDecodeError:
        # Return safe defaults so extraction still runs
        return {
            "REPORT_TYPE":         "mixed",
            "NARRATIVE_STRUCTURE": "unknown",
            "TEMPORAL_CONTEXT":    {
                "historical_background":    "",
                "current_primary_findings": "",
                "primary_timeframe":        ""
            },
            "REPORT_MOTIVE":  "Unknown",
            "KEY_SUBJECTS":   {},
            "ANALYST_NOTE":   "Triage failed — extraction proceeding with defaults"
        }


# ── Phase 2: Extraction ───────────────────────────────────────────────────────

def extract_intelligence(text: str, triage: dict) -> Optional[str]:
    """
    Phase 2: Extract structured intelligence using triage context.
    Handles chunking for large articles automatically.

    Returns raw JSON string (caller parses it).
    """
    extraction_prompt = build_extraction_prompt(triage)
    chunks = chunk_text(text)

    # Single chunk — direct extraction
    if len(chunks) == 1:
        return _call_api(
            messages=[
                {"role": "system", "content": extraction_prompt},
                {"role": "user",   "content": chunks[0]}
            ],
            max_tokens=EXTRACTION_MAX_TOKENS
        )

    # Multiple chunks — extract each, then merge
    partials = []
    for i, chunk in enumerate(chunks, 1):
        chunk_note = (
            f"\n\nNOTE: This is chunk {i}/{len(chunks)}. "
            "Extract all intelligence visible in THIS chunk. "
            "A merge pass follows — do not worry about completeness."
        )
        raw = _call_api(
            messages=[
                {"role": "system", "content": extraction_prompt},
                {"role": "user",   "content": chunk + chunk_note}
            ],
            max_tokens=EXTRACTION_MAX_TOKENS
        )
        partials.append(raw)
        time.sleep(1)  # rate limit breathing room between chunks

    # Merge all partial extractions
    return _merge_extractions(partials, triage)


def _merge_extractions(partials: list[str], triage: dict) -> str:
    """
    Merges multiple partial extraction results into one unified report.
    Uses AI to intelligently deduplicate and combine.
    """
    merge_prompt = f"""You are a CTI analyst merging {len(partials)} partial intelligence extractions.

Pre-assessed context:
{json.dumps(triage, indent=2)}

Merge rules:
1. DEDUPLICATE all lists — same IOC appearing in multiple chunks = one entry
2. KEEP the most complete/specific version of any field
3. CONCATENATE attack_flow steps into chronological order
4. UNIFY the executive_summary across all chunks
5. COMBINE tags without duplicates
6. For risk_level: use the HIGHEST level found across chunks

Return the merged result as a single valid JSON object matching the extraction schema.
Return STRICT JSON only.
"""

    merged_input = "\n\n---CHUNK BOUNDARY---\n\n".join(partials)

    return _call_api(
        messages=[
            {"role": "system", "content": merge_prompt},
            {"role": "user",   "content": merged_input}
        ],
        max_tokens=EXTRACTION_MAX_TOKENS
    )


# ── Full Pipeline ─────────────────────────────────────────────────────────────

def analyze_article(article_id: int, text: str, title: str = "") -> Optional[dict]:
    """
    Runs the complete two-phase pipeline on one article.
    Saves results to database on success.

    Returns the intelligence dict, or None on failure.
    """

    # Phase 1 — Triage
    triage = triage_report(text)

    # Phase 2 — Extraction
    raw = extract_intelligence(text, triage)
    if not raw:
        return None

    # Parse JSON
    try:
        result = json.loads(_clean_json(raw))
    except json.JSONDecodeError:
        # Try to extract JSON from response (AI sometimes adds preamble)
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if not match:
            return None
        try:
            result = json.loads(match.group())
        except json.JSONDecodeError:
            return None

    # Attach triage metadata
    result["_triage"]     = triage
    result["_article_id"] = article_id

    # Save to database
    db.save_intelligence(article_id, result)
    db.update_article_status(article_id, "processed")

    return result


def run_processing(limit: int = MAX_PROCESS_PER_RUN) -> dict:
    """
    Processes all pending articles through the AI pipeline.

    Args:
        limit: max articles to process in this run

    Returns:
        Stats dict: {processed, failed, skipped}
    """
    pending = db.get_pending_articles(limit=limit)

    if not pending:
        return {"processed": 0, "failed": 0, "pending_remaining": 0}

    stats = {"processed": 0, "failed": 0}

    for article in pending:
        article_id = article["id"]
        text       = article["raw_text"] or ""
        title      = article["title"] or ""

        if len(text) < 200:
            db.update_article_status(article_id, "skipped", "Text too short")
            continue

        # Mark as processing (prevents double-processing if run twice)
        db.update_article_status(article_id, "processing")

        try:
            result = analyze_article(article_id, text, title)
            if result:
                stats["processed"] += 1
            else:
                db.update_article_status(article_id, "failed", "AI returned no result")
                stats["failed"] += 1

        except Exception as e:
            db.update_article_status(article_id, "failed", str(e)[:500])
            stats["failed"] += 1

        # Rate limit breathing room between articles
        time.sleep(2)

    # Count remaining pending after this run
    remaining = db.get_pending_articles(limit=1000)
    stats["pending_remaining"] = len(remaining)

    return stats

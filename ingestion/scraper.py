"""
ingestion/scraper.py — Fetches and extracts clean text from URLs.

Two functions:
  scrape_url()  → fetches a webpage and extracts article text
  read_pdf()    → extracts text from a local or remote PDF file
"""

import re
import io
import requests
from typing import Optional
from bs4 import BeautifulSoup

from config import REQUEST_TIMEOUT

# Mimics Chrome browser — prevents most bot-blocking
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection":      "keep-alive",
}


def scrape_url(url: str) -> Optional[str]:
    """
    Fetches a URL and extracts the main article text.

    Strategy:
    1. Fetch the page with browser-like headers
    2. Remove noise (scripts, navs, footers)
    3. Find the main content container
    4. Extract meaningful text elements
    5. Normalize whitespace

    Returns clean text string, or None on failure.
    """
    try:
        resp = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()

        # Skip non-HTML content
        content_type = resp.headers.get("Content-Type", "")
        if "pdf" in content_type.lower():
            return _scrape_pdf_from_response(resp.content)
        if not any(t in content_type.lower() for t in ["html", "text"]):
            return None

        soup = BeautifulSoup(resp.text, "lxml")

        # Remove all noise elements
        noise_tags = [
            "script", "style", "nav", "footer", "header",
            "aside", "form", "iframe", "noscript", "button",
            "advertisement", "cookie-notice", "popup",
            "sidebar", "widget", "banner", "ad",
            "related-posts", "social-share", "comments"
        ]
        for tag in soup(noise_tags):
            tag.decompose()

        # Also remove elements by common noise class names
        for elem in soup.find_all(class_=re.compile(
            r"\b(nav|menu|sidebar|footer|header|cookie|popup|"
            r"advertisement|social|share|comment|related|widget)\b",
            re.I
        )):
            elem.decompose()

        # Find main content — priority order
        # Security blogs usually use article, main, or a content div
        content = (
            soup.find("article") or
            soup.find("main") or
            soup.find(attrs={"class": re.compile(
                r"\b(post[-_]?content|article[-_]?content|entry[-_]?content|"
                r"blog[-_]?body|post[-_]?body|content[-_]?body|"
                r"article[-_]?body|main[-_]?content|story[-_]?body)\b",
                re.I
            )}) or
            soup.find("div", id=re.compile(
                r"\b(content|main|article|post|entry)\b", re.I
            )) or
            soup.find("body")
        )

        if not content:
            return None

        # Extract meaningful text from these specific elements
        # pre and code are critical for security blogs — they contain commands and hashes
        text_elements = ["h1", "h2", "h3", "h4", "h5", "p", "li", "pre", "code", "blockquote", "td"]
        parts = []
        for elem in content.find_all(text_elements):
            # get_text with separator=" " joins inline elements properly
            t = elem.get_text(separator=" ").strip()
            # Skip very short fragments (navigation, buttons, single words)
            if len(t) > 40:
                parts.append(t)

        if not parts:
            # Fallback: just get all text
            text = content.get_text(separator="\n", strip=True)
        else:
            text = "\n\n".join(parts)

        # Normalize whitespace
        text = re.sub(r"[ \t]{2,}", " ", text)    # collapse multiple spaces
        text = re.sub(r"\n{3,}", "\n\n", text)     # max 2 consecutive newlines
        text = text.strip()

        return text if len(text) > 100 else None

    except requests.RequestException:
        return None
    except Exception:
        return None


def read_pdf(file_path: str) -> Optional[str]:
    """
    Extracts text from a local PDF file.

    Args:
        file_path: path to PDF file on disk

    Returns:
        Extracted text or None on failure.
    """
    try:
        from pypdf import PdfReader
        reader = PdfReader(file_path)
        pages = []
        for i, page in enumerate(reader.pages):
            text = page.extract_text()
            if text and text.strip():
                pages.append(f"--- Page {i+1} ---\n{text.strip()}")
        return "\n\n".join(pages) if pages else None
    except Exception:
        return None


def _scrape_pdf_from_response(content: bytes) -> Optional[str]:
    """
    Extracts text from PDF bytes (when server returns a PDF directly).
    """
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(content))
        pages = []
        for page in reader.pages:
            text = page.extract_text()
            if text and text.strip():
                pages.append(text.strip())
        return "\n\n".join(pages) if pages else None
    except Exception:
        return None

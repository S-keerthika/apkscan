"""Public mobile app store listing lookup and lightweight metadata readiness checks.

This module does not download store binaries or certify app-store policy compliance.
It inspects publicly exposed listing metadata only.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs

import requests

REQUEST_TIMEOUT = 20


def parse_google_play_url(url: str) -> str | None:
    try:
        parsed = urlparse(url.strip())
        if parsed.scheme not in {"https", "http"} or parsed.netloc.lower() not in {
            "play.google.com", "www.play.google.com"
        }:
            return None
        app_id = parse_qs(parsed.query).get("id", [None])[0]
        return app_id if app_id and re.fullmatch(r"[A-Za-z0-9_.]+", app_id) else None
    except Exception:
        return None


def parse_app_store_id(url: str) -> str | None:
    """Extract the numeric Apple App Store ID from a standard apps.apple.com URL."""
    try:
        parsed = urlparse(url.strip())
        if parsed.scheme not in {"https", "http"} or parsed.netloc.lower() not in {
            "apps.apple.com", "www.apps.apple.com"
        }:
            return None
        match = re.search(r"/id(\d+)(?:$|[/?])", parsed.path)
        return match.group(1) if match else None
    except Exception:
        return None


def search_google_play(query: str, limit: int = 10, country: str = "us") -> list[dict]:
    """Search public Google Play listings by app name or developer."""
    try:
        from google_play_scraper import search as gp_search
    except ImportError as exc:
        raise RuntimeError("Install google-play-scraper to search Google Play.") from exc
    query = query.strip()
    if not query:
        return []
    import inspect
    params = inspect.signature(gp_search).parameters
    kwargs = {}
    if "lang" in params:
        kwargs["lang"] = "en"
    if "country" in params:
        kwargs["country"] = country
    # the result-count keyword differs between google-play-scraper releases (n_hits in 1.x, n in older ones)
    if "n_hits" in params:
        kwargs["n_hits"] = limit
    elif "n" in params:
        kwargs["n"] = limit
    try:
        results = gp_search(query, **kwargs)
        return (results or [])[:limit]
    except Exception as exc:
        raise ValueError(f"Could not search Google Play: {exc}") from exc


def search_app_store(query: str, country: str = "us", limit: int = 10) -> list[dict]:
    """Search Apple App Store by app name using Apple's public Search API."""
    if not query.strip():
        return []
    try:
        response = requests.get(
            "https://itunes.apple.com/search",
            params={"term": query.strip(), "entity": "software", "country": country, "limit": limit},
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "AppScanListingInspector/1.0"},
        )
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        raise ValueError(f"Could not search Apple App Store: {exc}") from exc
    except ValueError as exc:
        raise ValueError("Apple's search service returned invalid JSON.") from exc
    return payload.get("results") or []


def fetch_google_play(app_id: str) -> dict:
    try:
        from google_play_scraper import app as gp_app
        from google_play_scraper import permissions as gp_permissions
        from google_play_scraper.exceptions import NotFoundError
    except ImportError as exc:
        raise RuntimeError("Install google-play-scraper to inspect Google Play listings.") from exc

    try:
        details = gp_app(app_id)
    except NotFoundError as exc:
        raise ValueError(f"No Google Play listing found for package '{app_id}'.") from exc
    except Exception as exc:
        raise ValueError(f"Could not fetch the Google Play listing: {exc}") from exc

    try:
        permissions = gp_permissions(app_id)
    except Exception:
        permissions = []
    return {"platform": "Google Play", "details": details, "permissions": permissions}


def fetch_app_store(app_id: str, country: str = "us") -> dict:
    """Fetch public Apple listing metadata via Apple's iTunes Lookup API."""
    endpoint = "https://itunes.apple.com/lookup"
    try:
        response = requests.get(
            endpoint,
            params={"id": app_id, "country": country},
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "AppScanListingInspector/1.0"},
        )
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        raise ValueError(f"Could not reach Apple's public lookup service: {exc}") from exc
    except ValueError as exc:
        raise ValueError("Apple's lookup service returned invalid JSON.") from exc

    results = payload.get("results") or []
    if not results:
        raise ValueError(f"No Apple App Store listing found for app ID '{app_id}' in country '{country}'.")
    return {"platform": "Apple App Store", "details": results[0], "permissions": []}


def listing_checks(platform: str, details: dict) -> list[dict]:
    """Basic metadata presence checks; these are not official policy determinations."""
    if platform == "Google Play":
        fields = [
            ("App title", details.get("title")),
            ("Description", details.get("description")),
            ("Developer identity", details.get("developer") or details.get("developerName")),
            ("Content rating", details.get("contentRating")),
            ("Privacy policy URL", details.get("privacyPolicy")),
            ("App category", details.get("genre")),
            ("Store listing URL", details.get("url")),
        ]
    else:
        fields = [
            ("App title", details.get("trackName")),
            ("Description", details.get("description")),
            ("Developer / seller", details.get("sellerName") or details.get("artistName")),
            ("Age rating", details.get("trackContentRating")),
            ("Privacy policy URL", details.get("sellerUrl") or details.get("privacyPolicyUrl")),
            ("App category", details.get("primaryGenreName")),
            ("Store listing URL", details.get("trackViewUrl")),
        ]

    return [
        {
            "check": label,
            "status": "Present" if value else "Not exposed / missing",
            "note": "Metadata field is available." if value else
                    "Could not verify this field from the public listing; check it manually.",
        }
        for label, value in fields
    ]



_PKG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")


def classify_query(text: str, platform: str) -> tuple[str, str]:
    """Decide what the user typed. Returns (kind, value).

    kind: "id"   -> a Google Play package id / Apple numeric id / store URL that can be resolved directly
          "name" -> free text to search for
    """
    text = (text or "").strip()
    if not text:
        return "name", ""
    if platform == "Google Play":
        pid = parse_google_play_url(text)
        if pid:
            return "id", pid
        if _PKG_RE.fullmatch(text):
            return "id", text
    else:
        aid = parse_app_store_id(text)
        if aid:
            return "id", aid
        m = re.fullmatch(r"(?:id)?(\d{6,})", text, flags=re.I)
        if m:
            return "id", m.group(1)
    return "name", text

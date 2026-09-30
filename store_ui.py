"""store_ui.py — store finder for Google Play and Apple App Store.

One smart input accepts an app name, a package id / numeric App Store id, or a store URL.
Names produce a list of result cards; ids/URLs resolve straight to the listing.
Only public listing metadata is used — no store binaries are downloaded.
"""
from __future__ import annotations

import html
import json
import time
from datetime import datetime, timezone

import streamlit as st

from store_inspector import (
    classify_query, search_google_play, search_app_store,
    fetch_google_play, fetch_app_store, listing_checks,
)

ACCENT = "#0D9488"      # replaced by the active theme via theme.tint()
WARM = "#F59E0B"        # amber for stars

_CSS = f"""
<style>
  .sf-label {{ font-size:12px; font-weight:800; letter-spacing:.1em; text-transform:uppercase; opacity:.7; margin:14px 0 8px; }}
  .sf-label span {{ font-weight:500; letter-spacing:0; text-transform:none; }}
  .sf-score {{ display:flex; align-items:center; gap:14px; margin:10px 0 6px; }}
  .sf-score .n {{ font-size:52px; font-weight:800; line-height:1; color:{ACCENT}; letter-spacing:-.03em; }}
  .sf-score .st {{ color:{WARM}; font-size:18px; letter-spacing:2px; }}
  .sf-score .sub {{ font-size:12.5px; opacity:.75; margin-top:2px; }}
  .sf-rows {{ margin:10px 0 14px; border-top:1px solid rgba(128,128,128,.28); }}
  .sf-rows > div {{ display:flex; justify-content:space-between; gap:10px; padding:9px 0; border-bottom:1px solid rgba(128,128,128,.2); font-size:14px; }}
  .sf-rows span {{ opacity:.7; }} .sf-rows b {{ text-align:right; word-break:break-word; }}
  .sf-lock {{ font-size:12.5px; opacity:.75; margin:2px 0 6px; }}
  .sf-head {{ display:flex; justify-content:space-between; align-items:center; gap:12px;
              background:linear-gradient(90deg,#0B3B3A,#115E59); color:#ECFEFF; border-radius:14px 14px 0 0;
              padding:12px 18px; font-family:'JetBrains Mono',monospace; font-size:12px; letter-spacing:.08em; text-transform:uppercase; margin-top:14px; }}
  .sf-head b {{ color:#5EEAD4; font-weight:700; }}
  .sf-name {{ font-weight:800; font-size:16px; }}
  .sf-ver  {{ font-family:'JetBrains Mono',monospace; font-size:11.5px; opacity:.65; margin-left:6px; }}
  .sf-pkg  {{ font-family:'JetBrains Mono',monospace; font-size:12.5px; opacity:.8; }}
  .sf-dev  {{ font-size:12.5px; opacity:.65; }}
  .sf-chip {{ display:inline-block; font-family:'JetBrains Mono',monospace; font-size:11.5px; padding:3px 10px;
              border-radius:8px; background:rgba(13,148,136,.13); border:1px solid rgba(13,148,136,.35); }}
  .sf-stars {{ font-family:'JetBrains Mono',monospace; font-size:12px; font-weight:700; color:{WARM}; }}
  .sf-hero  {{ display:flex; gap:18px; align-items:center; }}
  .sf-sev-high   {{ color:#DC2626; font-weight:700; }}
  .sf-sev-medium {{ color:#D97706; font-weight:700; }}
  .sf-sev-low    {{ color:#0D9488; font-weight:700; }}
  .sf-hist {{ display:flex; align-items:center; gap:8px; font-size:12px; margin:3px 0; }}
  .sf-hist .bar {{ flex:1; height:8px; border-radius:5px; background:rgba(128,128,128,.22); overflow:hidden; }}
  .sf-hist .bar > div {{ height:100%; background:{ACCENT}; }}
</style>
"""

SENSITIVE_WORDS = {
    "location": "Location access", "contacts": "Contacts access", "microphone": "Microphone / audio recording",
    "record audio": "Microphone / audio recording", "camera": "Camera access", "sms": "SMS access",
    "text message": "SMS access", "call log": "Call log access", "phone": "Phone state / calls",
    "storage": "Shared storage access", "photos": "Photos / media access", "calendar": "Calendar access",
    "body sensors": "Body sensors", "install packages": "Can install packages",
}


# ----------------------------------------------------------------------------- data access
@st.cache_data(ttl=600, show_spinner=False)
def _cached_search(platform: str, query: str, country: str) -> list[dict]:
    return search_google_play(query, country=country) if platform == "Google Play" else search_app_store(query, country)


@st.cache_data(ttl=600, show_spinner=False)
def _cached_fetch(platform: str, app_id: str, country: str) -> dict:
    return fetch_google_play(app_id) if platform == "Google Play" else fetch_app_store(app_id, country)


def _norm(platform: str, item: dict) -> dict:
    """Normalise a search hit from either store into one shape."""
    if platform == "Google Play":
        score = item.get("score")
        return {
            "id": item.get("appId") or "", "name": item.get("title") or "Unnamed app", "pkg": item.get("appId") or "",
            "dev": item.get("developer") or "", "icon": item.get("icon"), "category": item.get("genre") or "",
            "version": "", "rating": score if isinstance(score, (int, float)) else None,
            "extra": "Free" if item.get("free") else "Paid",
        }
    rating = item.get("averageUserRating")
    return {
        "id": str(item.get("trackId") or ""), "name": item.get("trackName") or "Unnamed app",
        "pkg": item.get("bundleId") or "", "dev": item.get("sellerName") or item.get("artistName") or "",
        "icon": item.get("artworkUrl100") or item.get("artworkUrl512"), "category": item.get("primaryGenreName") or "",
        "version": item.get("version") or "", "rating": rating if isinstance(rating, (int, float)) else None,
        "extra": (f"{item.get('userRatingCount'):,} ratings" if item.get("userRatingCount") else ""),
    }


# ----------------------------------------------------------------------------- risk signals
def _age_days(ts) -> int | None:
    try:
        if isinstance(ts, (int, float)):
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        else:
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


def listing_signals(platform: str, d: dict, permissions) -> list[dict]:
    """Heuristic risk signals from PUBLIC listing data. Pointers for triage, not verdicts."""
    out = []

    def add(sev, title, note):
        out.append({"severity": sev, "signal": title, "note": note})

    if platform == "Google Play":
        if not d.get("privacyPolicy"):
            add("medium", "No privacy policy URL", "The listing does not expose a privacy policy link.")
        if d.get("containsAds"):
            add("low", "Contains ads", "Ad SDKs commonly add network endpoints and tracking identifiers.")
        if d.get("offersIAP"):
            add("low", "In-app purchases", "Payment flows are worth reviewing in a binary scan.")
        if not (d.get("developerEmail") or d.get("developerWebsite")):
            add("low", "No developer contact", "Neither a support email nor website is listed.")
        age = _age_days(d.get("updated"))
        if age is not None and age > 365:
            add("medium", "Not updated in over a year", f"Last updated about {age // 30} months ago; unpatched dependencies are more likely.")
        installs = d.get("realInstalls") or 0
        if d.get("score") and d.get("ratings", 0) > 200 and d["score"] < 3.5:
            add("low", "Low user rating", f"Average {d['score']:.1f} across {d['ratings']:,} ratings.")
        if installs and installs < 1000:
            add("low", "Very low install base", "Little public track record.")
        flat = []
        if isinstance(permissions, dict):
            for cat, items in permissions.items():
                flat += [f"{cat}: {i}" for i in items]
        elif isinstance(permissions, list):
            flat = [str(p) for p in permissions]
        hits = sorted({label for text in flat for word, label in SENSITIVE_WORDS.items() if word in text.lower()})
        if hits:
            add("medium" if len(hits) >= 4 else "low", f"{len(hits)} sensitive permission group(s)", ", ".join(hits))
    else:
        if not d.get("sellerUrl"):
            add("low", "No seller website", "The listing does not expose a seller URL.")
        age = _age_days(d.get("currentVersionReleaseDate"))
        if age is not None and age > 365:
            add("medium", "Not updated in over a year", f"Current version released about {age // 30} months ago.")
        if not d.get("averageUserRating"):
            add("low", "No rating yet", "No public rating signal available.")
        if d.get("advisories"):
            add("medium", "Content advisories", ", ".join(d["advisories"]))
        mos = str(d.get("minimumOsVersion") or "")
        try:
            if mos and float(mos.split(".")[0]) < 13:
                add("low", "Supports very old iOS", f"Minimum iOS {mos} keeps legacy (less secure) APIs reachable.")
        except ValueError:
            pass
    if not out:
        add("info", "No listing-level red flags", "Public metadata looks routine. A binary scan is still the only way to check the code.")
    return out


# ----------------------------------------------------------------------------- rendering
def _stars(r):
    return f'<span class="sf-stars">★ {r:.1f}</span>' if r else '<span class="sf-stars">—</span>'


def _render_results(platform: str, hits: list[dict], country: str, query: str, guard):
    st.markdown(
        f'<div class="sf-label">{len(hits)} match(es) on {platform} for “{html.escape(query)}” '
        f'<span>· pick one to resolve</span></div>', unsafe_allow_html=True)
    for row in range(0, len(hits), 2):
        cols = st.columns(2, gap="medium")
        for col, (i, raw) in zip(cols, list(enumerate(hits))[row:row + 2]):
            a = _norm(platform, raw)
            with col, st.container(border=True):
                top_i, top_t = st.columns([1, 3.2], vertical_alignment="center")
                with top_i:
                    if a["icon"]:
                        st.image(a["icon"], width=56)
                with top_t:
                    ver = f'<span class="sf-ver">v{html.escape(a["version"])}</span>' if a["version"] else ""
                    st.markdown(f'<div><span class="sf-name">{html.escape(a["name"])}</span>{ver}</div>'
                                f'<div class="sf-dev">{html.escape(a["dev"])}</div>', unsafe_allow_html=True)
                chip = f'<span class="sf-chip">{html.escape(a["category"])}</span> ' if a["category"] else ""
                st.markdown(f'<div class="sf-pkg">{html.escape(a["pkg"])}</div>'
                            f'<div style="margin:6px 0 2px">{chip}{_stars(a["rating"])} '
                            f'<span class="sf-dev">{html.escape(a["extra"])}</span></div>', unsafe_allow_html=True)
                if st.button("Resolve this app →", key=f"resolve_{platform}_{i}_{a['id']}", use_container_width=True, type="primary"):
                    if _try_resolve(platform, a["id"], country, guard):
                        st.rerun()


def _try_resolve(platform: str, app_id: str, country: str, guard) -> bool:
    """Resolving needs an account and a scan credit (same rule as uploading a binary)."""
    authed = st.session_state.get("authenticated")
    if not authed:
        st.session_state["pending_resolve"] = (platform, app_id, country)   # retried automatically after sign-in
    else:
        st.session_state.pop("pending_resolve", None)
    if not guard(f"{platform}:{app_id}:{country}"):
        return False
    st.session_state.pop("pending_resolve", None)
    return _resolve(platform, app_id, country)


def _resolve(platform: str, app_id: str, country: str) -> bool:
    try:
        with st.spinner(f"Resolving {app_id} on {platform}…"):
            listing = _cached_fetch(platform, app_id, country)
        st.session_state["resolved_listing"] = {"platform": platform, "app_id": app_id, "country": country, "listing": listing}
        st.session_state.pop(f"{platform}_hits", None)
        return True
    except Exception as exc:
        st.error(str(exc))
        return False


def _remember(query: str):
    recent = st.session_state.setdefault("recent_searches", [])
    if query in recent:
        recent.remove(query)
    recent.insert(0, query)
    del recent[6:]


def render_listing(res: dict, authed: bool, open_auth, go_upload) -> None:
    platform, listing, app_id = res["platform"], res["listing"], res["app_id"]
    d, perms = listing["details"], listing.get("permissions")
    play = platform == "Google Play"

    title = d.get("title") if play else d.get("trackName")
    icon = d.get("icon") if play else d.get("artworkUrl512")
    dev = (d.get("developer") if play else (d.get("sellerName") or d.get("artistName"))) or "Unknown developer"
    pkg = d.get("appId") if play else d.get("bundleId")
    url = d.get("url") if play else d.get("trackViewUrl")

    left, right = st.columns([1.4, 2.6], gap="large")
    with left, st.container(border=True):
        if icon:
            st.image(icon, width=96)
        st.markdown(f"### {title or 'App listing'}")
        st.markdown(f'<div class="sf-pkg">{html.escape(str(pkg or app_id))}</div><div class="sf-dev">{html.escape(dev)}</div>', unsafe_allow_html=True)
        genre = d.get("genre") if play else d.get("primaryGenreName")
        st.markdown(f'<div style="margin:8px 0 10px">{f"<span class=sf-chip>{html.escape(genre)}</span> " if genre else ""}<span class="sf-chip">{platform}</span></div>', unsafe_allow_html=True)
        if play:
            score = d.get("score") if isinstance(d.get("score"), (int, float)) else None
            count = f"{d.get('ratings', 0):,} ratings" if d.get("ratings") else "No rating count"
            rows = [("Installs", d.get("installs") or "—"), ("Version", d.get("version") or "—"),
                    ("Content rating", d.get("contentRating") or "—"), ("Price", "Free" if d.get("free") else f"{d.get('currency', '')} {d.get('price', '')}")]
        else:
            score = d.get("averageUserRating") if isinstance(d.get("averageUserRating"), (int, float)) else None
            count = f"{d.get('userRatingCount', 0):,} ratings" if d.get("userRatingCount") else "No rating count"
            size = f"{round(int(d['fileSizeBytes']) / 1_048_576, 1)} MB" if d.get("fileSizeBytes") else "—"
            rows = [("Version", d.get("version") or "—"), ("Age rating", d.get("trackContentRating") or "—"),
                    ("Min iOS", d.get("minimumOsVersion") or "—"), ("Size", size),
                    ("Price", d.get("formattedPrice") or "Free")]
        full = int(round(score)) if score else 0
        st.markdown(
            f'<div class="sf-score"><div class="n">{f"{score:.1f}" if score else "—"}</div>'
            f'<div><div class="st">{"★" * full}{"☆" * (5 - full)}</div><div class="sub">{count}</div></div></div>'
            '<div class="sf-rows">' + "".join(f"<div><span>{html.escape(k)}</span><b>{html.escape(str(v))}</b></div>" for k, v in rows) + "</div>",
            unsafe_allow_html=True)
        if url:
            st.link_button("Open store page ↗", url, use_container_width=True)
        if st.button("✖ Clear", key="clear_listing", use_container_width=True):
            st.session_state.pop("resolved_listing", None)
            st.rerun()

    with right:
        signals = listing_signals(platform, d, perms)
        checks = listing_checks(platform, d)
        tabs = st.tabs(["📋 Listing", "🚩 Risk signals", "🔑 Permissions" if play else "📱 Capabilities",
                        "🏢 Publisher", "✅ Metadata checks", "⬇ Export"])

        with tabs[0]:
            if play:
                info = {"Package ID": d.get("appId"), "Category": d.get("genre"), "Content rating": d.get("contentRating"),
                        "Released": d.get("released"), "Last updated": d.get("lastUpdatedOn"),
                        "Requires Android": d.get("androidVersion"), "Contains ads": d.get("containsAds"),
                        "In-app purchases": d.get("offersIAP")}
            else:
                info = {"Apple app ID": d.get("trackId"), "Bundle ID": d.get("bundleId"), "Category": d.get("primaryGenreName"),
                        "Age rating": d.get("trackContentRating"), "Released": d.get("releaseDate"),
                        "Current version date": d.get("currentVersionReleaseDate"), "Minimum iOS": d.get("minimumOsVersion"),
                        "Size (MB)": round(int(d["fileSizeBytes"]) / 1_048_576, 1) if d.get("fileSizeBytes") else None}
            st.json({k: v for k, v in info.items() if v not in (None, "")})
            st.markdown("**Package / bundle ID (copy)**")
            st.code(str(pkg or app_id), language=None)
            if d.get("summary") or d.get("description"):
                with st.expander("Description"):
                    st.write(d.get("description") or d.get("summary"))
            notes = d.get("recentChanges") or d.get("releaseNotes")
            if notes:
                with st.expander("What's new"):
                    st.write(notes)
            shots = (d.get("screenshots") or d.get("screenshotUrls") or [])[:4]
            if shots:
                st.image(shots, width=150)
            hist = d.get("histogram")
            if play and hist and sum(hist):
                st.markdown("**Rating distribution**")
                total = sum(hist)
                st.markdown("".join(
                    f'<div class="sf-hist"><span>{star}★</span><div class="bar"><div style="width:{n / total * 100:.0f}%"></div></div><span>{n:,}</span></div>'
                    for star, n in zip(range(5, 0, -1), reversed(hist))), unsafe_allow_html=True)

        with tabs[1]:
            st.caption("Heuristics from public listing data only. They point at where to look; they are not a security verdict.")
            for s in signals:
                st.markdown(f'<span class="sf-sev-{s["severity"]}">[{s["severity"].upper()}]</span> **{html.escape(s["signal"])}** — {html.escape(s["note"])}', unsafe_allow_html=True)

        with tabs[2]:
            if play:
                if isinstance(perms, dict) and perms:
                    st.caption(f"{sum(len(v) for v in perms.values())} permissions declared across {len(perms)} groups.")
                    for cat, items in perms.items():
                        with st.expander(f"{cat} ({len(items)})"):
                            for it in items:
                                st.markdown(f"- {it}")
                elif perms:
                    st.write(perms)
                else:
                    st.info("No permission declarations were exposed for this listing.")
            else:
                st.write({"Supported devices": len(d.get("supportedDevices") or []),
                          "Languages": ", ".join(d.get("languageCodesISO2A") or [])[:120],
                          "Features": d.get("features") or []})
                st.caption("Apple does not publish per-permission declarations in its public lookup API.")

        with tabs[3]:
            if play:
                st.json({k: v for k, v in {"Developer": d.get("developer"), "Email": d.get("developerEmail"),
                         "Website": d.get("developerWebsite"), "Address": d.get("developerAddress"),
                         "Privacy policy": d.get("privacyPolicy")}.items() if v})
            else:
                st.json({k: v for k, v in {"Seller": d.get("sellerName"), "Artist": d.get("artistName"),
                         "Seller URL": d.get("sellerUrl"), "Artist ID": d.get("artistId")}.items() if v})

        with tabs[4]:
            st.dataframe(checks, use_container_width=True, hide_index=True)

        with tabs[5]:
            if not authed:
                st.markdown("🔒 **Sign in to download the listing report.**")
                if st.button("Sign In to Export", type="primary", key="store_export_signin"):
                    open_auth()
            else:
                payload = {"platform": platform, "app_id": app_id, "country": res["country"], "title": title,
                           "publisher": dev, "risk_signals": signals, "metadata_checks": checks,
                           "permissions": perms if play else None,
                           "disclaimer": "Public listing metadata only; not a binary security scan or policy-compliance verdict."}
                st.download_button("Download listing report (JSON)", data=json.dumps(payload, indent=2, ensure_ascii=False, default=str),
                                   file_name=f"{platform.lower().replace(' ', '_')}_{app_id}_listing_report.json", mime="application/json")


    with st.container(border=True):
        cc1, cc2 = st.columns([4, 1.6], vertical_alignment="center")
        cc1.markdown("**Want the code-level audit?** Store listings only show public metadata. "
                     "Upload the APK/ZIP you are authorised to test to run manifest, certificate, DEX, component and entropy analysis.")
        with cc2:
            if st.button("⬆ Upload binary", type="primary", key="goto_upload", use_container_width=True):
                go_upload()


def render_store_finder(platform: str, authed: bool, open_auth, go_upload, guard) -> bool:
    """Draws the finder for one store. Returns True when a resolved listing is on screen."""
    st.markdown(_CSS, unsafe_allow_html=True)
    key = platform.lower().replace(" ", "_")
    default_country = "in" if platform == "Apple App Store" else "us"

    if f"{key}_pending_q" in st.session_state:          # must be set before the widget is created
        st.session_state[f"{key}_q"] = st.session_state.pop(f"{key}_pending_q")

    with st.form(f"{key}_form", border=False, clear_on_submit=False):
        c_q, c_cc, c_go = st.columns([6, 1.1, 1.7], vertical_alignment="bottom")
        q = c_q.text_input(
            "Search", key=f"{key}_q", label_visibility="collapsed",
            placeholder=("Search Google Play (e.g. Spotify, WhatsApp) or paste a package ID / Play URL…"
                         if platform == "Google Play" else
                         "Search the App Store (e.g. Instagram, Notion) or paste an App Store URL / numeric ID…"))
        country = c_cc.text_input("Country", value=default_country, max_chars=2, key=f"{key}_cc",
                                  label_visibility="collapsed", placeholder="cc",
                                  help="Two-letter storefront code (us, in, gb…)").strip().lower()
        go = c_go.form_submit_button("🔎 Resolve App", type="primary", use_container_width=True)

    if authed:
        pr = st.session_state.get("pending_resolve")
        if pr and pr[0] == platform:
            st.session_state.pop("pending_resolve", None)
            if _try_resolve(pr[0], pr[1], pr[2], guard):
                st.rerun()
    st.markdown('<div class="sf-lock">🔒 Searching is free. Resolving an app needs an account and uses one scan credit, the same as uploading a binary.</div>'
                if not authed else
                '<div class="sf-lock">Resolving an app uses one scan credit on the Free plan; Pro and Admin are unlimited.</div>',
                unsafe_allow_html=True)

    recent = st.session_state.get("recent_searches", [])
    if recent:
        cols = st.columns(min(len(recent), 6))
        for col, term in zip(cols, recent[:6]):
            if col.button(f"↺ {term[:18]}", key=f"recent_{key}_{term}", use_container_width=True):
                st.session_state[f"{key}_pending_q"] = term
                st.session_state[f"{key}_auto"] = term
                st.rerun()

    query = (st.session_state.pop(f"{key}_auto", None) or (q.strip() if go else "")).strip()
    if query:
        if not (len(country) == 2 and country.isalpha()):
            st.error("Enter a valid two-letter country code.")
        else:
            _remember(query)
            kind, value = classify_query(query, platform)
            if kind == "id":
                _try_resolve(platform, value, country, guard)
            else:
                try:
                    with st.spinner(f"Searching {platform}…"):
                        hits = _cached_search(platform, value, country)
                    st.session_state[f"{platform}_hits"] = {"hits": hits, "query": value, "country": country}
                    st.session_state.pop("resolved_listing", None)
                except Exception as exc:
                    st.error(str(exc))

    res = st.session_state.get("resolved_listing")
    if res and res["platform"] == platform:
        render_listing(res, authed, open_auth, go_upload)
        return True

    found = st.session_state.get(f"{platform}_hits")
    if found:
        if found["hits"]:
            _render_results(platform, found["hits"], found["country"], found["query"], guard)
        else:
            st.warning("No apps matched that search. Try a different name, a package ID, or a store URL.")
        return True
    return False

"""
app.py — Streamlit front end for the local APK static-analysis scanner.
"""

import os
import tempfile
import traceback
import dataclasses
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import zipfile
import io
import html

import streamlit as st

# ReportLab PDF imports
from reportlab.lib import colors  # pyright: ignore[reportMissingModuleSource]
from reportlab.lib.enums import TA_CENTER, TA_LEFT  # pyright: ignore[reportMissingModuleSource]
from reportlab.lib.pagesizes import A4  # pyright: ignore[reportMissingModuleSource]
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle  # pyright: ignore[reportMissingModuleSource]
from reportlab.lib.units import mm  # pyright: ignore[reportMissingModuleSource]
from reportlab.platypus import (  # pyright: ignore[reportMissingModuleSource]
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

# Application modules
from auth import get_supabase, init_db, create_user, authenticate_user, verify_email_token, resend_verification
from email_utils import send_verification_email
from apk_analyzer import analyze_apk, extract_apks_from_zip, run_deep_bytecode_analysis, DANGEROUS_PERMISSIONS
import store_ui
import theme
from store_inspector import (
    parse_google_play_url, parse_app_store_id, search_google_play, search_app_store, fetch_google_play, fetch_app_store, listing_checks,
)
from payments import (
    create_payment_order, 
    sync_user_subscription, 
    render_razorpay_checkout_button,
    check_and_decrement_scan_limit,
    verify_payment_signature,
    get_subscription_status,
    PRICE_INR,
    PRICE_USD,
)

st.set_page_config(page_title="APKSCAN | Mobile Application Scanner (APK)", page_icon="🛡️", layout="wide")


def inject_custom_css():
    st.markdown(
        """
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
        <style>
            html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
            code, pre, .stCode { font-family: 'JetBrains Mono', monospace !important; }

            /* Hide default Streamlit chrome for a cleaner, branded look */
            #MainMenu, footer { visibility: hidden; }
            header[data-testid="stHeader"] { background: transparent; }

            /* App-wide gradient banner behind the title area */
            .app-hero {
                background: linear-gradient(135deg, #0B3B3A 0%, #0D9488 55%, #5EEAD4 100%);
                border-radius: 16px;
                padding: 28px 32px;
                margin-bottom: 24px;
                color: white;
                box-shadow: 0 10px 30px -10px rgba(13, 148, 136, 0.45);
            }
            .app-hero h1 {
                margin: 0 0 4px 0;
                font-size: 28px;
                font-weight: 800;
                letter-spacing: -0.02em;
                color: white;
            }
            .app-hero p {
                margin: 0;
                font-size: 15px;
                color: #CCFBF1;
                font-weight: 500;
            }

            /* Sidebar */
            section[data-testid="stSidebar"] {
                background: linear-gradient(180deg, #0F172A 0%, #1E293B 100%);
            }
            section[data-testid="stSidebar"] * { color: #E2E8F0 !important; }
            section[data-testid="stSidebar"] .stRadio label { font-weight: 500; }

            /* Buttons */
            .stButton > button {
                border-radius: 10px;
                font-weight: 600;
                transition: transform 0.12s ease, box-shadow 0.12s ease;
                border: none;
            }
            .stButton > button[kind="primary"] {
                background: linear-gradient(135deg, #0D9488, #0F766E);
                box-shadow: 0 4px 14px -4px rgba(13, 148, 136, 0.6);
            }
            .stButton > button:hover { transform: translateY(-1px); }

            /* Metrics */
            div[data-testid="stMetric"] {
                background: #F8FAFC;
                border: 1px solid #E2E8F0;
                border-radius: 12px;
                padding: 14px 16px;
            }

            /* Tabs */
            .stTabs [data-baseweb="tab"] { font-weight: 600; }

            /* Login card container */
            .login-wrap { max-width: 480px; margin: 40px auto 0 auto; }

            /* SaaS workspace styling */
            .block-container { max-width: 1440px; padding-top: 1.5rem; padding-bottom: 3rem; }
            section[data-testid="stSidebar"] { background: #101828; border-right: 1px solid #263449; }
            section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { color: #CBD5E1 !important; }
            section[data-testid="stSidebar"] .stRadio > label { color: #94A3B8 !important; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .09em; }
            section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] label { padding: 10px 12px; border-radius: 10px; margin: 3px 0; }
            section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] label:hover { background: #1E293B; }
            .workspace-top { display:flex; align-items:center; justify-content:space-between; gap:16px; margin-bottom:22px; }
            .workspace-brand { display:flex; align-items:center; gap:12px; color:#0F172A; font-weight:800; font-size:20px; letter-spacing:-.04em; }
            .brand-mark { display:inline-flex; align-items:center; justify-content:center; width:42px; height:42px; border-radius:13px; background:linear-gradient(135deg,#0D9488,#0F766E); color:white; font-size:22px; box-shadow:0 8px 20px #0d948830; }
            .workspace-kicker { color:#64748B; font-size:12px; font-weight:700; letter-spacing:.12em; text-transform:uppercase; margin-bottom:7px; }
            .workspace-title { font-size:30px; line-height:1.2; color:#0F172A; font-weight:800; letter-spacing:-.04em; margin:0 0 8px; }
            .workspace-subtitle { font-size:15px; color:#64748B; margin:0; }
            .app-hero { background:linear-gradient(120deg,#101828 0%,#0B3B3A 58%,#0F766E 100%); border:1px solid #1F5F5A; border-radius:22px; padding:30px 32px; margin:18px 0 24px; box-shadow:0 18px 50px -28px #0f766ea8; }
            .app-hero h1 { font-size:30px; font-weight:800; letter-spacing:-.04em; }
            .app-hero p { color:#CBD5E1; font-size:15px; }
            div[data-testid="stMetric"] { background:#FFFFFF; border:1px solid #E7ECF3; border-radius:16px; padding:17px 18px; box-shadow:0 3px 12px #0f172a06; }
            div[data-testid="stMetricLabel"] { color:#64748B; font-size:12px; font-weight:600; }
            div[data-testid="stMetricValue"] { color:#0F172A; font-weight:800; }
            .stTabs [data-baseweb="tab-list"] { gap:8px; }
            .stTabs [data-baseweb="tab"] { border-radius:9px 9px 0 0; font-weight:650; }
            div[data-testid="stFileUploader"] { background:#F8FAFC; border:1px dashed #CBD5E1; border-radius:16px; padding:16px; }
            div[data-testid="stRadio"] > label { font-weight:700; color:#334155; }
            .stButton > button, .stDownloadButton > button { border-radius:11px; min-height:44px; font-weight:700; }
            .stTextInput input { border-radius:11px; }
            div[data-testid="stAlert"] { border-radius:12px; }

            /* Store discovery and inspection surfaces */
            div[data-testid="stSelectbox"] > label,
            div[data-testid="stTextInput"] > label { color:#334155; font-weight:700; }
            div[data-testid="stSelectbox"] [data-baseweb="select"] > div {
                border:1px solid #D9E2EF; border-radius:12px; min-height:48px;
                background:#FFFFFF; box-shadow:0 2px 8px #0f172a05;
            }
            div[data-testid="stTextInput"] input {
                min-height:48px; border:1px solid #D9E2EF; border-radius:12px;
                background:#FFFFFF;
            }
            div[data-testid="stExpander"] {
                border:1px solid #E2E8F0; border-radius:14px; overflow:hidden;
                background:#FFFFFF;
            }
            div[data-testid="stDataFrame"] { border:1px solid #E2E8F0; border-radius:12px; overflow:hidden; }
            .store-section {
                padding:20px 22px; border:1px solid #E2E8F0; border-radius:18px;
                background:linear-gradient(180deg,#FFFFFF 0%,#F8FAFC 100%);
                margin:12px 0 18px;
            }
            .store-section-title { color:#0F172A; font-size:20px; font-weight:800; letter-spacing:-.03em; }
            .store-section-copy { color:#64748B; font-size:13px; margin-top:4px; }
            .stDownloadButton > button { background:#F8FAFC; border:1px solid #D9E2EF; color:#0F172A; }
            @media (max-width: 760px) {
                .workspace-top { align-items:flex-start; flex-direction:column; }
                .workspace-title { font-size:25px; }
                .app-hero { padding:22px; }
                .app-hero h1 { font-size:24px; }
            }
        </style>
        """,
        unsafe_allow_html=True,
    )

SEVERITY_COLOR = {
    "high": "🔴",
    "medium": "🟠",
    "low": "🟡",
    "info": "🔵",
}

RISK_COLOR = {"High": "🔴", "Medium": "🟠", "Low": "🟢"}
MAX_UPLOAD_MB = 400


def build_pdf_report(result, apk_name):
    """Generate a professional APK security assessment PDF."""
    buffer = io.BytesIO()
    PAGE_WIDTH, PAGE_HEIGHT = A4

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=22 * mm,
        bottomMargin=18 * mm,
        title=f"APK Security Report - {apk_name}",
        author="APK Security Scanner",
    )

    styles = getSampleStyleSheet()

    NAVY = colors.HexColor(theme.tint("#0B3B3A"))
    LIGHT_BLUE = colors.HexColor(theme.tint("#ECFDF9"))
    RED = colors.HexColor("#DC2626")
    LIGHT_RED = colors.HexColor("#FEF2F2")
    ORANGE = colors.HexColor("#EA580C")
    LIGHT_ORANGE = colors.HexColor("#FFF7ED")
    YELLOW = colors.HexColor("#CA8A04")
    LIGHT_YELLOW = colors.HexColor("#FEFCE8")
    GREEN = colors.HexColor("#16A34A")
    LIGHT_GREEN = colors.HexColor("#F0FDF4")
    GRAY = colors.HexColor("#64748B")
    LIGHT_GRAY = colors.HexColor("#F8FAFC")
    BORDER = colors.HexColor("#CBD5E1")
    DARK = colors.HexColor("#0F172A")

    title_style = ParagraphStyle(
        "ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=24, leading=28, textColor=NAVY, alignment=TA_LEFT, spaceAfter=8
    )
    subtitle_style = ParagraphStyle(
        "Subtitle", parent=styles["Normal"], fontName="Helvetica", fontSize=10, leading=14, textColor=GRAY, spaceAfter=5
    )
    section_style = ParagraphStyle(
        "Section", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=15, leading=18, textColor=NAVY, spaceBefore=10, spaceAfter=8
    )
    body_style = ParagraphStyle(
        "Body", parent=styles["BodyText"], fontName="Helvetica", fontSize=9, leading=13, textColor=DARK, spaceAfter=4
    )
    small_style = ParagraphStyle(
        "Small", parent=body_style, fontSize=8, leading=11, textColor=GRAY
    )
    finding_title_style = ParagraphStyle(
        "FindingTitle", parent=body_style, fontName="Helvetica-Bold", fontSize=10, leading=13, textColor=DARK
    )
    evidence_style = ParagraphStyle(
        "Evidence", parent=body_style, fontName="Courier", fontSize=7.5, leading=10, textColor=DARK
    )
    center_style = ParagraphStyle(
        "Center", parent=body_style, alignment=TA_CENTER
    )

    def safe(value):
        return html.escape(str(value)) if value is not None else ""

    def severity_style(severity):
        sev = str(severity).lower()
        if sev == "high": return RED, LIGHT_RED
        if sev == "medium": return ORANGE, LIGHT_ORANGE
        if sev == "low": return YELLOW, LIGHT_YELLOW
        return GRAY, LIGHT_GRAY

    def risk_style(level):
        lvl = str(level).lower()
        if lvl == "high": return RED, LIGHT_RED
        if lvl == "medium": return ORANGE, LIGHT_ORANGE
        if lvl == "low": return GREEN, LIGHT_GREEN
        return GRAY, LIGHT_GRAY

    def draw_header_footer(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(18 * mm, PAGE_HEIGHT - 14 * mm, PAGE_WIDTH - 18 * mm, PAGE_HEIGHT - 14 * mm)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(NAVY)
        canvas.drawString(18 * mm, PAGE_HEIGHT - 11 * mm, "APK SECURITY SCANNER")
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(GRAY)
        canvas.drawRightString(PAGE_WIDTH - 18 * mm, PAGE_HEIGHT - 11 * mm, "Static Application Security Assessment")
        canvas.setStrokeColor(BORDER)
        canvas.line(18 * mm, 12 * mm, PAGE_WIDTH - 18 * mm, 12 * mm)
        canvas.drawString(18 * mm, 7 * mm, "Generated by APK Security Scanner")
        canvas.drawRightString(PAGE_WIDTH - 18 * mm, 7 * mm, f"Page {doc.page}")
        canvas.restoreState()

    story = [
        Spacer(1, 8 * mm),
        Paragraph("APK Security Assessment", title_style),
        Paragraph("Static security analysis report", subtitle_style),
        Spacer(1, 8),
    ]

    metadata = [
        [Paragraph("<b>APK FILE</b>", small_style), Paragraph(safe(apk_name), body_style)],
        [Paragraph("<b>SHA-256</b>", small_style), Paragraph(f"<font name='Courier'>{safe(result.sha256)}</font>", small_style)],
    ]

    metadata_table = Table(metadata, colWidths=[32 * mm, 132 * mm])
    metadata_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GRAY),
        ("BOX", (0, 0), (-1, -1), 0.7, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(metadata_table)
    story.append(Spacer(1, 12))

    risk_level = result.risk_level or "Unknown"
    risk_score = result.risk_score
    finding_count = len(result.findings)
    risk_fg, risk_bg = risk_style(risk_level)

    summary_data = [
        [Paragraph("<b>RISK LEVEL</b>", center_style), Paragraph("<b>RISK SCORE</b>", center_style), Paragraph("<b>FINDINGS</b>", center_style)],
        [
            Paragraph(f"<font color='{risk_fg.hexval()}' size='18'><b>{safe(risk_level).upper()}</b></font>", center_style),
            Paragraph(f"<font color='{NAVY.hexval()}' size='18'><b>{safe(risk_score)}</b></font>", center_style),
            Paragraph(f"<font color='{NAVY.hexval()}' size='18'><b>{finding_count}</b></font>", center_style),
        ],
    ]

    summary_table = Table(summary_data, colWidths=[55 * mm, 55 * mm, 55 * mm], rowHeights=[10 * mm, 18 * mm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, 1), (0, 1), risk_bg),
        ("BACKGROUND", (1, 1), (-1, 1), LIGHT_BLUE),
        ("BOX", (0, 0), (-1, -1), 0.8, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 15))

    story.append(Paragraph("1. Application Information", section_style))
    app_info = [
        ("Application Name", result.app_name or "Unknown"),
        ("Package Name", result.package_name or "Unknown"),
        ("Version Name", result.version_name or "Unknown"),
        ("Version Code", result.version_code or "Unknown"),
        ("Minimum SDK", result.min_sdk or "Unknown"),
        ("Target SDK", result.target_sdk or "Unknown"),
        ("Debuggable", result.is_debuggable),
        ("Allow Backup", result.allows_backup),
        ("Cleartext Traffic", result.uses_cleartext_traffic),
    ]

    app_rows = []
    for i in range(0, len(app_info), 2):
        row = []
        for j in range(2):
            if i + j < len(app_info):
                key, value = app_info[i + j]
                row.extend([
                    Paragraph(f"<b>{safe(key)}</b>", small_style),
                    Paragraph(safe(value) if value is not None else "Unknown", body_style),
                ])
        app_rows.append(row)

    app_table = Table(app_rows, colWidths=[38 * mm, 42 * mm, 38 * mm, 42 * mm])
    app_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), LIGHT_GRAY),
        ("BACKGROUND", (2, 0), (2, -1), LIGHT_GRAY),
        ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(app_table)

    story.append(Paragraph("2. Permissions", section_style))
    permissions = sorted(result.permissions or [])
    if permissions:
        permission_rows = [[Paragraph(f"<font name='Courier'>{safe(p)}</font>", small_style)] for p in permissions]
        permission_table = Table(permission_rows, colWidths=[160 * mm])
        permission_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GRAY),
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.3, BORDER),
        ]))
        story.append(permission_table)
    else:
        story.append(Paragraph("No permissions were extracted.", body_style))

    story.append(PageBreak())
    story.append(Paragraph("3. Findings Ranked by Priority", section_style))

    ranked_findings = result.ranked_findings()
    for index, finding in enumerate(ranked_findings, start=1):
        fg, bg = severity_style(finding.severity)
        title = f"{index}. {finding.category}: {finding.title}"

        header = Table(
            [[
                Paragraph(f"<b>{safe(title)}</b>", finding_title_style),
                Paragraph(f"<font color='{fg.hexval()}'><b>{safe(finding.severity).upper()}</b></font>", center_style),
            ]],
            colWidths=[128 * mm, 32 * mm],
        )
        header.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg),
            ("BOX", (0, 0), (-1, -1), 0.7, fg),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(header)
        story.append(Spacer(1, 4))
        story.append(Paragraph(f"<b>Description</b><br/>{safe(finding.detail)}", body_style))

        if finding.evidence:
            evidence_box = Table(
                [[Paragraph(f"<b>Evidence</b><br/><font name='Courier'>{safe(finding.evidence)}</font>", evidence_style)]],
                colWidths=[160 * mm],
            )
            evidence_box.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GRAY),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
            ]))
            story.append(evidence_box)
        story.append(Spacer(1, 8))

    doc.build(story, onFirstPage=draw_header_footer, onLaterPages=draw_header_footer)
    buffer.seek(0)
    return buffer.getvalue()


def extract_play_store_id(url: str):
    parsed = urlparse(url)
    is_play_url = "play.google.com" in parsed.netloc
    is_market_uri = parsed.scheme == "market"
    if not (is_play_url or is_market_uri):
        return None
    qs = parse_qs(parsed.query)
    return qs.get("id", [None])[0]


def fetch_play_store_details(app_id: str):
    from google_play_scraper import app as gp_app
    from google_play_scraper import permissions as gp_permissions
    from google_play_scraper.exceptions import NotFoundError

    try:
        details = gp_app(app_id)
    except NotFoundError:
        raise ValueError(f"No Play Store listing found for package id '{app_id}'.")
    except Exception as e:
        raise ValueError(f"Couldn't fetch Play Store listing: {e}")

    try:
        perms = gp_permissions(app_id)
    except Exception:
        perms = {}

    return details, perms


def render_play_store_details(details: dict, perms: dict):
    st.subheader(f"📦 {details.get('title', 'Unknown app')}")
    col1, col2, col3, col4 = st.columns(4)
    score = details.get("score")
    col1.metric("Rating", f"{score:.1f}⭐" if isinstance(score, (int, float)) else "—")
    col2.metric("Reviews", f"{details.get('reviews', 0):,}" if details.get("reviews") else "—")
    col3.metric("Installs", details.get("installs", "—"))
    col4.metric("Price", "Free" if details.get("free") else f"{details.get('currency','')} {details.get('inAppProductPrice','')}")

    tabs = st.tabs(["📋 Overview", "🏢 Developer", "🔑 Disclosed permissions"])
    with tabs[0]:
        st.json({
            "package_id": details.get("appId"),
            "category": details.get("genre"),
            "content_rating": details.get("contentRating"),
            "released": details.get("released"),
            "current_version": details.get("version"),
        })
    with tabs[1]:
        st.json({
            "developer": details.get("developer"),
            "developer_email": details.get("developerEmail"),
            "developer_website": details.get("developerWebsite"),
        })
    with tabs[2]:
        if perms:
            for category, items in perms.items():
                with st.expander(f"{category} ({len(items)})"):
                    for item in items:
                        st.write(f"- {item}")




def inject_mas_css(dark: bool):
    """MAS-style look: clean white cards, pill badges, monospace tags, optional dark mode."""
    palette = theme.palette(dark)
    st.markdown(f"""
    <style>
        section[data-testid="stSidebar"], div[data-testid="stSidebarCollapsedControl"] {{ display:none !important; }}
        .stApp {{ background:{palette['bg']}; color:{palette['text']}; }}
        .block-container {{ max-width:1180px; padding-top:1rem; }}
        header[data-testid="stHeader"] {{ display:none; }}
        .stApp p, .stApp label, .stApp span, .stApp h1, .stApp h2, .stApp h3, .stApp li {{ color:{palette['text']}; }}
        .mas-brand {{ display:flex; align-items:center; gap:14px; }}
        .mas-logo {{ width:52px; height:52px; border-radius:14px; background:{palette['soft']}; border:1px solid {palette['border']};
                    display:flex; align-items:center; justify-content:center; font-size:26px; }}
        .mas-name {{ font-size:26px; font-weight:800; letter-spacing:-.02em; color:{palette['text']}; }}
        .mas-tag {{ display:inline-block; font-family:'JetBrains Mono',monospace; font-size:11.5px; font-weight:600; letter-spacing:.04em;
                   background:{palette['tag']}; color:{palette['tagtxt']}; border:1px solid {palette['border']}; border-radius:7px; padding:3px 9px; margin-left:8px; vertical-align:middle; }}
        .mas-sub {{ color:{palette['sub']}; font-size:14px; margin-top:2px; }}
        .mas-card {{ background:{palette['card']}; border:1px solid {palette['border']}; border-radius:22px; padding:26px 30px; margin:18px 0; box-shadow:0 1px 3px #0f172a0a; }}
        .mas-card h2 {{ margin:0; font-size:26px; font-weight:800; letter-spacing:-.02em; }}
        .mas-info {{ background:{palette['soft']}; border:1px solid {palette['border']}; border-radius:16px; padding:16px 20px; margin-top:14px; font-size:14px; color:{palette['text']}; }}
        .mas-info code {{ font-family:'JetBrains Mono',monospace; background:{palette['tag']}; color:{palette['tagtxt']}; padding:2px 7px; border-radius:6px; font-size:12.5px; }}
        .mas-empty {{ text-align:center; padding:34px 10px 10px; }}
        .mas-empty .ico {{ width:76px; height:76px; margin:0 auto 18px; border-radius:20px; background:{palette['soft']}; border:1px solid {palette['border']}; display:flex; align-items:center; justify-content:center; font-size:38px; }}
        .mas-empty h3 {{ font-size:26px; font-weight:800; margin:0 0 10px; }}
        .mas-empty p {{ color:{palette['sub']}; max-width:640px; margin:0 auto 18px; line-height:1.6; }}
        .mas-kpi {{ background:{palette['card']}; border:1px solid {palette['border']}; border-radius:16px; padding:16px 18px; }}
        .mas-kpi .k {{ font-size:11.5px; font-weight:700; letter-spacing:.08em; text-transform:uppercase; color:{palette['sub']}; }}
        .mas-kpi .v {{ font-size:26px; font-weight:800; margin-top:4px; word-break:break-all; }}
        .mas-kpi .s {{ font-size:12px; color:{palette['sub']}; margin-top:2px; }}
        .mas-drop {{ border:2px dashed {palette['border']}; background:{palette['soft']}; border-radius:18px; padding:34px 20px; text-align:center; margin:10px 0 14px; }}
        .mas-drop b {{ font-size:17px; }}
        .mas-drop div {{ color:{palette['sub']}; font-size:13px; margin-top:4px; }}
        .mas-lock {{ background:{palette['soft']}; border:1px solid {palette['border']}; border-radius:16px; padding:22px; text-align:center; }}
        .mas-bar {{ height:10px; border-radius:6px; background:{palette['border']}; overflow:hidden; }}
        .mas-bar > div {{ height:100%; border-radius:6px; }}
        .stTabs [data-baseweb="tab-list"] {{ border-bottom:1px solid {palette['border']}; gap:6px; }}
        .stTabs [data-baseweb="tab"] {{ font-size:15px; padding:12px 16px; }}
        .stTabs [aria-selected="true"] {{ color:#0D9488 !important; }}
        .stTabs [data-baseweb="tab-highlight"] {{ background-color:#0D9488 !important; }}
        .stCheckbox [data-baseweb="checkbox"] > div:first-child {{ border-color:#0D9488; }}
        div[data-testid="stTextInput"] input:focus {{ border-color:#0D9488 !important; box-shadow:0 0 0 1px #0D9488 !important; }}
        div[data-testid="stRadio"] div[role="radiogroup"] {{ background:{palette['soft']}; border:1px solid {palette['border']}; border-radius:14px; padding:6px; gap:6px; }}
        div[data-testid="stRadio"] div[role="radiogroup"] label {{ padding:10px 16px; border-radius:10px; margin:0; }}
        div[data-testid="stRadio"] div[role="radiogroup"] label:has(input:checked) {{ background:#0D9488; }}
        div[data-testid="stRadio"] div[role="radiogroup"] label:has(input:checked) * {{ color:#fff !important; }}
        div[data-testid="stRadio"] div[role="radiogroup"] label > div:first-child {{ display:none; }}
        [data-testid="stButtonGroup"] button {{ border-radius:10px; font-weight:700; padding:10px 18px; background:{palette['soft']}; color:{palette['text']}; border:1px solid {palette['border']}; }}
        [data-testid="stButtonGroup"] button[data-testid="stBaseButton-segmented_controlActive"] {{ background:#0D9488; color:#fff; border-color:#0D9488; }}
        [data-testid="stButtonGroup"] button[data-testid="stBaseButton-segmented_controlActive"] * {{ color:#fff !important; }}
        .st-key-topbar {{ background:linear-gradient(100deg,#0B3B3A,#115E59); border-radius:18px; padding:14px 22px; margin-bottom:18px; }}
        .st-key-topbar [data-testid="stMarkdownContainer"] * {{ color:#ECFEFF; }}
        .st-key-topbar .tb-name {{ font-size:22px; font-weight:800; letter-spacing:-.01em; color:#fff !important; }}
        .st-key-topbar .tb-sub {{ font-size:11.5px; letter-spacing:.1em; text-transform:uppercase; color:#5EEAD4 !important; margin-top:2px; }}
        .st-key-topbar button {{ background:rgba(255,255,255,.08); color:#fff; border:1px solid rgba(255,255,255,.25); }}
        .st-key-topbar button * {{ color:inherit !important; }}
        .st-key-topbar button[kind="primary"] {{ background:#5EEAD4; color:#0B3B3A; border:none; }}
        .st-key-rail {{ background:{palette['card']}; border:1px solid {palette['border']}; border-radius:18px; padding:16px 14px; }}
        .rail-label {{ font-size:11px; font-weight:800; letter-spacing:.14em; text-transform:uppercase; color:{palette['sub']}; margin:6px 0 8px; }}
        .st-key-rail button {{ justify-content:flex-start; text-align:left; }}
        .step {{ display:flex; gap:11px; align-items:center; padding:7px 0; font-size:13.5px; color:{palette['sub']}; }}
        .step .dot {{ width:24px; height:24px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:12px; font-weight:800; border:2px solid {palette['border']}; flex:none; }}
        .step.done {{ color:{palette['text']}; }} .step.done .dot {{ background:#0D9488; border-color:#0D9488; color:#fff; }}
        .step.now {{ color:{palette['text']}; font-weight:700; }} .step.now .dot {{ border-color:#0D9488; color:#0D9488; }}
        .hero2 {{ background:linear-gradient(115deg,#0B3B3A 0%,#115E59 60%,#0D9488 130%); border-radius:20px; padding:24px 28px; margin-bottom:16px; }}
        .hero2 .t {{ font-size:26px; font-weight:800; letter-spacing:-.02em; color:#fff !important; }}
        .hero2 .s {{ font-size:14px; color:#CCFBF1 !important; margin-top:4px; }}
        .hero2 .chips {{ margin-top:14px; display:flex; flex-wrap:wrap; gap:8px; }}
        .hero2 .chips span {{ font-family:'JetBrains Mono',monospace; font-size:11.5px; color:#ECFEFF !important; border:1px solid rgba(255,255,255,.28); background:rgba(255,255,255,.08); padding:4px 11px; border-radius:999px; }}
        .tiles {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:14px; margin:8px 0 14px; }}
        .tile {{ background:{palette['card']}; border:1px solid {palette['border']}; border-radius:16px; padding:18px; }}
        .tile .ic {{ width:38px; height:38px; border-radius:11px; background:{palette['soft']}; display:flex; align-items:center; justify-content:center; font-size:19px; margin-bottom:10px; }}
        .tile b {{ font-size:15px; }} .tile p {{ font-size:13px; color:{palette['sub']}; margin:4px 0 0; line-height:1.5; }}
        .sumrow {{ display:flex; gap:24px; align-items:center; background:{palette['card']}; border:1px solid {palette['border']}; border-radius:20px; padding:20px 24px; margin-bottom:16px; flex-wrap:wrap; }}
        .ring {{ width:104px; height:104px; border-radius:50%; display:flex; align-items:center; justify-content:center; flex:none; }}
        .ring-in {{ width:80px; height:80px; border-radius:50%; background:{palette['card']}; display:flex; flex-direction:column; align-items:center; justify-content:center; }}
        .ring-in b {{ font-size:26px; line-height:1; }} .ring-in span {{ font-size:11px; color:{palette['sub']}; font-weight:700; text-transform:uppercase; letter-spacing:.08em; }}
        .sevbar {{ display:flex; height:12px; border-radius:8px; overflow:hidden; background:{palette['border']}; margin:10px 0 6px; min-width:260px; }}
        .stButton > button {{ border-radius:12px; border:1px solid {palette['border']}; background:{palette['card']}; color:{palette['text']}; }}
        .stButton > button[kind="primary"] {{ background:#0D9488; color:#fff; border:none; }}
        div[data-testid="stTextInput"] input {{ background:{palette['card']}; color:{palette['text']}; }}
        div[data-testid="stExpander"], div[data-testid="stMetric"] {{ background:{palette['card']}; border-color:{palette['border']}; }}
    </style>
    """, unsafe_allow_html=True)



def _handle_verify_link():
    """Email verification link (?verify=<token>) — works from any page state."""
    qp = st.query_params
    if "verify" in qp:
        token = qp["verify"]
        st.query_params.clear()
        st.session_state["verify_result"] = "success" if verify_email_token(token) else "failed"
    if "verify_result" in st.session_state:
        if st.session_state.pop("verify_result") == "success":
            st.success("✅ Email confirmed! You can log in now.")
            st.session_state["open_auth"] = "Login"
        else:
            st.error("That verification link is invalid or has already been used.")


@st.dialog("Sign in to continue")
def auth_dialog(default_tab: str = "Login", reason: str = ""):
    if reason:
        st.info(reason)
    login_tab, signup_tab = st.tabs(["Login", "Create Account"])

    with login_tab:
        email = st.text_input("Email", key="login_email")
        password = st.text_input("Password", type="password", key="login_password")
        if st.button("Login", type="primary", key="login_btn", use_container_width=True):
            result = authenticate_user(email, password)
            if result == "unverified":
                st.warning("Please confirm your email before logging in — check your inbox for the activation link.")
                st.session_state["resend_email"] = email
            elif result:
                st.session_state.authenticated = True
                st.session_state.user = result
                st.rerun()
            else:
                st.error("Invalid email or password.")
        if st.session_state.get("resend_email") and st.button("Resend verification email", key="resend_login"):
            token = resend_verification(st.session_state["resend_email"])
            if token and send_verification_email(st.session_state["resend_email"], token):
                st.success("Verification email sent — check your inbox.")
            elif not token:
                st.error("Couldn't resend — check the email address is correct.")

    with signup_tab:
        new_name = st.text_input("Full Name", key="signup_name")
        new_email = st.text_input("Email", key="signup_email")
        new_password = st.text_input("Password", type="password", key="signup_password")
        confirm_password = st.text_input("Confirm Password", type="password", key="signup_confirm")
        if st.button("Create Account", type="primary", key="signup_btn", use_container_width=True):
            if not new_name.strip() or not new_email.strip() or not new_password:
                st.error("All fields are required.")
            elif new_password != confirm_password:
                st.error("Passwords do not match.")
            else:
                token = create_user(new_email, new_password, role="user", name=new_name.strip())
                if token:
                    if send_verification_email(new_email.lower().strip(), token):
                        st.success("Account created! Check your email for an activation link, then log in.")
                else:
                    st.error("An account with this email already exists.")


def require_login(reason: str = "Please log in or create an account to continue.") -> bool:
    """True if signed in; otherwise opens the sign-in dialog and returns False."""
    if st.session_state.get("authenticated"):
        return True
    auth_dialog(reason=reason)
    return False


def is_admin_user():
    user = st.session_state.get("user") or {}
    return str(user.get("role", "user")).lower() == "admin"


def save_scan_report(user_id: int, file_name: str, sha256: str, risk_level: str, risk_score: int, findings_count: int, report_json: dict):
    """Saves completed scan results into public.scan_reports table."""
    supabase = get_supabase()
    try:
        supabase.table("scan_reports").insert({
            "user_id": user_id,
            "file_name": file_name,
            "sha256": sha256,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "findings_count": findings_count,
            "report_data": report_json
        }).execute()
        st.toast("Report saved to history!", icon="💾")
    except Exception as e:
        st.warning(f"Could not persist report: {e}")


def render_history_page(user_id: int):
    st.markdown(
        """
        <div class="app-hero">
            <h1>📜 Scan History</h1>
            <p>Every past report, saved and searchable.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    supabase = get_supabase()
    res = supabase.table("scan_reports").select("*").eq("user_id", user_id).order("created_at", desc=True).execute()

    if not res.data:
        st.info("No past scans found. Run your first scan from the **APK Scanner** tab.")
        return

    col_search, col_filter = st.columns([3, 1])
    with col_search:
        query = st.text_input("🔎 Search by file or package name", key="history_search")
    with col_filter:
        risk_filter = st.selectbox("Risk level", ["All", "High", "Medium", "Low"], key="history_risk_filter")

    reports = res.data
    if query:
        q = query.lower()
        reports = [
            r for r in reports
            if q in r["file_name"].lower()
            or q in (r.get("report_data") or {}).get("package_name", "").lower()
        ]
    if risk_filter != "All":
        reports = [r for r in reports if r["risk_level"] == risk_filter]

    if not reports:
        st.info("No scans match that search.")
        return

    st.caption(f"{len(reports)} scan{'s' if len(reports) != 1 else ''}")

    for report in reports:
        data = report.get("report_data") or {}
        icon = RISK_COLOR.get(report["risk_level"], "⚪")
        with st.expander(
            f"{icon} **{report['file_name']}** — {report['risk_level']} risk "
            f"({report['findings_count']} findings) · {report['created_at'][:10]}"
        ):
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Risk score", report["risk_score"])
            c2.metric("Findings", report["findings_count"])
            c3.metric("Package", data.get("package_name") or "—")
            c4.metric("Version", data.get("version_name") or "—")

            findings = data.get("findings") or []
            permissions = data.get("permissions") or []

            detail_tabs = st.tabs([f"⚠️ Findings ({len(findings)})", f"🔑 Permissions ({len(permissions)})"])
            with detail_tabs[0]:
                if not findings:
                    st.caption("No issues flagged.")
                for f in findings:
                    sev = f.get("severity", "info")
                    sev_icon = SEVERITY_COLOR.get(sev, "")
                    st.markdown(f"{sev_icon} **[{sev.upper()}] {f.get('category', '')}: {f.get('title', '')}**")
                    st.caption(f.get("detail", ""))
            with detail_tabs[1]:
                if not permissions:
                    st.caption("No permissions recorded.")
                for p in sorted(permissions):
                    short = p.split(".")[-1]
                    if p in DANGEROUS_PERMISSIONS:
                        st.markdown(f"🔴 **{short}** — {DANGEROUS_PERMISSIONS[p]}")
                    else:
                        st.markdown(f"⚪ {short}")

            st.caption(f"SHA-256: `{report['sha256']}`")


def render_pricing_page(user):
    if "scan_error" in st.session_state:
        st.error(st.session_state.scan_error)
        del st.session_state.scan_error

    # --- Handle a Razorpay checkout redirect (verify BEFORE trusting it) ---
    qp = st.query_params
    if "payment_id" in qp and "payment_order_id" in qp and "payment_signature" in qp:
        order_id = qp["payment_order_id"]
        payment_id = qp["payment_id"]
        signature = qp["payment_signature"]

        st.query_params.clear()

        if verify_payment_signature(order_id, payment_id, signature):
            if sync_user_subscription(user["id"], plan_tier="pro"):
                st.session_state.pop("active_order", None)
                st.success("Payment verified — your 1-Day Premium Pass is active! 🎉")
                st.balloons()
            else:
                st.error(
                    "Payment was verified but the subscription record couldn't be "
                    "updated. Please contact support with this Payment ID: "
                    f"`{payment_id}`."
                )
        else:
            st.error(
                "We couldn't verify this payment's signature, so no charge has "
                "been applied to your account. If money was deducted, contact "
                f"support with this reference: `{payment_id}`."
            )

    st.markdown(
        """
        <div class="app-hero">
            <h1>💳 Choice of Subscriptions</h1>
            <p>Unlock advanced static code inspection, bytecode deep search, and priority analysis for 24 hours.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(
            """
            <div style="border: 1px solid #CBD5E1; border-radius: 12px; padding: 24px; background-color: #F8FAFC; height: 100%;">
                <span style="background-color: #E2E8F0; color: #475569; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600;">BASIC</span>
                <h2 style="margin-top: 12px; margin-bottom: 4px; font-size: 28px;">Free Tier</h2>
                <h3 style="color: #64748B; margin-top: 0; font-weight: 500;">₹0 <span style="font-size: 14px;">/ forever</span></h3>
                <hr style="border-top: 1px solid #E2E8F0; margin: 16px 0;">
                <ul style="list-style-type: none; padding-left: 0; line-height: 1.8; color: #334155;">
                    <li>✅ <strong>1 Free Scan Limit</strong></li>
                    <li>✅ Standard Rules Engine</li>
                    <li>❌ Deep Bytecode Inspection</li>
                    <li>❌ PDF Assessment Reports</li>
                    <li>❌ Unlimited Scan History</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col2:
        st.markdown(
            """
            <div style="border: 2px solid #0D9488; border-radius: 12px; padding: 24px; background-color: #ECFDF9; height: 100%;">
                <span style="background-color: #0D9488; color: white; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600;">RECOMMENDED</span>
                <h2 style="margin-top: 12px; margin-bottom: 4px; font-size: 28px; color: #1E40AF;">1-Day Premium</h2>
                <h3 style="color: #0D9488; margin-top: 0; font-weight: 700;">₹59 / $5 <span style="font-size: 14px; font-weight: 400; color: #475569;">/ 24 hours</span></h3>
                <hr style="border-top: 1px solid #BFDBFE; margin: 16px 0;">
                <ul style="list-style-type: none; padding-left: 0; line-height: 1.8; color: #0B3B3A;">
                    <li>✨ <strong>Unlimited APK Scans</strong></li>
                    <li>✨ Deep DEX Bytecode Search</li>
                    <li>✨ Export Comprehensive PDF Reports</li>
                    <li>✨ Permanent Scan History Storage</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.write("")

    status = get_subscription_status(user["id"])
    if status["plan_tier"] == "pro" and status["expires_at"]:
        expires_local = datetime.fromisoformat(status["expires_at"]).astimezone()
        st.success(
            f"✅ Your 1-Day Premium Pass is active until "
            f"**{expires_local.strftime('%b %d, %I:%M %p %Z')}**."
        )
    else:
        if status["expired"]:
            st.warning("⏰ Your 1-Day Premium Pass has expired. Get another to keep unlimited scans.")
        st.subheader("⚡ Get 1-Day Premium")

        region = st.selectbox("Select Your Region", ["India (₹)", "International ($)"])
        if region == "India (₹)":
            price = PRICE_INR
            currency = "INR"
        else:
            price = PRICE_USD
            currency = "USD"

        if st.button("🚀 Get Premium", type="primary"):
            order = create_payment_order(price, currency)
            if order:
                st.session_state["active_order"] = order
                st.session_state["active_price"] = price
                st.session_state["active_currency"] = currency

    if "active_order" in st.session_state:
        order = st.session_state["active_order"]
        price = st.session_state.get("active_price", PRICE_INR)
        currency = st.session_state.get("active_currency", "INR")
        
        st.markdown("---")
        st.subheader("💳 Checkout securely via Razorpay")
        render_razorpay_checkout_button(order["id"], price, currency, user.get("email", ""))



def shannon_entropy(data: bytes) -> float:
    import math
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def compute_entropy_report(path: str, top: int = 15):
    """Per-entry Shannon entropy for files inside the APK (bits/byte, max 8.0)."""
    rows = []
    try:
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if info.is_dir() or info.file_size < 1024:
                    continue
                with z.open(info) as fh:
                    data = fh.read(2_000_000)  # cap per-file read for speed
                rows.append({"file": info.filename, "size_kb": round(info.file_size / 1024, 1),
                             "entropy": round(shannon_entropy(data), 3)})
    except Exception:
        return []
    return sorted(rows, key=lambda r: r["entropy"], reverse=True)[:top]


def kpi(label, value, sub=""):
    return (f'<div class="mas-kpi"><div class="k">{html.escape(str(label))}</div>'
            f'<div class="v">{html.escape(str(value))}</div><div class="s">{html.escape(str(sub))}</div></div>')


def render_topbar():
    dark = st.session_state.get("dark_mode", False)
    authed = st.session_state.get("authenticated")
    with st.container(key="topbar"):
        left, r1, r2, r3, r4 = st.columns([5.5, 1.4, 1.1, 1.1, 1.2], vertical_alignment="center")
        with left:
            st.markdown('<div class="tb-name">🛡️ APKSCAN Console</div>'
                        '<div class="tb-sub">Static mobile security • OWASP MASVS • triage</div>', unsafe_allow_html=True)
        with r1:
            if st.button("☀️ Light" if dark else "🌙 Dark", key="top_theme", use_container_width=True):
                st.session_state.dark_mode = not dark
                st.rerun()
        if not authed:
            with r2:
                if st.button("Log In", key="top_login", use_container_width=True):
                    auth_dialog(reason="")
            with r3:
                if st.button("Sign Up", key="top_signup", type="primary", use_container_width=True):
                    auth_dialog(reason="")
        else:
            user = st.session_state.get("user") or {}
            with r2:
                with st.popover("👤 " + (user.get("email", "User")[:1].upper()), use_container_width=True):
                    st.markdown(f"**{user.get('email', 'User')}**")
                    st.caption(f"Role: {str(user.get('role', 'user')).lower()}")
                    if st.button("🚪 Logout", key="profile_logout"):
                        st.session_state.authenticated = False
                        st.session_state.user = None
                        st.session_state.pop("last_scan", None)
                        st.rerun()
        with r4:
            with st.popover("☰ Menu", use_container_width=True):
                theme.picker()
                st.divider()
                for label in ["🔍 APK Scanner", "📜 Scan History", "⚡ Upgrade Pro"]:
                    if st.button(label, key=f"menu_{label}", use_container_width=True):
                        if label == "🔍 APK Scanner" or require_login("Log in to open this page."):
                            reset_workspace()
                            st.session_state.selected_page = label
                            st.rerun()


SOURCES = ["⬆ Direct Binary Upload", "▶ Google Play", "🍎 Apple App Store"]


def reset_workspace():
    """Clear scan results, resolved listing and search hits so nothing stale shows after navigating."""
    for k in ("last_scan", "resolved_listing", "Google Play_hits", "Apple App Store_hits", "pending_resolve"):
        st.session_state.pop(k, None)


def store_guard(key: str) -> bool:
    """Gate for resolving a store listing: sign-in first, then a scan credit (Free), unlimited for Pro/Admin."""
    if not st.session_state.get("authenticated"):
        auth_dialog(reason="Log in or create an account to resolve this app.")
        return False
    user = st.session_state.get("user") or {}
    if is_admin_user():
        return True
    paid = st.session_state.setdefault("resolved_paid", set())
    if key in paid:                                   # re-opening the same app doesn't cost another credit
        return True
    if not check_and_decrement_scan_limit(user["id"]):
        st.session_state.scan_error = "⚠️ You have used your free scan limit! Please upgrade to Pro to resolve and scan more apps."
        st.session_state.pending_redirect = "⚡ Upgrade Pro"
        st.rerun()
    paid.add(key)
    return True


def render_rail(source, authed, user):
    """Left rail: source picker, pipeline progress, plan status."""
    with st.container(key="rail"):
        st.markdown('<div class="rail-label">Source</div>', unsafe_allow_html=True)
        for label in SOURCES:
            if st.button(label, key=f"src_{label}", type="primary" if label == source else "secondary", use_container_width=True):
                if label != source:
                    reset_workspace()
                st.session_state.source_choice = label
                st.rerun()

        done = 0
        if st.session_state.get("resolved_listing"):
            done = 1
        if "last_scan" in st.session_state:
            done = 3
        if authed and "last_scan" in st.session_state:
            done = 4
        steps = ["Resolve or upload", "Static analysis", "Triage findings", "Export report"]
        rows = "".join(
            f'<div class="step {"done" if i < done else "now" if i == done else ""}"><div class="dot">{"✓" if i < done else i + 1}</div>{name}</div>'
            for i, name in enumerate(steps))
        st.markdown(f'<div class="rail-label" style="margin-top:18px">Pipeline</div>{rows}', unsafe_allow_html=True)

        st.markdown('<div class="rail-label" style="margin-top:18px">Access</div>', unsafe_allow_html=True)
        if not authed:
            st.caption("Guest — browse stores freely. Sign in to scan binaries and export reports.")
        elif is_admin_user():
            st.caption("👑 Admin — unlimited scans")
        else:
            try:
                plan = get_subscription_status(user["id"])
                if plan["plan_tier"] == "pro" and plan["expires_at"]:
                    st.caption(f"⭐ Premium until {datetime.fromisoformat(plan['expires_at']).astimezone().strftime('%I:%M %p')}")
                else:
                    st.caption("👤 Free plan — 1 scan")
            except Exception:
                st.caption("👤 Signed in")


def render_results(scan, authed):
    """Tabbed workspace: Overview / Findings / Component Map / Dependency SCA / Entropy / Reports."""
    result = scan["result"]
    n = len(result.findings) if scan else 0
    sev = {s: sum(1 for f in result.findings if f.severity == s) for s in ["high", "medium", "low", "info"]}
    col = {"High": "#DC2626", "Medium": "#F59E0B", "Low": "#16A34A"}.get(result.risk_level, "#0D9488")
    frac = max(0.04, min(result.risk_score / 40, 1.0)) * 360
    total = max(1, n)
    seg = "".join(f'<div style="width:{sev[k] / total * 100:.1f}%;background:{c}"></div>'
                  for k, c in [("high", "#DC2626"), ("medium", "#F59E0B"), ("low", "#0D9488"), ("info", "#94A3B8")])
    st.markdown(
        f'<div class="sumrow"><div class="ring" style="background:conic-gradient({col} {frac:.0f}deg, rgba(128,128,128,.25) 0)">'
        f'<div class="ring-in"><b>{result.risk_score}</b><span>{html.escape(result.risk_level)}</span></div></div>'
        f'<div><div style="font-size:20px;font-weight:800">{html.escape(result.app_name or scan["name"])}</div>'
        f'<div class="mas-sub">{html.escape(result.package_name or "unknown package")} • {n} findings</div>'
        f'<div class="sevbar">{seg}</div>'
        f'<div class="mas-sub">🔴 {sev["high"]} high &nbsp; 🟠 {sev["medium"]} medium &nbsp; 🟡 {sev["low"]} low &nbsp; 🔵 {sev["info"]} info</div></div></div>',
        unsafe_allow_html=True)
    tabs = st.tabs(["📈 Overview", f"🛡 Findings List ({n})", "🧩 Component Map", "📦 Dependency SCA",
                    "🔢 Shannon Entropy", "📄 Reports & Export 🔒 Auth Req" if not authed else "📄 Reports & Export"])

    with tabs[0]:
        sev_counts = {s: sum(1 for f in result.findings if f.severity == s) for s in ["high", "medium", "low", "info"]}
        st.markdown(f"### {html.escape(result.app_name or scan['name'])}", unsafe_allow_html=True)
        c = st.columns(4)
        c[0].markdown(kpi("Risk level", f"{RISK_COLOR.get(result.risk_level, '')} {result.risk_level}", f"Score {result.risk_score}"), unsafe_allow_html=True)
        c[1].markdown(kpi("Findings", n, f"{sev_counts['high']} high • {sev_counts['medium']} medium"), unsafe_allow_html=True)
        c[2].markdown(kpi("Package", result.package_name or "unknown", f"v{result.version_name or '?'} ({result.version_code or '?'})"), unsafe_allow_html=True)
        c[3].markdown(kpi("SDK", f"{result.min_sdk or '?'} → {result.target_sdk or '?'}", "min → target"), unsafe_allow_html=True)
        st.write("")
        flags = st.columns(3)
        flags[0].markdown(kpi("Debuggable", "Yes ⚠️" if result.is_debuggable else "No ✅"), unsafe_allow_html=True)
        flags[1].markdown(kpi("Allow backup", "Yes ⚠️" if result.allows_backup else "No ✅"), unsafe_allow_html=True)
        flags[2].markdown(kpi("Cleartext traffic", "Yes ⚠️" if result.uses_cleartext_traffic else "No ✅"), unsafe_allow_html=True)
        st.caption(f"SHA-256: `{result.sha256}`")
        if result.cert_info:
            with st.expander("Signing certificate"):
                st.json(result.cert_info)
        with st.expander(f"Permissions ({len(result.permissions)})"):
            for p in sorted(result.permissions):
                short = p.split(".")[-1]
                st.markdown(f"🔴 **{short}** — {DANGEROUS_PERMISSIONS[p]}" if p in DANGEROUS_PERMISSIONS else f"⚪ {short}")

    with tabs[1]:
        if not result.findings:
            st.success("No issues flagged.")
        for f in result.ranked_findings():
            with st.expander(f"{SEVERITY_COLOR.get(f.severity, '')} [{f.priority_score}] {f.category}: {f.title}"):
                st.write(f.detail)
                if f.evidence:
                    st.json(f.evidence)

    with tabs[2]:
        comps = result.exported_components
        st.markdown(f"**{len(comps)} exported component(s)** reachable by other apps without a permission guard.")
        if comps:
            st.dataframe(comps, use_container_width=True, hide_index=True)
        else:
            st.success("No unprotected exported components found.")
        if result.urls_found or result.ips_found:
            with st.expander(f"Network endpoints ({len(result.urls_found)} URLs, {len(result.ips_found)} IPs)"):
                st.write(sorted(set(result.urls_found))[:200])
                st.write(sorted(set(result.ips_found))[:100])

    with tabs[3]:
        st.caption("Bundled native libraries inventoried from the APK (inventory only — native code is not disassembled).")
        if result.native_libs:
            st.dataframe(result.native_libs, use_container_width=True, hide_index=True)
        else:
            st.info("No native (.so) libraries bundled.")
        sdk_findings = [f for f in result.findings if "librar" in f.category.lower() or "sdk" in f.title.lower()]
        for f in sdk_findings:
            st.markdown(f"{SEVERITY_COLOR.get(f.severity, '')} **{f.title}** — {f.detail}")

    with tabs[4]:
        st.caption("Shannon entropy in bits/byte (max 8.0). Values above ~7.2 suggest packed, encrypted or compressed content.")
        rows = scan.get("entropy") or []
        if not rows:
            st.info("Entropy data isn't available for this scan.")
        for r in rows:
            color = "#DC2626" if r["entropy"] >= 7.5 else "#F59E0B" if r["entropy"] >= 7.2 else theme.tint("#0D9488")
            st.markdown(
                f"<div style='display:flex;justify-content:space-between;font-size:13px'><span style='font-family:JetBrains Mono,monospace'>{html.escape(r['file'])}</span>"
                f"<b>{r['entropy']:.2f}</b></div><div class='mas-bar'><div style='width:{r['entropy']/8*100:.0f}%;background:{color}'></div></div><div style='height:8px'></div>",
                unsafe_allow_html=True)

    with tabs[5]:
        if not authed:
            st.markdown('<div class="mas-lock"><b>🔒 Sign in to export reports</b><p>Download the full PDF assessment and keep it in your scan history.</p></div>', unsafe_allow_html=True)
            if st.button("Sign In to Access Reports", type="primary", key="lock_signin"):
                auth_dialog(reason="")
        else:
            st.download_button("📥 Download Full Report (PDF)", data=build_pdf_report(result, scan["name"]),
                               file_name=f"{os.path.splitext(scan['name'])[0]}_security_report.pdf", mime="application/pdf")
            st.markdown("**Go beyond the initial scan with Pro** — more scan capacity and deeper bytecode analysis.")
            if st.button("⚡ Explore Pro", key="scan_result_upgrade"):
                st.session_state.pending_redirect = "⚡ Upgrade Pro"
                st.rerun()


def render_empty_workspace(authed):
    tiles = [("🛡", "Findings, ranked", "Manifest, certificate, crypto and code-pattern issues ordered by priority."),
             ("🧩", "Component map", "Exported activities, services, receivers and providers reachable by other apps."),
             ("📦", "Dependency inventory", "Bundled native libraries grouped by architecture."),
             ("🔢", "Entropy heat-check", "Spot packed, encrypted or obfuscated files inside the package.")]
    st.markdown('<div class="rail-label">What your report includes</div><div class="tiles">' + "".join(
        f'<div class="tile"><div class="ic">{i}</div><b>{t}</b><p>{d}</p></div>' for i, t, d in tiles) + '</div>', unsafe_allow_html=True)
    if not authed:
        c1, c2, _ = st.columns([1.4, 1.1, 2])
        with c1:
            if st.button("🔑 Sign in to unlock reports", type="primary", key="empty_signin", use_container_width=True):
                auth_dialog(reason="")
        with c2:
            if st.button("✨ Create account", key="empty_signup", use_container_width=True):
                auth_dialog(reason="")


def run_scan(apk_paths, display_name, deep_scan, user, cleanup_path):
    if user and not is_admin_user():
        if not check_and_decrement_scan_limit(user["id"]):
            st.session_state.scan_error = "⚠️ You have used your 1 free scan limit! Please upgrade to Pro to run unlimited scans."
            st.session_state.pending_redirect = "⚡ Upgrade Pro"
            st.rerun()
    with st.spinner("Running analysis..."):
        try:
            apk_path = apk_paths[0]
            for apk_path in apk_paths:
                apk_name = display_name or os.path.basename(apk_path)
                result = analyze_apk(apk_path, apk_name)
                if deep_scan:
                    run_deep_bytecode_analysis(apk_path, result)
                entropy = compute_entropy_report(apk_path)
                if user and "id" in user:
                    save_scan_report(user_id=user["id"], file_name=apk_name, sha256=result.sha256,
                                     risk_level=result.risk_level, risk_score=result.risk_score,
                                     findings_count=len(result.findings), report_json=dataclasses.asdict(result))
                st.session_state["last_scan"] = {"result": result, "name": apk_name, "entropy": entropy}
        except Exception as e:
            st.error(f"Analysis failed: {e}")
            st.code(traceback.format_exc())
        finally:
            if cleanup_path and os.path.exists(cleanup_path):
                os.remove(cleanup_path)


def main():
    theme.install_markdown_hook()
    if "dark_mode" not in st.session_state:
        st.session_state.dark_mode = False
    inject_custom_css()
    inject_mas_css(st.session_state.dark_mode)
    init_db()
    st.session_state.setdefault("authenticated", False)
    st.session_state.setdefault("user", None)

    render_topbar()
    _handle_verify_link()
    st.caption("UI build r8 · clean navigation")

    authed = st.session_state.authenticated
    user = st.session_state.get("user")

    # Sub-pages (signed-in only)
    if "pending_redirect" in st.session_state:
        st.session_state.selected_page = st.session_state.pop("pending_redirect")
    page = st.session_state.get("selected_page", "🔍 APK Scanner")
    if page != "🔍 APK Scanner":
        if not authed:
            st.session_state.selected_page = "🔍 APK Scanner"
            st.rerun()
        if page == "📜 Scan History":
            render_history_page(user["id"])
        else:
            render_pricing_page(user)
        return

    if "pending_source" in st.session_state:
        st.session_state.source_choice = st.session_state.pop("pending_source")
    source = st.session_state.setdefault("source_choice", SOURCES[0])
    if source not in SOURCES:
        source = st.session_state.source_choice = SOURCES[0]

    rail_col, main_col = st.columns([1, 3.3], gap="large")
    with rail_col:
        render_rail(source, authed, user)

    with main_col:
        titles = {SOURCES[0]: ("Direct Binary Upload", "Upload an APK or ZIP you are authorised to test for manifest, certificate, DEX, component and entropy analysis."),
                  SOURCES[1]: ("Google Play Resolver", "Search by name, package ID or Play URL. Reads public listing data, permission declarations and risk signals."),
                  SOURCES[2]: ("App Store Resolver", "Search by name, store URL or numeric ID. Reads public listing data and risk signals.")}
        t, sub = titles[source]
        st.markdown(f'<div class="hero2"><div class="t">{t}</div><div class="s">{sub}</div>'
                    f'<div class="chips"><span>STATIC ONLY</span><span>NOTHING EXECUTED</span><span>MASVS-ALIGNED</span><span>MAX {MAX_UPLOAD_MB} MB</span></div></div>',
                    unsafe_allow_html=True)

        if source != SOURCES[0]:
            platform = "Google Play" if "Google" in source else "Apple App Store"
            shown = store_ui.render_store_finder(
                platform, authed,
                open_auth=lambda: auth_dialog(reason=""),
                go_upload=lambda: (reset_workspace(), st.session_state.__setitem__("pending_source", SOURCES[0]), st.rerun()),
                guard=store_guard,
            )
            if not shown:
                render_empty_workspace(authed)
            return

        # ---- Direct binary upload ----
        tmp_path, display_name, apk_paths = None, None, []
        if not authed:
            st.markdown(f'<div class="mas-drop"><b>📦 Drop an APK / ZIP here</b><div>Maximum upload size: {MAX_UPLOAD_MB} MB • Sign-in is required to run a scan</div></div>', unsafe_allow_html=True)
            _, ub, _ = st.columns([1.5, 2, 1.5])
            with ub:
                if st.button("📦 Upload APK / ZIP", type="primary", key="landing_upload_cta", use_container_width=True):
                    auth_dialog(reason="Please log in or create an account to upload an APK and view your scan report.")
        else:
            uploaded = st.file_uploader("Upload an APK or ZIP file", type=["apk", "zip"], label_visibility="collapsed")
            if uploaded is not None:
                if uploaded.size / (1024 * 1024) > MAX_UPLOAD_MB:
                    st.error(f"File exceeds limit of {MAX_UPLOAD_MB} MB.")
                    return
                with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
                    tmp.write(uploaded.getbuffer())
                    tmp_path = tmp.name
                display_name = uploaded.name
                if uploaded.name.lower().endswith(".zip"):
                    try:
                        apk_paths = extract_apks_from_zip(tmp_path)
                    except zipfile.BadZipFile:
                        st.error("Invalid ZIP file.")
                        return
                else:
                    apk_paths = [tmp_path]
            deep_scan = st.checkbox("Also run deep bytecode analysis (slower)", value=False)
            if tmp_path and st.button("Start Scan", type="primary"):
                if require_login():
                    run_scan(apk_paths, display_name, deep_scan, user, tmp_path)

        st.write("")
        if "last_scan" in st.session_state:
            render_results(st.session_state["last_scan"], authed)
        else:
            render_empty_workspace(authed)


if __name__ == "__main__":
    main()

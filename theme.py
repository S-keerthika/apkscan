"""theme.py — one place to change the app's colours.

Add or edit a preset in PRESETS (name -> accent hex), or use the custom colour picker in the ☰ Menu.
Every other shade (dark header, tints, light/dark surfaces) is derived from the accent automatically.
"""
import colorsys
import re

import streamlit as st

PRESETS = {
    "Violet":  "#7C3AED",
    "Sunset":  "#EA580C",
    "Rose":    "#E11D48",
    "Emerald": "#059669",
    "Indigo":  "#4F46E5",
    "Ocean":   "#0284C7",
    "Slate":   "#475569",
    "Teal":    "#0D9488",
}
DEFAULT = "Violet"


def _hsl(hex_color, s=None, l=None, ds=1.0):
    hex_color = hex_color.lstrip("#")
    r, g, b = (int(hex_color[i:i + 2], 16) / 255 for i in (0, 2, 4))
    h, li, sa = colorsys.rgb_to_hls(r, g, b)
    li = li if l is None else l
    sa = min(1.0, (sa if s is None else s) * ds)
    r, g, b = colorsys.hls_to_rgb(h, li, sa)
    return "#%02X%02X%02X" % (round(r * 255), round(g * 255), round(b * 255))


def current_accent() -> str:
    name = st.session_state.get("theme_name", DEFAULT)
    if name == "Custom":
        return st.session_state.get("theme_custom", PRESETS[DEFAULT])
    return PRESETS.get(name, PRESETS[DEFAULT])


def shades(accent: str) -> dict:
    return {
        "accent": accent,
        "accent_dark": _hsl(accent, l=0.32 if _lum(accent) > 0.32 else None) if _lum(accent) > 0.32 else _hsl(accent, l=_lum(accent) * 0.8),
        "deep": _hsl(accent, s=0.6, l=0.14),
        "deep2": _hsl(accent, s=0.55, l=0.22),
        "deep3": _hsl(accent, s=0.45, l=0.28),
        "light": _hsl(accent, s=0.9, l=0.72),
        "tint": _hsl(accent, s=0.7, l=0.96),
        "tint2": _hsl(accent, s=0.8, l=0.9),
    }


def _lum(hex_color):
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
    return colorsys.rgb_to_hls(r, g, b)[1]


def palette(dark: bool) -> dict:
    a = current_accent()
    s = shades(a)
    if dark:
        return dict(bg=_hsl(a, s=0.4, l=0.06), card=_hsl(a, s=0.35, l=0.1), border=_hsl(a, s=0.3, l=0.2),
                    text=_hsl(a, s=0.3, l=0.94), sub=_hsl(a, s=0.15, l=0.68), soft=_hsl(a, s=0.35, l=0.14),
                    tag=_hsl(a, s=0.4, l=0.18), tagtxt=s["light"])
    return dict(bg=_hsl(a, s=0.35, l=0.965), card="#FFFFFF", border=_hsl(a, s=0.3, l=0.88),
                text=_hsl(a, s=0.4, l=0.1), sub=_hsl(a, s=0.15, l=0.4), soft=_hsl(a, s=0.5, l=0.95),
                tag=_hsl(a, s=0.6, l=0.91), tagtxt=s["accent_dark"])


# The original teal constants used while building the UI -> theme shade that replaces them.
_MAP = {"#0D9488": "accent", "#0F766E": "accent_dark", "#0B3B3A": "deep", "#115E59": "deep2",
        "#1F5F5A": "deep3", "#5EEAD4": "light", "#ECFDF9": "tint", "#CCFBF1": "tint2", "#ECFEFF": "tint"}
_HEX = re.compile("|".join(re.escape(k) for k in _MAP), re.I)
_RGBA = re.compile(r"rgba\(\s*13\s*,\s*148\s*,\s*136", re.I)


def tint(text: str) -> str:
    """Swap the built-in colour constants in a CSS/HTML string for the active theme's shades."""
    a = current_accent()
    sh = shades(a)
    r, g, b = (int(a.lstrip("#")[i:i + 2], 16) for i in (0, 2, 4))
    text = _RGBA.sub(f"rgba({r},{g},{b}", text)
    text = _HEX.sub(lambda m: sh[_MAP[m.group(0).upper()]], text)
    # glow colours written as 8-digit hex (#0d948830 / #0f766ea8)
    text = re.sub(r"#0d9488([0-9a-f]{2})", lambda m: a + m.group(1), text, flags=re.I)
    text = re.sub(r"#0f766e([0-9a-f]{2})", lambda m: sh["accent_dark"] + m.group(1), text, flags=re.I)
    return text


def install_markdown_hook():
    """Route every unsafe_allow_html markdown through tint() so all existing CSS follows the theme."""
    if getattr(st.markdown, "_themed", False):
        return
    original = st.markdown

    def themed(body, *args, **kwargs):
        if isinstance(body, str) and kwargs.get("unsafe_allow_html"):
            body = tint(body)
        return original(body, *args, **kwargs)

    themed._themed = True
    st.markdown = themed


def picker():
    """Colour controls for the ☰ Menu popover."""
    names = list(PRESETS) + ["Custom"]
    cur = st.session_state.get("theme_name", DEFAULT)
    choice = st.selectbox("🎨 Accent colour", names, index=names.index(cur) if cur in names else 0, key="theme_select")
    changed = choice != cur
    if choice == "Custom":
        col = st.color_picker("Pick a colour", value=st.session_state.get("theme_custom", PRESETS[DEFAULT]), key="theme_picker")
        if col != st.session_state.get("theme_custom"):
            st.session_state["theme_custom"] = col
            changed = True
    if changed:
        st.session_state["theme_name"] = choice
        st.rerun()

"""
apk_analyzer.py

Static analysis engine for APK files. Performs read-only inspection —
no execution of the APK, no dynamic/sandbox analysis. Designed to be
run against untrusted files, so keep this process isolated (separate
container/venv, resource limits) once you move past local testing.
"""
import zipfile
import os
import shutil
import re
import tempfile 
import hashlib
from importlib.resources import path
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any
from unittest import result

from androguard.core.apk import APK

# androguard logs very verbosely via loguru by default — silence it so the
# Streamlit app isn't flooded with debug output on every scan.
try:
    from loguru import logger as _loguru_logger
    _loguru_logger.remove()
except Exception:
    pass

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"



# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS": "Can send SMS silently (premium-rate fraud, OTP theft)",
    "android.permission.RECEIVE_SMS": "Can intercept incoming SMS (OTP/2FA theft)",
    "android.permission.READ_SMS": "Can read SMS history",
    "android.permission.CALL_PHONE": "Can place calls without user interaction",
    "android.permission.RECEIVE_BOOT_COMPLETED": "Can auto-start on device boot (persistence)",
    "android.permission.SYSTEM_ALERT_WINDOW": "Can draw over other apps (overlay/phishing attacks)",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Can abuse Accessibility Service (screen reading, auto-click — common banking-trojan technique)",
    "android.permission.BIND_DEVICE_ADMIN": "Can request device admin rights (hard to uninstall, lock device)",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Can install other APKs (dropper behavior)",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Broad file write access",
    "android.permission.READ_CONTACTS": "Can exfiltrate contact list",
    "android.permission.RECORD_AUDIO": "Can record audio",
    "android.permission.CAMERA": "Can access camera",
    "android.permission.ACCESS_FINE_LOCATION": "Can track precise location",
    "android.permission.READ_CALL_LOG": "Can read call history",
    "android.permission.PACKAGE_USAGE_STATS": "Can monitor which apps user is running",
}

# Combinations that are individually normal but jointly suspicious
RISKY_COMBOS = [
    (
        {"android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.SYSTEM_ALERT_WINDOW"},
        "Auto-start + draw-over-other-apps: classic overlay/phishing malware pattern",
    ),
    (
        {"android.permission.RECEIVE_SMS", "android.permission.READ_SMS", "android.permission.INTERNET"},
        "SMS read/intercept + network access: classic OTP/2FA-theft exfiltration pattern",
    ),
    (
        {"android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SYSTEM_ALERT_WINDOW"},
        "Accessibility abuse + overlay: common banking-trojan combo",
    ),
]

# Suspicious API / string patterns to grep for in decompiled DEX strings.
# These are PRESENCE checks: finding the API means "this code path exists,
# go look at it" — not a positive proof of exploitability. Kept intentionally
# broad (aligned to the OWASP MASVS / MSTG-style checklist) since the goal
# is to not silently miss a category, at the cost of some false positives
# that need human triage.
SUSPICIOUS_CODE_PATTERNS = [
    (r"DexClassLoader", "low",
     "Dynamic code loading (can load code not present at install time). Capped at low: "
     "needs an untrusted/attacker-controlled code source to actually be dangerous, which "
     "bare presence doesn't establish — plenty of legitimate apps use this for plugins/"
     "multidex."),
    (r"PathClassLoader", "low",
     "Dynamic code loading. Same reasoning as DexClassLoader — capped at low pending an "
     "established untrusted source."),
    (r"loadLibrary", "info",
     "Loads native (.so) libraries — worth reviewing what they do, but this is a routine "
     "API used by a large fraction of real apps for entirely benign reasons."),
    (r"getSubscriberId", "low",
     "Reads SIM subscriber ID (IMSI). Reading the value alone isn't a vulnerability — "
     "matters only if it's exfiltrated or misused, which this check doesn't establish."),
    (r"sendTextMessage", "medium",
     "Sends SMS from code (possible premium-rate fraud). Kept above the other bare-"
     "presence findings in this list: unlike reading a value, this is a capability with "
     "direct financial-harm potential if the destination number is attacker-influenced."),
]

URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Known hardcoded-secret shapes worth flagging outright
SECRET_PATTERNS = {
    r"AKIA[0-9A-Z]{16}": "AWS Access Key ID",
    r"AIza[0-9A-Za-z\-_]{35}": "Google API key",
    r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----": "Embedded private key (PEM)",
    r"xox[baprs]-[0-9A-Za-z-]{10,}": "Slack token",
    r"ghp_[0-9A-Za-z]{36}": "GitHub personal access token",
}

# ---------------------------------------------------------------------------
# Deep code-level checks (each maps to one row of a MASVS/PIVAA-style
# mobile-app checklist). Each entry: (regex, category, severity, title, detail)
# Matching is done against the raw printable-string dump of the DEX(es), so
# these are detecting the presence of API/method-name strings in the
# compiled code, which is how the DEX constant pool stores class/method
# references even after basic (non-string-encrypting) obfuscation.
# ---------------------------------------------------------------------------

DEEP_CODE_CHECKS = [
    # --- Crypto -------------------------------------------------------------
    # Calibration note: severities below were recalibrated against an
    # explicit review table (not ad-hoc). Bare API/string PRESENCE without
    # confirmed usage context is capped at low/info — "the API exists" does
    # not establish impact. Strong, purpose-built, unambiguous signals (ECB/
    # DES/RC4 as literal cipher-transformation tokens; ALLOW_ALL_HOSTNAME_
    # VERIFIER) stay higher since there's no ambiguous "maybe it's fine"
    # reading of them the way there is for e.g. a bare SecretKeySpec
    # construction (which is often built correctly with a random key).
    
    (r"\bDES\b", "Weak encryption", "medium",
     "DES cipher string found",
     "DES has a 56-bit effective key and is brute-forceable on commodity hardware today. "
     "Verify this is a Cipher transformation string and not an unrelated identifier — "
     "bare presence capped at medium pending that confirmation."),
    (r"\bRC4\b", "Weak encryption", "medium",
     "RC4 stream cipher string found",
     "RC4 has known keystream biases and is considered broken; avoid for new code. Bare "
     "presence capped at medium pending confirmation this is an actual cipher call."),
    (r"IvParameterSpec", "Weak initialization vector", "low",
     "IvParameterSpec construction found",
     "Constructor presence alone isn't a vulnerability — manually verify the IV is "
     "generated fresh per-encryption via SecureRandom, not a hardcoded/static byte array. "
     "If a hardcoded IV is confirmed (see the deep-scan byte-array trace), that's a "
     "stronger, separately-reported finding."),
    (r"SecretKeySpec", "Hardcoded encryption keys", "low",
     "SecretKeySpec construction found",
     "Constructor presence alone isn't a vulnerability — most SecretKeySpec calls use a "
     "properly random key. Manually verify the key material isn't a hardcoded literal. If "
     "a hardcoded key is confirmed (see the deep-scan byte-array/string-correlation "
     "trace), that's a stronger, separately-reported finding."),
    (r"\bMD5\b", "Weak hashing", "low",
     "MD5 string found (likely MessageDigest.getInstance(\"MD5\"))",
     "MD5 is cryptographically broken (collision attacks) — fine for checksums, unsafe for "
     "passwords/integrity/security purposes. Severity depends entirely on what it's used "
     "for, which this presence check can't establish."),
    (r"SHA-?1\b", "Weak hashing", "low",
     "SHA-1 string found",
     "SHA-1 is deprecated for security-sensitive use due to practical collision attacks. "
     "Severity depends on use."),
    (r"Ljava/util/Random;", "Predictable RNG", "low",
     "java.util.Random type reference found",
     "java.util.Random is a deterministic PRNG, predictable if the seed is known/guessable. "
     "This is only a real problem if used for tokens/keys/nonces — most Random usage in "
     "real apps is for UI/game logic, not security. High only if confirmed used for a "
     "security-sensitive value."),

    # --- Network / TLS -------------------------------------------------------
    (r"ALLOW_ALL_HOSTNAME_VERIFIER", "MITM / hostname verification", "high",
     "ALLOW_ALL_HOSTNAME_VERIFIER referenced",
     "This constant disables hostname verification entirely — allows MITM even over TLS. "
     "Kept high (unlike other bare-presence findings here) because there's no benign "
     "reading of this specific constant's presence — it exists to disable a security check."),
    (r"checkServerTrusted", "MITM / hostname verification", "low",
     "Custom TrustManager.checkServerTrusted found",
     "Method presence alone isn't a vulnerability — most custom TrustManagers validate "
     "correctly. Manually verify this method actually validates the chain rather than "
     "returning immediately. If confirmed to accept all certificates (see the deep-scan "
     "method-body trace), that's a stronger, separately-reported 'Untrusted CA' finding."),
    (r"onReceivedSslError", "Self-signed CA in WebView", "medium",
     "WebViewClient.onReceivedSslError override found",
     "Override presence alone isn't a vulnerability — it may correctly call cancel(). "
     "Manually verify, or check the deep-scan method-body trace which distinguishes "
     "proceed() (high) from cancel() (low, correct behavior) when it can resolve this."),
    # (r"setHostnameVerifier", "MITM / hostname verification", "low",
    #  "Custom HostnameVerifier set",
    #  "Manually verify it doesn't unconditionally return true."),

    # --- WebView --------------------------------------------------------------
    # (r"setJavaScriptEnabled", "JavaScript enabled in WebView", "low",
    #  "WebView JavaScript execution enabled",
    #  "Normal WebView behavior for most apps that use WebView at all — only a real concern "
    #  "combined with loading remote/untrusted URLs and/or a JS-bridge (addJavascriptInterface)."),
    # (r"\bloadUrl\b", "Remote URL in WebView", "info",
    #  "WebView.loadUrl call found",
    #  "Normal WebView operation. Only worth a look if the URL is attacker-influenced "
    #  "(external Intent data, deep link) rather than a hardcoded/app-controlled URL."),
    (r"addJavascriptInterface",
    "WebView JavaScript bridge",
    "low",
    "addJavascriptInterface reference found",
    "Heuristic match only. Deep bytecode analysis is required to determine "
    "whether the application actually registers a JavaScript bridge and whether "
    "the associated WebView loads untrusted or remote content."),
    # (r"setAllowFileAccess|setAllowUniversalAccessFromFileURLs", "Path traversal", "low",
    #  "WebView file access setting found",
    #  "Setting presence alone doesn't establish traversal — broad file:// access from a "
    #  "WebView that ALSO loads remote content can enable local file exfiltration via "
    #  "crafted pages, but that combination isn't confirmed by this check alone."),
    (r"setPluginState", "Deprecated setPluginState", "low",
     "Deprecated WebView.setPluginState API used",
     "This API is deprecated; if it's enabling plugin content, review whether it's still needed."),

    # --- Data storage / IPC ----------------------------------------------------
    (r"MODE_WORLD_READABLE", "World-readable/writable files", "medium",
     "MODE_WORLD_READABLE used for file creation",
     "Any app on the device can read this file's contents — deprecated and removed on "
     "modern Android for good reason. Severity depends on what's actually stored there, "
     "which this check doesn't establish."),
    (r"MODE_WORLD_WRITEABLE", "World-readable/writable files", "medium",
     "MODE_WORLD_WRITEABLE used for file creation",
     "Any app on the device can write/tamper with this file. Severity depends on what's "
     "actually written/read there, which this check doesn't establish."),
    (r"ObjectInputStream", "Object deserialization", "low",
     "ObjectInputStream usage found",
     "Usage presence alone isn't a vulnerability — needs an attacker-controlled serialized "
     "input to actually be exploitable, which this check doesn't establish. Deserializing "
     "data from an untrusted source with Java's native serialization is a known RCE/"
     "gadget-chain vector if that precondition holds."),
    (r"\brawQuery\b", "User input in SQL queries", "low",
     "SQLiteDatabase.rawQuery reference found",
     "API presence alone proves nothing — rawQuery bypasses parameterized-query safety "
     "only if the query string is built via concatenation with attacker-controlled input, "
     "neither of which this check establishes. See the deep-scan StringBuilder-correlation "
     "trace for a stronger, more specific finding."),
    (r"\bexecSQL\b", "User input in SQL queries", "low",
     "SQLiteDatabase.execSQL reference found",
     "API presence alone proves nothing — execSQL is a real SQL-injection vector only if "
     "it concatenates attacker-controlled input, which this check doesn't establish."),
    (r"\bcreateTempFile\b", "Temporary files", "info",
     "File.createTempFile usage found",
     "Normal API. Verify temp files containing sensitive data are created with restrictive "
     "permissions and cleaned up."),
    (r"\.\./", "Path traversal", "info",
     "Literal '../' path-traversal sequence found in strings",
     "A string occurrence isn't path traversal by itself — this is very often a harmless "
     "comment, URL fragment, or unrelated relative-path reference. Only worth investigating "
     "if it's used in file-path construction from external input."),

    # --- SQLite -----------------------------------------------------------------
    (r"SQLiteOpenHelper", "Cleartext SQLite", "info",
     "SQLiteOpenHelper (standard, unencrypted SQLite) in use",
     "Normal database usage for most Android apps. Standard SQLite databases are stored "
     "unencrypted on disk — only worth escalating if this specific database holds "
     "sensitive data, which this check doesn't establish."),
]

# Correlation checks: flagged only when multiple independent tokens co-occur,
# since compiled bytecode stores class names / method names / literals as
# separate constant-pool entries rather than as contiguous source text.
CORRELATION_CHECKS = [
    (["Ljava/lang/Runtime;", "exec"], "Banned APIs", "medium",
     "Runtime.exec reference found",
     "Both the Runtime type and an 'exec' method name are referenced. Common real-world "
     "cause: root-detection checks like `Runtime.getRuntime().exec(new String[]{\"which\", "
     "\"su\"})` with hardcoded, non-attacker-controlled arguments — confirmed as the actual "
     "cause in a real test app, hence 'medium' rather than 'high' by default. Still worth "
     "checking whether any argument to exec() is built from external/user input, which "
     "would make this a real command-injection risk."),
    (["SSLSocketFactory", "getInsecure"], "MITM / hostname verification", "high",
     "Insecure SSLSocketFactory reference found",
     "Both 'SSLSocketFactory' and 'getInsecure' are referenced — this pairing is commonly "
     "used to disable certificate validation entirely."),
    (["Landroid/telephony/TelephonyManager;", "getDeviceId"], "Code patterns", "low",
     "TelephonyManager.getDeviceId reference found",
     "Reads device IMEI — fingerprinting/tracking, but reading a device identifier alone "
     "isn't a vulnerability any more than a declared permission is on its own (same "
     "'API/data alone proves nothing without knowing where it goes' logic). Requiring "
     "TelephonyManager co-occurrence specifically to avoid a confirmed false positive: a "
     "bare 'getDeviceId' token match also fires on the unrelated "
     "android.view.KeyEvent.getDeviceId() (an input-device ID for key/controller events, "
     "nothing to do with IMEI) and on bundled Google Play Services classes."),
]




# ---------------------------------------------------------------------------
# Result containers
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    category: str
    severity: str  # "info" | "low" | "medium" | "high"  — IMPACT if this is real
    title: str
    detail: str
    confidence: str = "heuristic"  # "confirmed" (structural/manifest fact or bytecode-traced) | "heuristic" (string/pattern presence)
    evidence: Dict[str, Any] = field(default_factory=dict)  # structured facts (class/method names, byte offsets, hex, xref counts) — the "proof record", separate from the human-readable detail prose
    priority_score: int = 0  # Risk Engine output: confidence x impact, used to RANK findings — computed in ScanResult.add(), not by the caller

    def __post_init__(self):
        self.priority_score = _compute_priority_score(self.severity, self.confidence)


# Risk Engine: combines IMPACT (severity) and CONFIDENCE into one ranking
# number. A "high" heuristic finding (unconfirmed, could be library noise)
# is deliberately ranked BELOW a "medium" confirmed finding (bytecode-traced
# or a direct manifest/cert fact) — confidence matters as much as raw
# severity for "what should a human look at first," which is the actual
# question priority ranking needs to answer.
_IMPACT_WEIGHT = {"high": 30, "medium": 20, "low": 10, "info": 0}
_CONFIDENCE_MULT = {
    "confirmed": 1.0,
    "high": 0.75,
    "medium": 0.50,
    "low": 0.25,
    "heuristic": 0.10,
}


def _compute_priority_score(severity: str, confidence: str) -> int:
    return round(_IMPACT_WEIGHT.get(severity, 0) * _CONFIDENCE_MULT.get(confidence, 1.0))


@dataclass
class ScanResult:
    file_name: str
    sha256: str
    package_name: str = ""
    app_name: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    is_debuggable: bool = False
    allows_backup: bool = False
    uses_cleartext_traffic: bool = False
    permissions: List[str] = field(default_factory=list)
    exported_components: List[Dict[str, str]] = field(default_factory=list)
    cert_info: Dict[str, Any] = field(default_factory=dict)
    urls_found: List[str] = field(default_factory=list)
    ips_found: List[str] = field(default_factory=list)
    native_libs: List[Dict[str, str]] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "Low"

    def add(
        self,
        category: str,
        severity: str,
        title: str,
        detail: str,
        confidence: str = "heuristic",
        evidence: Dict[str, Any] = None,
    ):
        """
        Add a finding.

        If the detector did not provide structured evidence, automatically
        create a basic evidence record so every finding has a Proof / Evidence
        section in the UI.

        IMPORTANT:
        This fallback does NOT invent bytecode instructions or source lines.
        Exact bytecode proof should still be supplied by deep detectors when
        available.
        """

        # ------------------------------------------------------------
        # Use detector-provided evidence when available
        # ------------------------------------------------------------
        if evidence:
            final_evidence = dict(evidence)

        else:
            # --------------------------------------------------------
            # Automatic fallback evidence
            # --------------------------------------------------------
            final_evidence = {
                "type": "detector evidence",
                "file": self.file_name,
                "category": category,
                "severity": severity,
                "confidence": confidence,
                "finding": title,
                "description": detail,
            }

            # --------------------------------------------------------
            # Manifest evidence
            # --------------------------------------------------------
            if category == "Manifest":

                if "debuggable" in title.lower():
                    final_evidence.update({
                        "evidence_type": "AndroidManifest.xml",
                        "manifest_attribute": "android:debuggable",
                        "manifest_value": "true",
                        "proof": (
                            'AndroidManifest.xml contains '
                            'android:debuggable="true".'
                        ),
                    })

                elif "allowbackup" in title.lower():
                    final_evidence.update({
                        "evidence_type": "AndroidManifest.xml",
                        "manifest_attribute": "android:allowBackup",
                        "manifest_value": "true",
                        "proof": (
                            'AndroidManifest.xml contains '
                            'android:allowBackup="true".'
                        ),
                    })

            # --------------------------------------------------------
            # Network cleartext evidence
            # --------------------------------------------------------
            elif category == "Network":

                if "cleartext" in title.lower():
                    final_evidence.update({
                        "evidence_type": "AndroidManifest.xml",
                        "manifest_attribute": (
                            "android:usesCleartextTraffic"
                        ),
                        "manifest_value": "true",
                        "proof": (
                            'AndroidManifest.xml allows cleartext network '
                            'traffic through android:usesCleartextTraffic="true".'
                        ),
                    })

            # --------------------------------------------------------
            # Permission evidence
            # --------------------------------------------------------
            elif category == "Permissions":

                permission_name = title.split(":")[-1].strip()

                final_evidence.update({
                    "evidence_type": "AndroidManifest.xml",
                    "permission": permission_name,
                    "proof": (
                        f"AndroidManifest.xml declares the permission "
                        f"{permission_name}."
                    ),
                })

            # --------------------------------------------------------
            # Signing evidence
            # --------------------------------------------------------
            elif category == "Signing":

                if self.cert_info:
                    final_evidence.update({
                        "evidence_type": "APK certificate",
                        "certificate": self.cert_info,
                        "proof": (
                            "Finding is based on the certificate metadata "
                            "extracted from the APK."
                        ),
                    })
                else:
                    final_evidence.update({
                        "evidence_type": "APK signing metadata",
                        "proof": (
                            "Finding is based on APK signing/certificate "
                            "analysis."
                        ),
                    })

            # --------------------------------------------------------
            # Attack-surface evidence
            # --------------------------------------------------------
            elif category == "Attack surface":

                components = self.exported_components or []

                final_evidence.update({
                    "evidence_type": "AndroidManifest.xml",
                    "component_count": len(components),
                    "components": components,
                    "proof": (
                        "The AndroidManifest.xml contains exported components "
                        "without a declared permission guard."
                    ),
                })

            # --------------------------------------------------------
            # Hardcoded data
            # --------------------------------------------------------
            elif category == "Hardcoded data":

                final_evidence.update({
                    "evidence_type": "DEX bytecode analysis",
                    "proof": (
                        "The detector identified a hardcoded value in compiled "
                        "DEX bytecode. Exact instruction-level evidence is "
                        "available when supplied by the deep bytecode detector."
                    ),
                })

            # --------------------------------------------------------
            # Heuristic / string findings
            # --------------------------------------------------------
            else:

                final_evidence.update({
                    "evidence_type": "APK string/code pattern analysis",
                    "scope": "APK-wide compiled code/string pool",
                    "proof": (
                        "The detector matched the finding against compiled "
                        "APK code, DEX strings, API names, or known code patterns."
                    ),
                })

                # Network URLs
                if category == "Network strings":
                    if self.urls_found:
                        final_evidence["urls"] = self.urls_found
                        final_evidence["url_count"] = len(self.urls_found)

                # IP addresses
                if category == "Network strings":
                    if self.ips_found:
                        final_evidence["ip_addresses"] = self.ips_found

                # Native libraries
                if category == "Native":
                    if self.native_libs:
                        final_evidence["native_libraries"] = self.native_libs

        # ------------------------------------------------------------
        # Store finding
        # ------------------------------------------------------------
        self.findings.append(
            Finding(
                category,
                severity,
                title,
                detail,
                confidence,
                final_evidence,
            )
        )

    def ranked_findings(self) -> List[Finding]:
        """Findings sorted by the Risk Engine's priority score, highest first —
        this is what 'rank the findings in high priority' actually means:
        confirmed-high first, then confirmed-medium and heuristic-high mixed
        by score, down to info. Ties broken by category name for stable
        grouping."""
        return sorted(self.findings, key=lambda f: (-f.priority_score, f.category))


SEVERITY_WEIGHT = {"info": 0, "low": 2, "high": 10, "medium": 5}


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Deep bytecode analysis (opt-in — slower, uses androguard's full
# cross-reference engine instead of raw string search). This catches real
# gaps the string-search pass structurally cannot see:
#   1. MODE_WORLD_READABLE/WRITEABLE — these are `public static final int`
#      constants that Java inlines as raw integer literals at compile time,
#      so the symbolic name never appears in the compiled DEX string pool.
#      Confirmed by testing against a known-vulnerable app where the source
#      genuinely calls getSharedPreferences(..., Context.MODE_WORLD_READABLE)
#      but the string pass reports nothing.
#   2. Hardcoded crypto key/IV material — the literal is often in a
#      different method than the SecretKeySpec/IvParameterSpec constructor
#      call (e.g. a field initializer in <init>, consumed later in an
#      encrypt method), so method-local correlation misses it; this does
#      class-level correlation instead.
# ---------------------------------------------------------------------------

# Common non-secret string literals that legitimately sit near crypto code
# (algorithm names, encodings, transformation strings) — filtered out so the
# hardcoded-key check doesn't just flag "AES" and "UTF-8" as secrets.
_CRYPTO_NOISE_STRINGS = {
    "AES", "DES", "DESEDE", "RSA", "RC4", "BLOWFISH", "HMACSHA1", "HMACSHA256",
    "UTF-8", "UTF8", "ASCII", "US-ASCII", "ISO-8859-1",
    "ECB", "CBC", "CTR", "GCM", "CFB", "OFB",
    "NOPADDING", "PKCS5PADDING", "PKCS7PADDING",
    "MD5", "SHA-1", "SHA1", "SHA-256", "SHA256", "SHA-512", "SHA512",
}

_MODE_VALUE_NAME = {1: "MODE_WORLD_READABLE", 2: "MODE_WORLD_WRITEABLE", 3: "MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE"}

_FILE_MODE_SINK_METHODS = {"getSharedPreferences", "openFileOutput", "openOrCreateDatabase"}
_KEY_MATERIAL_CTORS = {"SecretKeySpec", "IvParameterSpec"}


def _instr_lines(method):
    try:
        return [i.get_output() for i in method.get_method().get_instructions()]
    except AttributeError:
        return []  # ExternalMethod or similar — no body to inspect

def _instruction_evidence(method, keyword=None):
    evidence = []

    try:
        dalvik_method = method.get_method()

        for instruction_index, (offset, ins) in enumerate(
            dalvik_method.get_instructions_idx()
        ):
            text = ins.get_output()

            if keyword is not None and keyword.lower() not in text.lower():
                continue

            evidence.append({
                "dex_offset": f"0x{offset:x}",
                "instruction_index": instruction_index,
                "instruction": text,
            })

    except (AttributeError, TypeError):
        return []

    return evidence

def _bytecode_location(method, keyword=None):
    """
    Build a structured proof/location record for a bytecode finding.
    """

    class_name = getattr(method, "class_name", "") or ""
    method_name = getattr(method, "name", "") or ""

    class_name = class_name.strip("L;").replace("/", ".")

    locations = _instruction_evidence(method, keyword)

    return {
        "internal_file": "classes.dex",
        "class": class_name,
        "method": method_name,
        "locations": locations,
        "source_line": "Not available in compiled APK",
    }

def _instr_pairs(method):
    """Like _instr_lines but keeps the opcode name too, as (name, output) tuples."""
    try:
        return [(i.get_name(), i.get_output()) for i in method.get_method().get_instructions()]
    except AttributeError:
        return []

def is_valid_apk(path):
    """Return True only if the file is a valid ZIP/APK containing AndroidManifest.xml."""
    try:
        if not os.path.isfile(path):
            return False

        if not zipfile.is_zipfile(path):
            return False

        with zipfile.ZipFile(path, "r") as z:
            names = z.namelist()

            # A real APK should contain AndroidManifest.xml
            return "AndroidManifest.xml" in names

    except (zipfile.BadZipFile, OSError, ValueError):
        return False

def _register_of(token: str):
    """'v6' -> 'v6', 'p2' -> 'p2'; returns None if token isn't a register."""
    if re.fullmatch(r"[vp]\d+", token):
        return token
    return None


def _find_backward_int_literal(lines: List[str], start_idx: int, register: str, lookback: int = 10):
    """Scan backward from start_idx for `register, <int>` and return the int, else None."""
    for j in range(start_idx - 1, max(-1, start_idx - 1 - lookback), -1):
        line = lines[j]
        parts = [p.strip() for p in line.split(",")]
        if len(parts) == 2 and parts[0] == register:
            try:
                return int(parts[1], 0)
            except ValueError:
                return None
    return None

def _check_javascript_interface_usage(dx, app_package_prefix, result):
    """
    Find actual addJavascriptInterface() bytecode call sites
    inside the application's own package.

    This avoids reporting a vulnerability merely because the
    method name exists somewhere in a bundled third-party SDK.
    """

    target_method = "addJavascriptInterface"

    for classobj in dx.get_classes():
        cname = classobj.name

        # Only analyze the application's own classes.
        if not cname.startswith(app_package_prefix):
            continue

        class_name = cname.strip("L;").replace("/", ".")

        for method in classobj.get_methods():
            lines = _instr_lines(method)

            if not lines:
                continue

            matching_lines = [
                line for line in lines
                if target_method in line
            ]

            if not matching_lines:
                continue

            result.add(
                "WebView security",
                "medium",
                f"addJavascriptInterface() used in "
                f"{class_name}.{method.name}()",
                (
                    "The application bytecode contains an actual "
                    "addJavascriptInterface() call site. This exposes "
                    "a Java object to JavaScript running in a WebView. "
                    "The API call alone does not prove exploitability; "
                    "the WebView's loaded content and exposed interface "
                    "must also be reviewed."
                ),
                confidence="confirmed",
                evidence={
                    "class": class_name,
                    "method": method.name,
                    "api": target_method,
                    "bytecode": matching_lines,
                },
            )
def prepare_apk_for_analysis(path):
    """
    Return the actual APK path that should be passed to Androguard.

    Supports:
    - normal APK
    - APKM/APKS-style bundles containing base.apk
    """

    # Normal APK
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path, "r") as z:
            names = z.namelist()

            # APKM/APKS/XAPK-style bundle
            if "base.apk" in names:
                temp_dir = tempfile.mkdtemp(prefix="apk_bundle_")
                base_apk = os.path.join(temp_dir, "base.apk")

                with z.open("base.apk") as src, open(base_apk, "wb") as dst:
                    dst.write(src.read())

                return base_apk

    return path

def extract_apks_from_zip(zip_path):
    """
    Safely extract APK files from a ZIP archive.

    Returns:
        list[str]: paths to extracted APK files
    """
    extracted_apks = []

    extract_dir = tempfile.mkdtemp(prefix="apk_zip_")

    with zipfile.ZipFile(zip_path, "r") as z:
        for info in z.infolist():

            # Ignore directories
            if info.is_dir():
                continue

            # Only process APK files
            if not info.filename.lower().endswith(".apk"):
                continue

            # Prevent ZIP path traversal
            filename = os.path.basename(info.filename)

            if not filename:
                continue

            output_path = os.path.join(extract_dir, filename)

            with z.open(info) as source, open(output_path, "wb") as target:
                shutil.copyfileobj(source, target)

            extracted_apks.append(output_path)

    return extracted_apks

def _check_hardcoded_secrets(dx, app_package_prefix, result):
    """
    Detect potentially hardcoded credentials and secrets.

    This is intentionally heuristic unless the value is traced to a
    security-sensitive API or field.
    """

    secret_patterns = [
        (
            r'(?i)\b(password|passwd|pwd)\b\s*[:=]\s*["\'][^"\']{4,}["\']',
            "Hardcoded password"
        ),
        (
            r'(?i)\b(username|user_name|userid|user_id)\b\s*[:=]\s*["\'][^"\']+["\']',
            "Hardcoded username"
        ),
        (
            r'(?i)\b(api[_-]?key)\b\s*[:=]\s*["\'][A-Za-z0-9_\-]{12,}["\']',
            "Hardcoded API key"
        ),
        (
            r'(?i)\b(client[_-]?secret)\b\s*[:=]\s*["\'][^"\']{8,}["\']',
            "Hardcoded client secret"
        ),
        (
            r'(?i)\b(access[_-]?token)\b\s*[:=]\s*["\'][^"\']{12,}["\']',
            "Hardcoded access token"
        ),
        (
            r'(?i)\b(secret[_-]?key)\b\s*[:=]\s*["\'][^"\']{8,}["\']',
            "Hardcoded secret key"
        ),
        (
            r'AKIA[0-9A-Z]{16}',
            "Possible AWS access key"
        ),
        (
            r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
            "Possible JWT token"
        ),
        (
            r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            "Private key material"
        ),
    ]

    seen = set()

    for cls in dx.get_classes():
        cname = cls.name

        # Don't attribute library findings to the application.
        if not cname.startswith(app_package_prefix):
            continue

        for method in cls.get_methods():
            try:
                instructions = method.get_instructions()
            except Exception:
                continue

            for ins in instructions:
                try:
                    text = str(ins)
                except Exception:
                    continue

                for pattern, title in secret_patterns:
                    if re.search(pattern, text):
                        key = (cname, method.name, title, text)

                        if key in seen:
                            continue

                        seen.add(key)

                        result.add(
                            "Hardcoded data",
                            "high",
                            f"{title} in {cname}.{method.name}",
                            (
                                f"Potential secret detected in application bytecode. "
                                f"Matched pattern: {title}. "
                                f"This is a heuristic finding and should be manually "
                                f"verified before treating it as an exposed credential."
                            ),
                            confidence="heuristic",
                        )

def extract_apks_from_zip(zip_path: str) -> List[str]:
    extracted_paths = []

    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():

            name = member.filename

            # Ignore directories
            if member.is_dir():
                continue

            # Ignore macOS metadata
            if name.startswith("__MACOSX/"):
                continue

            if os.path.basename(name).startswith("._"):
                continue

            # Only real APK files
            if not name.lower().endswith(".apk"):
                continue

            apk_data = zf.read(member)

            with tempfile.NamedTemporaryFile(
                delete=False,
                suffix=".apk"
            ) as tmp:
                tmp.write(apk_data)
                extracted_paths.append(tmp.name)

    return extracted_paths


def _check_world_readable_writable(dx, app_package_prefix: str, result: "ScanResult") -> None:
    seen = set()
    for method_name in _FILE_MODE_SINK_METHODS:
        for sink in dx.find_methods(methodname=f"^{re.escape(method_name)}$"):
            for classobj, caller, offset in sink.get_xref_from():
                if not caller.class_name.startswith(app_package_prefix):
                    continue  # skip third-party SDK noise
                lines = _instr_lines(caller)
                for idx, line in enumerate(lines):
                    if f"->{method_name}(" not in line or "I)" not in line.split(f"->{method_name}(")[1][:40]:
                        continue
                    # invoke line looks like: "v4, v5, v6, Lpkg/Cls;->method(...I)..."
                    call_desc = line.split(f"->{method_name}(")[0]
                    regs = [t.strip() for t in call_desc.split(",")]
                    regs = [r for r in regs if _register_of(r)]
                    if not regs:
                        continue
                    mode_reg = regs[-1]  # last register arg = the trailing int mode param
                    mode_val = _find_backward_int_literal(lines, idx, mode_reg)
                    if mode_val in (1, 2, 3):
                        key = (caller.class_name, caller.name, mode_val)
                        if key in seen:
                            continue
                        seen.add(key)
                        result.add(
                            "World-readable/writable files", "medium",
                            f"{_MODE_VALUE_NAME.get(mode_val, mode_val)} passed to {method_name}()",
                            f"{caller.class_name.strip('L;').replace('/', '.')}.{caller.name}() calls "
                            f"{method_name}() with an inlined world-{'readable' if mode_val==1 else 'writable' if mode_val==2 else 'readable/writable'} "
                            "mode flag — any other app on the device can access this data. Confirmed via "
                            "bytecode trace (this constant is compiler-inlined and invisible to plain "
                            "string scanning), but capped at medium rather than high since impact "
                            "depends on what's actually stored there, which this check can't establish.",
                            confidence="confirmed",
                        )


def _check_hardcoded_key_material(dx, app_package_prefix: str, result: "ScanResult") -> None:
    flagged_classes = set()

    # Search all app-owned classes for methods that construct
    # SecretKeySpec/IvParameterSpec, then scan every method of that SAME
    # class for suspicious const-string literals (class-level correlation,
    # since the literal is often in a different method — e.g. a field
    # initializer in <init> — than where the key object gets built).
    for classobj in dx.get_classes():
        cname = classobj.name
        if not cname.startswith(app_package_prefix):
            continue
        if cname in flagged_classes:
            continue

        constructs_key_material = False
        for m in classobj.get_methods():
            lines = _instr_lines(m)
            if any(ctor in line for line in lines for ctor in _KEY_MATERIAL_CTORS):
                constructs_key_material = True
                break
        if not constructs_key_material:
            continue

        candidates = []
        for m in classobj.get_methods():
            for line in _instr_lines(m):
                match = re.match(r'^v\d+,\s*"(.+)"$', line)
                if not match:
                    continue
                literal = match.group(1)
                if literal.upper() in _CRYPTO_NOISE_STRINGS:
                    continue
                if len(literal) < 6 or len(literal) > 128:
                    continue
                candidates.append(literal)

        if candidates:
            flagged_classes.add(cname)
            preview = candidates[0]
            if len(preview) > 60:
                preview = preview[:57] + "..."
            result.add(
                "Hardcoded encryption keys", "high",
                f"Likely hardcoded key material in {cname.strip('L;').replace('/', '.')}",
                f"This class constructs a SecretKeySpec/IvParameterSpec and also contains a string "
                f"literal that isn't a recognized algorithm/encoding name — e.g. \"{preview}\". "
                "Confirmed via class-level bytecode correlation (the literal is often in a field "
                "initializer/constructor, a different method than where the key object is built, "
                "so plain string search alone won't connect the two).",
                confidence="confirmed",
            )


def _check_hardcoded_key_bytes(dx, app_package_prefix: str, result: "ScanResult") -> None:
    """
    Catches hardcoded key/IV material stored as a raw byte-array literal
    (`byte[] key = {1, 2, 3, ...}`), which is a distinct compiled form from
    a string literal — Java compiles array literals to `new-array` +
    `fill-array-data` (pointing at a `fill-array-data-payload` pseudo-
    instruction holding the actual bytes), not `const-string`. The
    class-level string-correlation check above cannot see this at all.
    Verified against PIVAA's Encryption.java, which hardcodes both an
    AES key and an all-zero IV this exact way.

    Uses register-level tracing (which register each `fill-array-data`
    fills, then a forward scan for the next SecretKeySpec/IvParameterSpec
    constructor call that consumes that exact register as its first
    argument) so a method that builds BOTH a key and an IV array — as
    PIVAA's methods do — attributes each byte array to the correct single
    category. An earlier method-level-only version of this check
    cross-attributed every array in the method to every category present,
    reporting the IV bytes as "hardcoded key" too; caught and fixed before
    shipping by inspecting the actual instruction sequence.

    An all-zero (or otherwise near-constant) IV is flagged as a stronger
    "weak IV" finding regardless of key material, since a static/
    predictable IV defeats CBC/CTR security guarantees on its own.
    """
    import ast

    for classobj in dx.get_classes():
        cname = classobj.name
        if not cname.startswith(app_package_prefix):
            continue

        for m in classobj.get_methods():
            pairs = _instr_pairs(m)
            if not pairs:
                continue

            # Step 1: every array-fill instruction, in order, with its register.
            filled = []
            for idx, (opname, output) in enumerate(pairs):
                if opname == "fill-array-data":
                    reg_match = re.match(r"^(v\d+),", output)
                    if reg_match:
                        filled.append((idx, reg_match.group(1)))
            if not filled:
                continue

            # Step 2: every payload's actual bytes, in the same order as the
            # fill-array-data instructions that reference them (standard
            # dx/javac emission order — payloads trail the real code in the
            # same sequence they were referenced).
            payloads = []
            for opname, output in pairs:
                if opname != "fill-array-data-payload":
                    continue
                match = re.search(r"b'((?:\\x[0-9a-fA-F]{2}|[^'])*)'", output)
                if not match:
                    payloads.append(None)
                    continue
                try:
                    payloads.append(ast.literal_eval("b'" + match.group(1) + "'"))
                except Exception:
                    payloads.append(None)

            # Step 3: for each filled array, find the SPECIFIC constructor
            # call that consumes it (forward scan, first constructor call
            # after the fill that uses this exact register as its first
            # arg) — this is what prevents cross-attributing one array to
            # both categories when a method builds both a key and an IV.
            for (fidx, reg), byte_data in zip(filled, payloads):
                if not byte_data or len(byte_data) < 4:
                    continue
                target = None
                for j in range(fidx + 1, len(pairs)):
                    opname, output = pairs[j]
                    if opname != "invoke-direct":
                        continue
                    if "SecretKeySpec;-><init>" not in output and "IvParameterSpec;-><init>" not in output:
                        continue
                    call_desc = output.split("Ljavax/crypto/spec/")[0]
                    arg_regs = [t.strip() for t in call_desc.split(",") if _register_of(t.strip())]
                    # invoke-direct on a constructor: first register is the
                    # receiver ("this", the newly-created instance), the
                    # actual constructor argument (the byte[]) is the second.
                    if len(arg_regs) >= 2 and arg_regs[1] == reg:
                        target = "iv" if "IvParameterSpec" in output else "key"
                    break  # only consider the nearest constructor call either way

                if target is None:
                    continue

                hex_preview = byte_data[:16].hex()
                cname_display = cname.strip("L;").replace("/", ".")
                is_degenerate = len(set(byte_data)) <= 2

                if target == "iv":
                    result.add(
                        "Weak initialization vector", "medium",
                        f"Hardcoded IV byte array in {cname_display}.{m.name}()",
                        f"IV bytes: {hex_preview}{'...' if len(byte_data) > 16 else ''}"
                        f"{' — constant/degenerate (e.g. all-zero), about as bad as an IV construction gets' if is_degenerate else ''}. "
                        "Confirmed via bytecode (fill-array-data-payload, register-traced to the "
                        "IvParameterSpec constructor call that consumes it). Capped at medium rather "
                        "than high per calibration: real-world severity depends on the cipher mode "
                        "and whether this same IV is reused across encryptions, neither of which "
                        "this check independently establishes — even a confirmed-hardcoded IV needs "
                        "that context to size the actual impact.",
                        confidence="confirmed",
                    )
                else:
                    result.add(
    "Hardcoded encryption keys",
    "high",
    f"Hardcoded key byte array in {cname_display}.{m.name}()",

    f"Key bytes: {hex_preview}{'...' if len(byte_data) > 16 else ''}. "
    "Confirmed via bytecode (fill-array-data-payload, register-traced to the "
    "SecretKeySpec constructor call that consumes it) — a raw byte-array "
    "literal, a different compiled form than a string literal, which the "
    "string-based hardcoded-key check cannot see. Kept high: an actual "
    "extractable key directly compromises confidentiality.",

    confidence="confirmed",

    evidence={
        "type": "bytecode-traced hardcoded key",
        "class": cname_display,
        "method": m.name,

        "key_bytes": byte_data.hex(),

        "fill_array_instruction_index": fidx,
        "fill_array_instruction": (
            f"{pairs[fidx][0]} {pairs[fidx][1]}"
        ),

        "constructor_instruction_index": j,
        "constructor_instruction": (
            f"{pairs[j][0]} {pairs[j][1]}"
        ),

        "api": "javax.crypto.spec.SecretKeySpec",
        "register": reg,

        "bytecode_proof": (
            f"fill-array-data at instruction #{fidx} "
            f"fills register {reg}; "
            f"the following SecretKeySpec constructor at instruction "
            f"#{j} consumes that same register."
        ),
    },
)


def _check_webview_ssl_bypass(dx, app_package_prefix: str, result: "ScanResult") -> None:
    """
    WebViewClient.onReceivedSslError() that calls handler.proceed() makes the
    WebView accept invalid/self-signed certificates unconditionally.
    """
    for m in dx.find_methods(methodname="^onReceivedSslError$"):
        if not m.class_name.startswith(app_package_prefix):
            continue
        lines = _instr_lines(m)
        cname = m.class_name.strip("L;").replace("/", ".")
        if any("proceed" in l for l in lines):
            result.add(
                "Self-signed CA in WebView", "high",
                f"onReceivedSslError() in {cname} calls proceed()",
                "Confirmed: this override calls SslErrorHandler.proceed(), which makes the "
                "WebView accept the invalid/self-signed certificate and continue loading — "
                "this defeats TLS validation for that WebView regardless of the error type.",
                confidence="confirmed",
            )
        elif any("cancel" in l for l in lines):
            result.add(
                "Self-signed CA in WebView", "low",
                f"onReceivedSslError() in {cname} — calls cancel(), looks safe",
                "Override calls SslErrorHandler.cancel() rather than proceed() — this is the "
                "correct behavior (rejects the connection on SSL error). Flagged only for "
                "visibility; not a vulnerability as written.",
                confidence="confirmed",
            )
        else:
            result.add(
                "Self-signed CA in WebView", "medium",
                f"onReceivedSslError() overridden in {cname} — behavior unclear",
                "Found the override but couldn't determine whether it calls proceed() or "
                "cancel() from the instruction scan — read this method manually.",
            )


def _describe_caller_arg_pattern(dx, target_class: str, target_method: str) -> str:
    """
    One-hop-up context for a method whose body concatenates SQL: looks at
    ITS callers and reports whether they only ever pass literal/constant
    strings (much lower real-world risk — e.g. enumerating the app's own
    fixed data) or at least one passes a non-literal value (parameter,
    variable — genuinely unresolved, could be external input), or whether
    no callers were found at all via static analysis (common for methods
    reached through a ContentProvider's query() dispatch, reflection, or
    other indirection androguard's static xref can't follow — this does
    NOT mean the method is unreachable, just that it couldn't be traced).
    This doesn't resolve exploitability on its own, but gives the reader
    real information instead of a blanket "verify manually."
    """
    try:
        callers = []
        for m in dx.find_methods(classname=re.escape(target_class), methodname=f"^{re.escape(target_method)}$"):
            callers.extend(m.get_xref_from())
    except Exception:
        callers = []
    if not callers:
        return (
            "No callers of this method were found via static analysis — this is common "
            "for methods reached through a ContentProvider's query() dispatch, an exported "
            "component's onReceive/onStartCommand, or reflection, none of which androguard's "
            "static call-graph reliably follows. This does NOT mean it's unreachable — "
            "treat it as unverified rather than dismissing it."
        )
    only_literal = True
    for classobj, caller, offset in callers:
        lines = _instr_lines(caller)
        for idx, line in enumerate(lines):
            if f"->{target_method}(" not in line:
                continue
            call_desc = line.split(f"->{target_method}(")[0]
            arg_regs = [t.strip() for t in call_desc.split(",") if _register_of(t.strip())]
            if len(arg_regs) < 2:
                continue
            arg_reg = arg_regs[1]  # first real arg after the receiver
            found_literal = False
            for j in range(idx - 1, max(-1, idx - 6), -1):
                if re.match(rf'^{re.escape(arg_reg)},\s*".*"$', lines[j]):
                    found_literal = True
                    break
            if not found_literal:
                only_literal = False
    if only_literal:
        return (
            f"Checked {len(callers)} call site(s) of this method: all pass a literal/constant "
            "string, not a variable — meaningfully lower real-world risk than an unresolved "
            "external input, though still worth confirming those literals are truly fixed "
            "and not, in turn, sourced from something external further up the chain."
        )
    return (
        f"Checked {len(callers)} call site(s): at least one passes a non-literal value "
        "(a variable/parameter, not a fixed string) — this is exactly the pattern that "
        "would carry external input if the caller's own argument is attacker-influenced. "
        "Worth tracing one level further up."
    )


def _check_sql_concatenation(dx, app_package_prefix: str, result: "ScanResult") -> None:
    """
    rawQuery/execSQL/query calls where the query STRING ARGUMENT ITSELF is
    the result of a StringBuilder.toString() are a strong SQL-injection
    tell. This checks register-level proximity (the toString() result must
    actually feed one of the sink call's argument registers) rather than
    just "both appear somewhere in this method" — a coarser version of this
    check produced a false positive on an exported ContentProvider where
    the StringBuilder was building an unrelated exception message in the
    same method as the (properly parameterized) query call.

    IMPORTANT CALIBRATION NOTE, found via real testing: this confirms a
    CODE PATTERN (concatenation feeding a SQL call), not confirmed
    EXPLOITABILITY. Tested against a2dp.Vol (a real, non-vulnerable-by-
    design app): it flagged `DataXmlExporter.exportTable()`, which does
    concatenate a table name into `"select * from " + tableName` — but
    that name is always enumerated from the app's OWN database schema via
    `sqlite_master` in a local backup/export feature, never external
    input. Concatenation is real; exploitability there is not. Since this
    can't be resolved in general without full taint tracing to a trusted
    source, `_describe_caller_arg_pattern` adds one hop of real context
    (are ALL known callers passing only literals?) instead of asserting a
    verdict either way.
    """
    seen = set()
    for method_name in ("rawQuery", "execSQL", "query"):
        for sink in dx.find_methods(methodname=f"^{method_name}$"):
            for classobj, caller, offset in sink.get_xref_from():
                if not caller.class_name.startswith(app_package_prefix):
                    continue
                lines = _instr_lines(caller)
                for idx, line in enumerate(lines):
                    if f"->{method_name}(" not in line:
                        continue
                    call_desc = line.split(f"->{method_name}(")[0]
                    arg_regs = {r for r in (t.strip() for t in call_desc.split(",")) if _register_of(r)}
                    if not arg_regs:
                        continue
                    # Look backward a bounded window for a StringBuilder.toString()
                    # whose RESULT REGISTER is actually one of the sink's args.
                    for j in range(idx - 1, max(-1, idx - 25), -1):
                        m = re.match(r"^([vp]\d+),\s*Ljava/lang/StringBuilder;->toString\(\)", lines[j])
                        if m and m.group(1) in arg_regs:
                            key = (caller.class_name, caller.name, method_name)
                            if key in seen:
                                break
                            seen.add(key)
                            cname = caller.class_name.strip("L;").replace("/", ".")
                            caller_context = _describe_caller_arg_pattern(dx, caller.class_name, caller.name)
                            result.add(
                                "User input in SQL queries", "medium",
                                f"{method_name}() argument built via StringBuilder in {cname}.{caller.name}()",
                                "Confirmed via register-level trace: a StringBuilder.toString() result "
                                "is passed directly as an argument to this SQL call (not just present "
                                "somewhere in the same method). This confirms the CONCATENATION "
                                "PATTERN exists — it does not by itself confirm the concatenated value "
                                "is attacker-controlled, which is why this is capped at medium rather "
                                "than high even though the pattern itself is bytecode-confirmed. " + caller_context,
                                confidence="confirmed",
                            )
                            break



def _check_hardcoded_secret_comparison(dx, app_package_prefix: str, result: "ScanResult") -> None:
    """
    Generic "Hardcoded data" check — separate from the crypto-key-specific
    check above. Looks for String.equals()/equalsIgnoreCase() calls where
    the argument is a plain const-string literal, which is the classic
    hardcoded-password/access-key comparison pattern (e.g.
    `if (userInput.equals("vendorsecretkey"))`).

    Restricted to methods/classes whose name suggests an auth/security
    context. An earlier, unrestricted version of this check was tested
    against real (non-vulnerable-by-design) apps and produced 13-16 false
    positives per app — Intent action strings, SQLite table names, and UI
    preference values all match ".equals(literal)" too, since that's an
    extremely common Java pattern with no inherent connection to secrets.
    The context filter is a blunt instrument (a real backdoor check with
    an innocuous-sounding method name would be missed), but it cut a real,
    verified false-positive rate to zero on two clean test apps while
    still catching the actual InsecureBankv2 backdoor-username case.
    """
    seen = set()
    noise = {
        "", "true", "false", "null", "yes", "no", "ok", "cancel", "error",
        "success", "failure", "utf-8", "utf8", "ascii",
    }
    context_re = re.compile(
        r"login|auth|password|passwd|pwd|credential|secret|token|verify|"
        r"valid|signin|sign_in|unlock|security|access|backdoor|admin",
        re.I,
    )
    # Java: String.equals()/equalsIgnoreCase(). Kotlin's `==` on strings and
    # `.equals()` calls typically compile to different sinks entirely
    # (Intrinsics.areEqual / StringsKt.equals) rather than java.lang.String's
    # equals — verified against InsecureShop (a Kotlin app), where a plain
    # `dx.find_methods(methodname="^equals$")` search never matches any
    # app-owned Kotlin comparison at all. Both sink families are checked so
    # this works on Java and Kotlin apps alike.
    sink_specs = ["equals", "equalsIgnoreCase", "areEqual"]
    for method_name in sink_specs:
        for sink in dx.find_methods(methodname=f"^{method_name}(\\$default)?$"):
            for classobj, caller, offset in sink.get_xref_from():
                if not caller.class_name.startswith(app_package_prefix):
                    continue
                context = f"{caller.class_name} {caller.name}"
                if not context_re.search(context):
                    continue  # no auth/security signal in class or method name — skip
                lines = _instr_lines(caller)
                for idx, line in enumerate(lines):
                    if f"->{method_name}(" not in line and f"->{method_name}$default(" not in line:
                        continue
                    call_desc = line.split(f"->{method_name}")[0]
                    arg_regs = [t.strip() for t in call_desc.split(",") if _register_of(t.strip())]
                    if not arg_regs:
                        continue
                    # Check ALL argument registers (not just the last) since
                    # Kotlin sink signatures put the literal in varying
                    # positions depending on which helper is used.
                    for arg_reg in arg_regs:
                        for j in range(idx - 1, max(-1, idx - 6), -1):
                            m = re.match(r'^([vp]\d+),\s*"(.+)"$', lines[j])
                            if not m or m.group(1) != arg_reg:
                                continue
                            literal = m.group(2)
                            if literal.lower() in noise or len(literal) < 5 or len(literal) > 80:
                                break
                            if not re.search(r"[A-Za-z]", literal):
                                break  # skip pure-numeric/symbol strings, low signal
                            key = (caller.class_name, caller.name, literal)
                            if key in seen:
                                break
                            seen.add(key)
                            cname = caller.class_name.strip("L;").replace("/", ".")
                            preview = literal if len(literal) <= 50 else literal[:47] + "..."
                            result.add(
                                "Hardcoded data", "high",
                                f"Hardcoded string compared in {cname}.{caller.name}()",
                                f"Found a comparison against literal \"{preview}\" — code compares a "
                                "value directly against a string baked into the APK. If this literal "
                                "is a password, access key, or license/unlock code, it can be "
                                "extracted by anyone who decompiles the APK (trivial to do) and used "
                                "to bypass whatever check this gates. Confirmed via register-level "
                                "bytecode trace.",
                                confidence="confirmed",
                            )
                            break


def _check_tapjacking_layouts(apk: APK, result: "ScanResult") -> bool:
    """
    Parses compiled layout XML resources (res/layout/*.xml) looking for
    android:filterTouchesWhenObscured="true" on sensitive-looking views
    (buttons). Returns True if at least one layout was successfully parsed,
    so the caller knows whether the absence-based fallback finding is
    warranted vs. this structural check already covered it.
    """
    from androguard.core.axml import AXMLPrinter
    from lxml import etree

    layout_files = [f for f in apk.get_files() if f.startswith("res/layout/") and f.endswith(".xml")]
    if not layout_files:
        return False

    any_button = False
    any_protected = False
    parsed_any = False

    for fname in layout_files[:200]:  # cap for very large APKs
        try:
            raw = apk.get_file(fname)
            xml_str = etree.tostring(AXMLPrinter(raw).get_xml_obj(), encoding="unicode")
        except Exception:
            continue
        parsed_any = True
        if re.search(r"<Button\b|<ImageButton\b", xml_str):
            any_button = True
            if re.search(r'filterTouchesWhenObscured\s*=\s*"true"', xml_str):
                any_protected = True

    if not parsed_any:
        return False

    if any_button and not any_protected:
        result.add(
            "Tapjacking protection", "low",
            "No layout sets filterTouchesWhenObscured=\"true\"",
            f"Parsed {len(layout_files)} layout resource(s) — found Button/ImageButton views but "
            "none with touch-filtering enabled when obscured. Context-dependent: capped at low "
            "since this doesn't establish that a sensitive screen (payment/consent/permission-"
            "grant) is actually affected, just that this specific mitigation isn't present "
            "anywhere in the scanned layouts.",
            confidence="confirmed",
        )
    elif any_protected:
        result.add(
            "Tapjacking protection", "low",
            "At least one layout sets filterTouchesWhenObscured=\"true\"",
            f"Found this protection in at least one of {len(layout_files)} layout resource(s) — "
            "good sign, though worth confirming it's actually on the sensitive screens "
            "(payment/consent) rather than an incidental one.",
            confidence="confirmed",
        )
    return True


_STRONG_CRED_FIELD_RE = re.compile(
    r"(password|passwd|pwd|secret|apikey|api_key|authtoken|auth_token|"
    r"accesstoken|access_token|privatekey|private_key|secretkey|secret_key)",
    re.I,
)
_WEAK_CRED_FIELD_RE = re.compile(r"(username|login|account)", re.I)


def _check_hardcoded_credential_map(dx, app_package_prefix: str, result: "ScanResult") -> None:
    """
    Catches a pattern the field-assignment and equals()-comparison checks
    both structurally miss: credentials stored as literal key/value pairs
    in a Map, e.g. Kotlin's `userCreds["shopuser"] = "!ns3csh0p"`, which
    compiles to `Map.put("shopuser", "!ns3csh0p")` with both arguments as
    immediately-preceding const-string literals — no field, no comparison
    at that call site at all. Verified against InsecureShop's real
    getUserCreds()/HashMap<String,String> credential store.
    """
    context_re = re.compile(r"cred|login|auth|password|passwd|pwd|secret|token|user", re.I)
    seen = set()
    for sink in dx.find_methods(methodname="^put$"):
        for classobj, caller, offset in sink.get_xref_from():
            if not caller.class_name.startswith(app_package_prefix):
                continue
            context = f"{caller.class_name} {caller.name}"
            if not context_re.search(context):
                continue
            pairs = _instr_pairs(caller)
            for idx, (opname, output) in enumerate(pairs):
                if "invoke" not in opname or "->put(" not in output:
                    continue
                if "Map;->put(" not in output and "HashMap;->put(" not in output:
                    continue
                if idx < 2:
                    continue
                key_name, key_out = pairs[idx - 2]
                val_name, val_out = pairs[idx - 1]
                if "const-string" not in key_name or "const-string" not in val_name:
                    continue
                km = re.match(r'^v\d+,\s*"(.+)"$', key_out)
                vm = re.match(r'^v\d+,\s*"(.+)"$', val_out)
                if not km or not vm:
                    continue
                key_lit, val_lit = km.group(1), vm.group(1)
                if len(val_lit) < 3 or len(val_lit) > 100:
                    continue
                sig = (caller.class_name, caller.name, key_lit, val_lit)
                if sig in seen:
                    continue
                seen.add(sig)
                cname = caller.class_name.strip("L;").replace("/", ".")
                val_preview = val_lit if len(val_lit) <= 50 else val_lit[:47] + "..."
                result.add(
                    "Hardcoded data", "high",
                    f"Hardcoded credential in Map.put() in {cname}.{caller.name}()",
                    f'Found `.put("{key_lit}", "{val_preview}")` — a literal key/value pair '
                    "stored directly in a Map, in a method whose name/class suggests a "
                    "credential store. Confirmed via bytecode (both arguments are "
                    "immediately-preceding const-string literals).",
                    confidence="confirmed",
                )


def _check_hardcoded_credential_fields(dx, app_package_prefix: str, result: "ScanResult") -> None:
    """
    Finds fields with credential-shaped names (password, secret, apikey,
    token, ...) that are assigned a plain string literal in a field
    initializer/constructor — e.g. `public String password =
    "verycomplicatedpassword";`. This is a distinct pattern from both the
    crypto-key correlation check (no SecretKeySpec/IvParameterSpec
    involved) and the equals()-comparison check (no comparison at all,
    just a literal sitting in a field) — plain field assignment is the
    most common real-world form of hardcoded credentials.
    """
    for classobj in dx.get_classes():
        cname = classobj.name
        if not cname.startswith(app_package_prefix):
            continue

        hits = []  # (field_name, literal, is_strong)
        for m in classobj.get_methods():
            pairs = _instr_pairs(m)
            for idx, (opname, output) in enumerate(pairs):
                if opname not in ("iput-object", "sput-object"):
                    continue
                field_match = re.search(r"->(\w+)\s+Ljava/lang/String;$", output)
                if not field_match:
                    continue
                field_name = field_match.group(1)
                is_strong = bool(_STRONG_CRED_FIELD_RE.search(field_name))
                is_weak = bool(_WEAK_CRED_FIELD_RE.search(field_name))
                if not (is_strong or is_weak):
                    continue
                if idx == 0:
                    continue
                prev_name, prev_output = pairs[idx - 1]
                if "const-string" not in prev_name:
                    continue
                m2 = re.match(r'^v\d+,\s*(.+)$', prev_output)
                if not m2:
                    continue
                literal = m2.group(1)
                if len(literal) < 2 or len(literal) > 100:
                    continue
                hits.append((field_name, literal, is_strong))

        if not hits or not any(h[2] for h in hits):
            continue  # require at least one strong-signal field name to reduce noise

        cname_display = cname.strip("L;").replace("/", ".")
        for field_name, literal, is_strong in hits:
            preview = literal if len(literal) <= 50 else literal[:47] + "..."
            result.add(
                "Hardcoded data", "high" if is_strong else "medium",
                f"Hardcoded credential field: {cname_display}.{field_name}",
                f'Field `{field_name}` is assigned the literal "{preview}" directly in a '
                "field initializer/constructor — confirmed via bytecode (const-string "
                "immediately followed by the field-store instruction). Anyone who "
                "decompiles this APK (trivial to do) gets this value in plaintext.",
                confidence="confirmed",
            )


def _finding_risk_score(finding):
    severity_weight = SEVERITY_WEIGHT.get(
        finding.severity, 0
    )

    confidence_multiplier = _CONFIDENCE_MULT.get(
        finding.confidence, 0.10
    )

    return round(
        severity_weight * confidence_multiplier
    )

def _check_exported_component_behavior(
    dx,
    app_package_prefix,
    exported_components,
    result,
):

    """
    Analyze exported application components for a simple source -> sink
    relationship.

    This is NOT full taint analysis.

    A finding is produced only when:
        exported component
            -> external input source
            -> sensitive sink

    The source must occur before the sink in the same method.

    This reduces false positives compared with simply checking whether
    a source and sink both exist somewhere in the method.
    """

    external_sources = {
        "getIntent(": "Intent",
        "getStringExtra(": "Intent string extra",
        "getIntExtra(": "Intent integer extra",
        "getBooleanExtra(": "Intent boolean extra",
        "getParcelableExtra(": "Intent parcelable extra",
        "getSerializableExtra(": "Intent serialized extra",
        "getData(": "Intent URI",
        "getDataString(": "Intent URI string",
        "getQueryParameter(": "URI query parameter",
    }

    sensitive_sinks = {
        "Runtime.exec(": "command execution",
        "loadUrl(": "WebView navigation",
        "execSQL(": "SQL execution",
        "rawQuery(": "SQL query",
        "openFileOutput(": "file write",
        "delete(": "file/data deletion",
        "setResult(": "activity result",
        "startActivity(": "activity launch",
        "startService(": "service launch",
        "sendBroadcast(": "broadcast sending",
    }

    component_map = {
        c["name"]: c["type"]
        for c in exported_components
    }

    for classobj in dx.get_classes():
        cname = classobj.name

        # Analyze only application classes.
        if not cname.startswith(app_package_prefix):
            continue

        class_name = cname.strip("L;").replace("/", ".")

        # Only exported components.
        if class_name not in component_map:
            continue

        component_type = component_map[class_name]

        for method in classobj.get_methods():
            lines = _instr_lines(method)

            if not lines:
                continue

            # ---------------------------------------------------------
            # Find source -> sink relationships in instruction order.
            # ---------------------------------------------------------

            source_hits = []

            for index, line in enumerate(lines):
                for source, source_description in external_sources.items():
                    if source in line:
                        source_hits.append(
                            (
                                index,
                                source,
                                source_description,
                            )
                        )

            if not source_hits:
                continue

            sink_hits = []

            for index, line in enumerate(lines):
                for sink, sink_description in sensitive_sinks.items():
                    if sink in line:
                        sink_hits.append(
                            (
                                index,
                                sink,
                                sink_description,
                            )
                        )

            if not sink_hits:
                continue

            # ---------------------------------------------------------
            # Only report when a source occurs BEFORE a sink.
            # ---------------------------------------------------------

            relationships = []

            for (
                source_index,
                source,
                source_description,
            ) in source_hits:

                for (
                    sink_index,
                    sink,
                    sink_description,
                ) in sink_hits:

                    if source_index < sink_index:
                        relationships.append(
                            {
                                "source_index": source_index,
                                "sink_index": sink_index,
                                "source": source_description,
                                "sink": sink_description,
                            }
                        )

            if not relationships:
                continue

            # ---------------------------------------------------------
            # Avoid duplicate findings for the same method.
            # ---------------------------------------------------------

            seen = set()

            for relationship in relationships:
                key = (
                    relationship["source"],
                    relationship["sink"],
                )

                if key in seen:
                    continue

                seen.add(key)

                source_description = relationship["source"]
                sink_description = relationship["sink"]

                # Candidate only:
                # source and sink are connected by method order,
                # but variable-level taint is not yet proven.
                result.add(
                    "Exported component analysis",
                    "medium",
                    (
                        f"Exported {component_type} has external input "
                        f"reaching {sink_description}: "
                        f"{class_name}.{method.name}()"
                    ),
                    (
                        f"The exported {component_type} reads external "
                        f"input through {source_description} and later "
                        f"reaches {sink_description} in the same method. "
                        f"This establishes an externally reachable "
                        f"source-to-sink candidate, but does not prove "
                        f"that the exact source value reaches the sink "
                        f"without additional variable-level data-flow "
                        f"analysis."
                    ),
                    confidence="confirmed",
                    evidence={
                        "component": class_name,
                        "component_type": component_type,
                        "method": method.name,
                        "source": source_description,
                        "sink": sink_description,
                        "source_instruction_index":
                            relationship["source_index"],
                        "sink_instruction_index":
                            relationship["sink_index"],
                        "analysis": "ordered source-to-sink",
                    },
                )
def run_deep_bytecode_analysis(path: str, result: "ScanResult") -> None:
    """
    Opt-in deep pass using androguard's full Analysis/cross-reference engine.
    Slower (can take 10s-60s+ depending on APK size) — only run this when
    the caller explicitly asks for it.
    """
    from androguard.misc import AnalyzeAPK

    app_pkg = result.package_name.replace(".", "/")
    app_prefix = f"L{app_pkg}"

    a, d, dx = AnalyzeAPK(path)

    try:
        _check_exported_component_behavior(
            dx,
            app_prefix,
            result.exported_components,
            result,
        )
        _check_javascript_interface_usage(
            dx,
            app_prefix,
            result,
        )
    except Exception as e:
        print(f"[DeepScan] Exported component analysis failed: {type(e).__name__}: {e}")

    try:
        _check_world_readable_writable(dx, app_prefix, result)
    except Exception as e:
        result.add("Deep scan", "low", "World-readable/writable check failed", str(e))

    try:
        _check_hardcoded_key_material(dx, app_prefix, result)
    except Exception as e:
        result.add("Deep scan", "low", "Hardcoded key material check failed", str(e))

    try:
        _check_hardcoded_key_bytes(dx, app_prefix, result)
    except Exception as e:
        result.add("Deep scan", "low", "Hardcoded key bytes check failed", str(e))

    try:
        _check_trust_manager_trivial(dx, app_prefix, result)
    except Exception as e:
        result.add("Deep scan", "low", "TrustManager triviality check failed", str(e))
        try:
            _check_runtime_exec_deep(dx, app_prefix, result)

        except Exception as e:
            result.add(
                "Deep scan",
                "low",
                "Runtime.exec deep check failed",
                str(e)
            )
    try:
        _check_runtime_exec_deep(dx, app_prefix, result)
    except Exception as e:
        result.add(
            "Deep scan",
            "low",
            "Runtime.exec deep check failed",
            str(e)
        )

    try:
        _check_hardcoded_secrets(dx, app_prefix, result)

    except Exception as e:
        result.add(
            "Deep scan",
            "low",
            "Hardcoded secret check failed",
            str(e)
        )

    try:
        _check_webview_ssl_bypass(dx, app_prefix, result)
        if any(f.category == "Self-signed CA in WebView" and f.confidence == "confirmed" for f in result.findings):
            # Confirmed proceed()/cancel() behavior supersedes the vaguer
            # fast-pass "override found" presence finding — same dedup
            # pattern used for tapjacking, to avoid showing both a specific
            # confirmed answer and a generic "go check this" note together.
            result.findings = [
                f for f in result.findings
                if not (f.category == "Self-signed CA in WebView" and f.confidence == "heuristic")
            ]
    except Exception as e:
        result.add("Deep scan", "low", "WebView SSL bypass check failed", str(e))

    try:
        _check_sql_concatenation(dx, app_prefix, result)
    except Exception as e:
        result.add("Deep scan", "low", "SQL concatenation check failed", str(e))

    try:
        _check_hardcoded_secret_comparison(dx, app_prefix, result)
    except Exception as e:
        result.add("Deep scan", "low", "Hardcoded secret comparison check failed", str(e))

    try:
        _check_hardcoded_credential_fields(dx, app_prefix, result)
    except Exception as e:
        result.add("Deep scan", "low", "Hardcoded credential field check failed", str(e))

    try:
        _check_hardcoded_credential_map(dx, app_prefix, result)
    except Exception as e:
        result.add("Deep scan", "low", "Hardcoded credential map check failed", str(e))

    try:
        apk_obj = APK(path)
        layout_check_ran = _check_tapjacking_layouts(apk_obj, result)
        if layout_check_ran:
            # Structural layout check superseded the fast-pass absence-only
            # info finding — remove it so the UI doesn't show both a vague
            # "no evidence found" note and the more specific structural one.
            result.findings = [
                f for f in result.findings
                if not (f.category == "Tapjacking protection" and f.confidence == "heuristic")
            ]
    except Exception as e:
        result.add("Deep scan", "low", "Tapjacking layout check failed", str(e))

    # ---- Risk Engine: generic supersede/dedup pass ---------------------------
    # Same principle already proven on tapjacking/self-signed-CA above: when a
    # CONFIRMED (bytecode-traced) finding exists for something, the vaguer
    # heuristic "found a reference, go check it" finding for the same
    # underlying issue is redundant noise, not additional signal. Applied
    # generically here to the remaining categories where testing showed both
    # variants co-occurring (Hardcoded encryption keys, Weak IV, SQL queries)
    # plus one cross-category case: a confirmed "Untrusted CA" accept-all
    # finding makes the generic "Custom TrustManager.checkServerTrusted found"
    # heuristic note redundant, even though they're filed under different
    # category names (both stem from the same checkServerTrusted() method).
    _SUPERSEDE_RULES = [
        ("Hardcoded encryption keys", "Hardcoded encryption keys", None),
        ("Weak initialization vector", "Weak initialization vector", None),
        ("User input in SQL queries", "User input in SQL queries", None),
        ("Untrusted CA", "MITM / hostname verification", "checkServerTrusted"),
    ]
    for confirmed_cat, heuristic_cat, title_filter in _SUPERSEDE_RULES:
        has_confirmed = any(
            f.category == confirmed_cat and f.confidence == "confirmed" for f in result.findings
        )
        if not has_confirmed:
            continue
        result.findings = [
            f for f in result.findings
            if not (
                f.category == heuristic_cat and f.confidence == "heuristic"
                and (title_filter is None or title_filter in f.title)
            )
        ]

    # Recompute score/level after deep findings are added
    score = sum(_finding_risk_score(f) for f in result.findings)
    result.risk_score = score
    if score >= 20:
        result.risk_level = "High"
    elif score >= 8:
        result.risk_level = "Medium"
    else:
        result.risk_level = "Low"


def _check_network_security_config(apk: APK, app_attribs: dict, result: "ScanResult") -> None:
    """
    Looks for a Network Security Config that trusts user/attacker-installable
    CAs (<certificates src="user"/>) or explicitly re-enables cleartext for
    specific domains — this is what actually enables MITM against an app
    that otherwise only talks HTTPS (e.g. via a rogue CA + proxy).
    """
    nsc_ref = app_attribs.get(f"{ANDROID_NS}networkSecurityConfig")
    candidates = []

    if nsc_ref:
        res_name = nsc_ref.split("/")[-1]
        for fname in apk.get_files():
            if fname.startswith("res/xml/") and res_name in fname and fname.endswith(".xml"):
                candidates.append(fname)

    if not candidates:
        for fname in apk.get_files():
            if fname.startswith("res/xml/") and fname.endswith(".xml"):
                candidates.append(fname)

    from androguard.core.axml import AXMLPrinter
    from lxml import etree

    for fname in candidates[:15]:
        try:
            raw = apk.get_file(fname)
            xml_str = etree.tostring(AXMLPrinter(raw).get_xml_obj(), encoding="unicode")
        except Exception:
            continue

        if "network-security-config" not in xml_str and "trust-anchors" not in xml_str:
            continue

        if re.search(r'src\s*=\s*"user"', xml_str):
            result.add(
                "Untrusted CA", "high",
                "Network Security Config trusts user-installed CAs",
                f"{fname} contains <certificates src=\"user\"/> — a certificate manually "
                "installed on the device (e.g. by an attacker via a MITM proxy) will be "
                "trusted for TLS, defeating certificate validation.",
                confidence="confirmed",
            )
        if re.search(r'cleartextTrafficPermitted\s*=\s*"true"', xml_str):
            result.add(
                "HTTP usage", "medium",
                "Network Security Config explicitly permits cleartext for a domain",
                f"{fname} allows plaintext HTTP for specific domain(s) — worth checking which.",
                confidence="confirmed",
            )
        break


def _check_native_libraries(apk: APK, result: "ScanResult") -> None:
    """
    Native (Native) branch of the analysis pipeline — an inventory step,
    explicitly NOT a disassembly/analysis step. Lists bundled .so files
    grouped by ABI/architecture and flags a few structural signals visible
    without actually disassembling the native code:
      - debug-looking .so filenames (common in dev builds accidentally shipped)
      - an unusually large number of ABIs (rare for a legitimate app, can
        indicate a fat/bloated build or an unusual toolchain)
      - presence of native code at all, since it's a real blind spot: this
        scanner does NOT disassemble/analyze native code — a finding here
        is a pointer to "go look at this with a native-code tool," not a
        verdict, exactly like a bare presence-based DEX finding.
    """
    so_files = [f for f in apk.get_files() if f.startswith("lib/") and f.endswith(".so")]
    if not so_files:
        return

    by_arch: Dict[str, List[str]] = {}
    for f in so_files:
        parts = f.split("/")
        arch = parts[1] if len(parts) > 2 else "unknown"
        by_arch.setdefault(arch, []).append(parts[-1])

    result.native_libs = [
        {"arch": arch, "count": str(len(libs)), "sample": ", ".join(sorted(set(libs))[:5])}
        for arch, libs in sorted(by_arch.items())
    ]

    result.add(
        "Native code", "info",
        f"{len(so_files)} native (.so) file(s) across {len(by_arch)} ABI(s)",
        "This scanner does not disassemble or analyze native code — this is an inventory "
        "only. If a vulnerability is suspected to live in native code (common for crypto, "
        "DRM, or anti-tamper logic), use a native-code-specific tool (e.g. Ghidra, IDA, "
        "radare2) separately; nothing about the DEX/manifest findings in this report covers "
        "native code.",
        confidence="confirmed",
    )

    debug_like = [f for f in so_files if re.search(r"debug|test|frida|xposed", f, re.I)]
    if debug_like:
        result.add(
            "Native code", "medium",
            f"{len(debug_like)} native lib(s) with debug/test/instrumentation-like names",
            f"Examples: {', '.join(debug_like[:5])}. Worth checking whether these are meant "
            "to ship in a release build, or a leftover dev/instrumentation artifact "
            "(a bundled Frida gadget in particular is a real, specific signal worth checking).",
            confidence="confirmed",
        )
def _get_bytecode_proof(m, keyword=None):
    try:
        cname = m.class_name.strip("L;").replace("/", ".")
    except Exception:
        cname = "UnknownClass"

    try:
        method_name = m.name
    except Exception:
        method_name = "UnknownMethod"

    proof = []

    try:
        method = m.get_method()
        code = method.get_code() if method else None

        if code:
            bc = code.get_bc()

            for index, ins in enumerate(bc.get_instructions()):
                try:
                    name = ins.get_name()
                    output = ins.get_output()

                    instruction = f"{name} {output}".strip()

                    if keyword is None or keyword.lower() in instruction.lower():
                        proof.append(
                            f"Instruction #{index}: {instruction}"
                        )

                except Exception:
                    continue

    except Exception as e:
        proof.append(f"Unable to extract bytecode: {e}")

    if not proof:
        proof.append("No matching bytecode instruction extracted.")

    return (
        f"Class: {cname}\n"
        f"Method: {method_name}\n"
        + "\n".join(proof[:10])
    )

def _check_trust_manager_trivial(dx, app_package_prefix, result):

    """
    A custom TrustManager.checkServerTrusted() that doesn't actually validate
    the chain (no throw of CertificateException, near-empty body) accepts
    ANY certificate.
    """

    for m in dx.find_methods(methodname="^checkServerTrusted$"):

        if not m.class_name.startswith(app_package_prefix):
            continue

        lines = _instr_lines(m)

        if not lines:
            continue

        has_throw = any(
            re.search(r"\bthrow\b|CertificateException", l)
            for l in lines
        )

        is_trivial = len(lines) <= 3

        cname = m.class_name.strip("L;").replace("/", ".")

        if is_trivial or not has_throw:

            # IMPORTANT:
            # m is available here because we are inside "for m ..."
            proof = _get_bytecode_proof(
                m,
                "checkServerTrusted"
            )

            result.add(
    "Untrusted CA",
    "high",
    f"checkServerTrusted() in {cname} appears to accept all certificates",

    (
        f"Found no exception-throwing / validation logic in this override "
        f"({len(lines)} instructions).\n\n"
        "PROOF:\n"
        f"{proof}\n\n"
        "This matches the classic empty-body TrustManager pattern "
        "that trusts any certificate."
    ),

    confidence="confirmed",

    evidence={
        "type": "bytecode-traced TrustManager",
        "class": cname,
        "method": m.name,
        "instruction_count": len(lines),
        "api": "javax.net.ssl.X509TrustManager.checkServerTrusted",

        "bytecode": lines,

        "validation_check": {
            "certificate_exception_reference": has_throw,
            "trivial_method": is_trivial,
        },

        "proof": (
            f"Class: {cname}\n"
            f"Method: {m.name}\n"
            f"Instructions: {len(lines)}\n"
            f"CertificateException/throw detected: {has_throw}\n"
            f"Trivial method: {is_trivial}"
        ),
    },
)

        else:

            proof = _get_bytecode_proof(
                m,
                "checkServerTrusted"
            )

            result.add(
                "MITM / hostname verification",
                "medium",
                f"checkServerTrusted() in {cname} — has some validation logic",
                (
                    "Contains throw/exception-related instructions, so it is not "
                    "the trivial accept-all pattern.\n\n"
                    "PROOF:\n"
                    f"{proof}"
                ),
            )


def _check_runtime_exec_deep(dx, app_package_prefix, result):
    """
    Confirm actual Runtime.exec() call sites in application-owned code.

    Reports:
      - application class
      - calling method
      - bytecode offset
      - exact invoke instruction
      - confidence = confirmed

    This avoids treating a generic method named "exec" as proof.
    """

    RUNTIME_CLASS = "Ljava/lang/Runtime;"

    try:
        # Find the actual Android Runtime.exec() API methods
        runtime_methods = dx.find_methods(
            class_name=r"^Ljava/lang/Runtime;$",
            methodname=r"^exec$"
        )

        found = False

        for runtime_method in runtime_methods:

            # Find methods in the APK that call Runtime.exec()
            for caller_class, caller_method, offset in runtime_method.get_xref_from():

                try:
                    caller_class_name = caller_class.name

                    # Only report application-owned code
                    if not caller_class_name.startswith(app_package_prefix):
                        continue

                    caller_method_name = caller_method.get_name()

                    # Get the actual calling method analysis object
                    caller_analysis = dx.get_method_analysis(caller_method)

                    bytecode_instruction = None

                    # Walk the caller's basic blocks to locate the
                    # instruction at the xref offset.
                    for block in caller_analysis.get_basic_blocks():

                        current_offset = block.get_start()

                        for ins in block.get_instructions():

                            if current_offset == offset:
                                bytecode_instruction = ins
                                break

                            current_offset += ins.get_length()

                        if bytecode_instruction is not None:
                            break

                    if bytecode_instruction is not None:
                        instruction_text = (
                            f"{bytecode_instruction.get_name()} "
                            f"{bytecode_instruction.get_output()}"
                        )
                    else:
                        instruction_text = (
                            "Runtime.exec() call instruction found, "
                            "but instruction text could not be resolved."
                        )

                    # Convert descriptor to readable Java-style name
                    readable_class = (
                        caller_class_name
                        .strip("L;")
                        .replace("/", ".")
                    )

                    proof = (
                        f"Confirmed actual Runtime.exec() call in "
                        f"application-owned code.\n\n"
                        f"Class: {readable_class}\n"
                        f"Method: {caller_method_name}\n"
                        f"Bytecode offset: 0x{offset:x}\n"
                        f"Instruction: {instruction_text}\n"
                        f"API: {RUNTIME_CLASS}->exec\n\n"
                        f"This is a bytecode-traced call site, not merely "
                        f"a string-pool or method-name match."
                    )
                    
                    result.add(
    "Banned APIs",
    "medium",
    f"Runtime.exec() confirmed in "
    f"{readable_class}.{caller_method_name}()",

    (
        "Confirmed actual Runtime.exec() call in application-owned code.\n\n"
        f"Class: {readable_class}\n"
        f"Method: {caller_method_name}\n"
        f"Bytecode offset: 0x{offset:x}\n"
        f"Instruction: {instruction_text}\n"
        f"API: {RUNTIME_CLASS}->exec"
    ),

    confidence="confirmed",

    evidence={
        "type": "bytecode-traced API call",
        "class": readable_class,
        "method": caller_method_name,
        "bytecode_offset": f"0x{offset:x}",
        "instruction": instruction_text,
        "api": f"{RUNTIME_CLASS}->exec",
    },
)
                    

                    found = True

                except Exception:
                    # Continue scanning other callers rather than failing
                    # the entire deep scan.
                    continue

        return found

    except Exception:
        return False

def _get_method_proof(m, keyword=None):
    """
    Return concrete bytecode evidence for a method.

    This gives:
      - application class
      - method name
      - instruction index
      - bytecode instruction

    This is more reliable than claiming a Java source line number,
    because APKs normally contain DEX bytecode rather than original
    source files.
    """
    try:
        cname = m.class_name.strip("L;").replace("/", ".")
    except Exception:
        cname = "UnknownClass"

    try:
        method_name = m.name
    except Exception:
        method_name = "UnknownMethod"

    proof_lines = []

    try:
        method = m.get_method()

        if method is None:
            return (
                f"Class: {cname}\n"
                f"Method: {method_name}\n"
                f"Bytecode evidence: unavailable"
            )

        code = method.get_code()

        if code is None:
            return (
                f"Class: {cname}\n"
                f"Method: {method_name}\n"
                f"Bytecode evidence: method has no code"
            )

        bc = code.get_bc()

        for idx, ins in enumerate(bc.get_instructions()):
            try:
                instruction = ins.get_name()

                try:
                    output = ins.get_output()
                except Exception:
                    output = ""

                text = f"{instruction} {output}".strip()

                if keyword is None or keyword.lower() in text.lower():
                    proof_lines.append(
                        f"Instruction {idx}: {text}"
                    )

            except Exception:
                continue

    except Exception as e:
        return (
            f"Class: {cname}\n"
            f"Method: {method_name}\n"
            f"Bytecode evidence unavailable: {e}"
        )

    if not proof_lines:
        proof_lines.append(
            "Matching bytecode instruction was not extracted."
        )

    return (
        f"Class: {cname}\n"
        f"Method: {method_name}\n"
        + "\n".join(proof_lines[:10])
    )

def analyze_apk(path: str, original_filename: str) -> ScanResult:
    result = ScanResult(file_name=original_filename, sha256=sha256_of(path))

    analysis_path = prepare_apk_for_analysis(path)

    apk = APK(analysis_path)

    # Basic APK metadata
    result.package_name = apk.get_package() or ""
    result.app_name = apk.get_app_name() or ""

    # ---------------------------------------------------------
    # Version information
    # Some APKs may not contain a normal "Name" version field.
    # Do NOT allow this to crash the complete scan.
    # ---------------------------------------------------------

    try:
        android_version = apk.get_androidversion() or {}
    except Exception:
        android_version = {}

    if not isinstance(android_version, dict):
        android_version = {}

    result.version_name = str(
        android_version.get("Name") or ""
    )

    result.version_code = str(
        android_version.get("Code") or ""
    )

    # ---------------------------------------------------------
    # SDK information
    # ---------------------------------------------------------

    try:
        min_sdk = apk.get_min_sdk_version()
    except Exception:
        min_sdk = None

    try:
        target_sdk = apk.get_target_sdk_version()
    except Exception:
        target_sdk = None

    result.min_sdk = (
        str(min_sdk) if min_sdk is not None else "not declared"
    )

    result.target_sdk = (
        str(target_sdk) if target_sdk is not None else "not declared"
    )

    try:
        manifest_root = apk.get_android_manifest_xml()
        app_el = manifest_root.find("application")
        app_attribs = app_el.attrib if app_el is not None else {}
    except Exception:
            manifest_root = None
            app_attribs = {}

    result.is_debuggable = app_attribs.get(f"{ANDROID_NS}debuggable") == "true"
        # allowBackup defaults to true on Android unless explicitly disabled
    result.allows_backup = app_attribs.get(f"{ANDROID_NS}allowBackup", "true") == "true"

        # ---- Manifest / permission analysis -----------------------------------
    perms = apk.get_permissions() or []
    result.permissions = perms
    perm_set = set(perms)

    for p in perms:
        if p in DANGEROUS_PERMISSIONS:
            result.add(
                "Permissions", "info",
                f"Dangerous permission: {p.split('.')[-1]}",
                DANGEROUS_PERMISSIONS[p] + " Capped at low: a declared permission alone isn't "
                "a vulnerability — nearly every app requesting camera/location/contacts access "
                "is doing so legitimately. A specific risky COMBINATION of permissions (see "
                "below) is a stronger signal than any single permission in isolation.",
                confidence="confirmed",
            )
            

    for combo, msg in RISKY_COMBOS:
        if combo.issubset(perm_set):
            result.add("Permissions", "high", "Risky permission combination", msg, confidence="confirmed")

    if result.is_debuggable:
        result.add(
            "Manifest", "medium", "App is debuggable",
            "android:debuggable=\"true\" in a distributed APK — should never ship like this; "
            "allows attaching a debugger and dumping memory/data. Capped at medium rather than "
            "high: true and a real release-hygiene failure, but not automatically exploitable "
            "by itself (an attacker needs local/physical access or another vector to leverage it).",
            confidence="confirmed",
        )

    if result.allows_backup:
        result.add(
            "Manifest", "low", "allowBackup enabled",
            "App data can be extracted via adb backup on rooted/debug-enabled devices.",
            confidence="confirmed",
        )

    try:
        uses_cleartext = app_attribs.get(f"{ANDROID_NS}usesCleartextTraffic")
        min_sdk_int = int(min_sdk) if min_sdk is not None else 0
        if uses_cleartext == "true" or (uses_cleartext is None and min_sdk_int < 28):
            result.uses_cleartext_traffic = True
            result.add(
            "Network",
            "medium",
            "Cleartext (HTTP) traffic allowed",
            "App can send unencrypted HTTP traffic — data can be intercepted on the network.",
            confidence="confirmed",
            evidence={
                "type": "AndroidManifest.xml",
                "file": "AndroidManifest.xml",
                "manifest_attribute": "android:usesCleartextTraffic=\"true\"",
                "proof": "android:usesCleartextTraffic=\"true\""
            },
        )
    except Exception:
        pass

    # ---- Exported components -----------------------------------------------
    # A component is effectively exported if z, OR if
    # it's unset but the component has an intent-filter (implicit export
    # pre-Android-12 behavior), and it declares no permission guard.
    try:
        for comp_type in ("activity", "service", "receiver", "provider"):
            for el in manifest_root.iter(comp_type):
                name = el.attrib.get(f"{ANDROID_NS}name", "?")
                exported_attr = el.attrib.get(f"{ANDROID_NS}exported")
                permission = el.attrib.get(f"{ANDROID_NS}permission")
                has_intent_filter = el.find("intent-filter") is not None

                is_exported = exported_attr == "true" or (
                    exported_attr is None and has_intent_filter
                )
                if is_exported and not permission:
                    result.exported_components.append({"type": comp_type, "name": name})
    except Exception:
        pass

    if result.exported_components:
        by_type: Dict[str, int] = {}
        for c in result.exported_components:
            by_type[c["type"]] = by_type.get(c["type"], 0) + 1
            print("\n=== EXPORTED COMPONENTS ===")
            for component in result.exported_components:
                print(
                    f"{component.get('type', 'unknown').upper()}: "
                    f"{component.get('name', 'unknown')}"
                )
        print("============================\n")

        type_label = {
            "activity": ("Exported Activity", "low"),
            "service": ("Exported Service", "low"),
            "receiver": ("Exported Broadcast Receiver", "low"),
            "provider": ("Exported Content Provider", "medium"),
        }

        # Sensitivity escalation for exported Content Providers specifically
        # (per calibration: "High only if sensitive data/operations are
        # accessible" — rather than leave this as a flat guess, check two
        # concrete, cheap signals: does the app hold sensitive-data
        # permissions at all, and does the provider's own class name hint
        # at sensitive content). Neither is proof, but together they're a
        # meaningfully better basis for "high" than assuming every exported
        # provider is equally dangerous regardless of what it holds.
        _SENSITIVE_PERMS = {
            "android.permission.READ_CONTACTS", "android.permission.READ_CALL_LOG",
            "android.permission.READ_SMS", "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION", "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
        }
        _SENSITIVE_NAME_RE = re.compile(
            r"user|account|payment|credential|contact|message|token|card|bank|auth|wallet",
            re.I,
        )
        app_has_sensitive_perms = bool(_SENSITIVE_PERMS & set(perms))
        provider_names = [c["name"] for c in result.exported_components if c["type"] == "provider"]
        provider_name_looks_sensitive = any(_SENSITIVE_NAME_RE.search(n) for n in provider_names)

        for comp_type, count in by_type.items():
            label, sev = type_label.get(comp_type, (f"Exported {comp_type}", "low"))
            escalation_note = ""
            component_names = [
                    c["name"]
                    for c in result.exported_components
                    if c["type"] == comp_type
                ]
            result.add(
                "Attack surface",
                sev,
                f"{label}: {count} unguarded",
                (
                    f"Other apps can interact with this exported "
                    f"{comp_type} without a declared permission."
                ),
                confidence="confirmed",
                evidence={
                    "component_type": comp_type,
                    "count": count,
                    "components": component_names,
                },
            )
            

    # ---- Network security config (trusting user/attacker-installed CAs) -----
    try:
        _check_network_security_config(apk, app_attribs, result)
    except Exception:
        pass

    # ---- Native code inventory (Native branch — inventory only, no disassembly) --
    try:
        _check_native_libraries(apk, result)
    except Exception:
        pass

    # ---- Certificate analysis -----------------------------------------------
    try:
        certs = apk.get_certificates()
        if certs:
            cert = certs[0]
            issuer = cert.issuer.human_friendly
            subject = cert.subject.human_friendly
            result.cert_info = {
                "issuer": issuer,
                "subject": subject,
                "serial": str(cert.serial_number),
                "not_before": str(cert.not_valid_before),
                "not_after": str(cert.not_valid_after),
                "self_signed": issuer == subject,
            }
            if result.cert_info["self_signed"]:
                result.add(
                    "Signing", "info", "Self-signed certificate",
                    "Normal for many legitimate apps and dev builds, but means there's no CA "
                    "chain vouching for the publisher's identity.",
                    confidence="confirmed",
                )
            if "Android Debug" in issuer or "androiddebugkey" in issuer.lower():
                result.add(
                    "Signing", "medium", "Signed with the default Android debug key",
                    "This build was never re-signed for release — strong signal it's a debug/"
                    "test build, or that release signing was mishandled. Capped at medium: a "
                    "real release-signing weakness, but it doesn't by itself expose data the "
                    "way a live vulnerability does — a debug-signed build just can't be trusted "
                    "as a legitimate release artifact.",
                    confidence="confirmed",
                )
        else:
            result.add("Signing", "high", "No certificate found", "APK is unsigned or signature could not be parsed.", confidence="confirmed")
    except Exception as e:
        result.add("Signing", "low", "Certificate parsing failed", str(e))

    # ---- String / code-level scan -------------------------------------------
    _LIB_CAVEAT = (
        " Note: this pass scans the whole compiled APK's string pool with no "
        "per-class attribution — it cannot tell whether this comes from the "
        "app's own code or a bundled third-party library (ad/analytics SDKs "
        "commonly trigger these). Confirmed against a real app: an "
        "addJavascriptInterface finding traced back turned out to be entirely "
        "inside Google Play Services' bundled code, not the app's own. Enable "
        "deep bytecode analysis for findings attributed to a specific class."
    )
    try:
        d = apk.get_dex()
        if d:
            strings_blob = _extract_dex_strings(apk)

            for pattern, severity, desc in SUSPICIOUS_CODE_PATTERNS:
                if re.search(pattern, strings_blob):
                    result.add(
                        "Code patterns",
                        severity,
                        f"Pattern found: {pattern}",
                        (
                            "APK-wide heuristic match. "
                            + desc
                            + _LIB_CAVEAT
                        ),
                        confidence="heuristic",
                        evidence={
                            "scope": "APK-wide string pool",
                            "attribution": "unknown",
                        },
                    )

            # Deep checklist-style checks (crypto, WebView, storage, SQL, etc.)
            categories_hit = set()
            for pattern, category, severity, title, detail in DEEP_CODE_CHECKS:
                if re.search(pattern, strings_blob):
                    result.add(
                        category,
                        severity,
                        title,
                        "APK-wide heuristic match. "
                        + detail
                        + _LIB_CAVEAT,
                        confidence="heuristic",
                        evidence={
                            "scope": "APK-wide string pool",
                            "attribution": "unknown",
                        },
                    )
                    categories_hit.add(category)

            for tokens, category, severity, title, detail in CORRELATION_CHECKS:
                if all(tok in strings_blob for tok in tokens):
                    result.add(
                        category,
                        severity,
                        title,
                        "APK-wide heuristic correlation. "
                        + detail
                        + _LIB_CAVEAT,
                        confidence="heuristic",
                        evidence={
                            "scope": "APK-wide string pool",
                            "attribution": "unknown",
                            "matched_tokens": tokens,
                        },
                    )
                    categories_hit.add(category)

            # Banned/weak-API rollup: surfaced only if at least one contributing
            # category actually fired, so this doesn't add noise on clean apps.
            banned_hit = categories_hit & {
                "Weak encryption", "Weak hashing", "Predictable RNG",
            }
            if banned_hit:
                result.add(
                    "Banned APIs", "info",
                    f"{len(banned_hit)} banned/weak-API categor{'y' if len(banned_hit)==1 else 'ies'} triggered",
                    "Rollup of the weak-crypto/weak-hash/weak-RNG findings above — these are "
                    "APIs considered unsafe for security-sensitive use in modern guidance.",
                )

            # Hardcoded secrets
            for pattern, label in SECRET_PATTERNS.items():
                if re.search(pattern, strings_blob):
                    result.add(
                        "Hardcoded data", "high", f"Possible hardcoded secret: {label}",
                        "A string matching a known credential format was found in the compiled "
                        "code — if real, this key/token should be revoked and moved server-side.",
                    )

            # Tapjacking: informational nudge since this can't be reliably proven
            # from string search alone (needs per-View layout inspection).
            if "setFilterTouchesWhenObscured" not in strings_blob:
                result.add(
                    "Tapjacking protection", "info",
                    "No evidence of setFilterTouchesWhenObscured",
                    "Couldn't find calls that enable touch-filtering when a view is obscured. "
                    "Worth a manual check on sensitive buttons (payment/consent screens) — "
                    "its absence doesn't confirm a vulnerability, but its presence would rule "
                    "one out.",
                )

            urls = set(URL_PATTERN.findall(strings_blob))
            ips = set(IP_PATTERN.findall(strings_blob))
            result.urls_found = sorted(urls)[:50]
            result.ips_found = sorted(ips)[:50]

            if urls:
                result.add(
                    "Network strings", "info", f"{len(urls)} hardcoded URL(s) found",
                    "Review these manually — not inherently malicious, but a common place to "
                    "spot C2 endpoints or analytics/ad SDKs.",
                )
    except Exception as e:
        result.add("Code patterns", "low", "DEX string scan failed", str(e))

    # ---- Score & finalize -----------------------------------------------------
    score = sum(_finding_risk_score(f) for f in result.findings)
    result.risk_score = score
    if score >= 20:
        result.risk_level = "High"
    elif score >= 8:
        result.risk_level = "Medium"
    else:
        result.risk_level = "Low"

    return result


def _extract_dex_strings(apk: APK, max_bytes: int = 20_000_000) -> str:
    """Pull the printable string pool out of all DEX files, capped for safety."""
    chunks = []
    total = 0
    for dex_bytes in apk.get_all_dex():
        total += len(dex_bytes)
        if total > max_bytes:
            break
        # crude but fast: printable ASCII runs of length >= 5
        chunks.append(
            b" ".join(re.findall(rb"[\x20-\x7e]{5,}", dex_bytes)).decode("ascii", errors="ignore")
        )
    return " ".join(chunks)

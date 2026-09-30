# APK Static Scanner

A local, static-analysis tool for APK files. Upload an APK, get a risk score
and a breakdown of manifest/permission/certificate/code-pattern findings.

**Important:** this performs *static* analysis only — it parses the manifest,
certificate, and DEX strings. It never installs or executes the APK. It's a
triage aid, not a malware verdict; always cross-check anything it flags.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
streamlit run app.py
```

Opens at `http://localhost:8501`. Upload a `.apk` file and it'll scan it in
place — nothing leaves your machine.

## Two scan modes

**Fast pass (always runs):** manifest/cert parsing + string search across the compiled DEX.
Takes under a second for most APKs.

**Deep bytecode pass (opt-in checkbox — 5s to 60s+ depending on APK size):** uses
androguard's full cross-reference engine to trace actual call sites instead of just
searching strings. This exists because real testing turned up things the fast pass
*cannot* see, structurally:

- `Context.MODE_WORLD_READABLE`/`MODE_WORLD_WRITEABLE` are `public static final int`
  constants — Java inlines them as raw integers at compile time, so the symbolic name
  never appears in the compiled DEX string pool. The deep pass instead traces calls to
  `getSharedPreferences`/`openFileOutput`/`openOrCreateDatabase` and reads back the
  actual inlined mode value from the bytecode.
- Hardcoded crypto key/IV material is often defined in one method (e.g. a field
  initializer in `<init>`) and consumed in a different method where `SecretKeySpec`/
  `IvParameterSpec` actually get constructed — method-local string search misses this
  pairing entirely. The deep pass correlates at the class level instead.

Both were validated against real vulnerable code, not just written speculatively — see
below.

## URL input — auto-fixes and validation

The URL option auto-converts GitHub/GitLab "blob" preview links (which serve an HTML page,
not the file) to their raw-download equivalents, and validates the downloaded content is
actually a ZIP/APK (checks for the `PK` magic bytes) before handing it to the analyzer —
so a bad URL gives a clear error instead of a cryptic "EOCD signature not found" ZIP error.

## Validated against a second real vulnerable app (PIVAA)

[PIVAA](https://github.com/HTBridge/pivaa) is a real intentionally-vulnerable test app —
and turned out to be the actual source of the vulnerability checklist used throughout this
project's testing. Running the scanner against it directly caught **two real bugs** that
InsecureBankv2 testing hadn't surfaced, because it doesn't happen to have custom
`checkServerTrusted()`/layout-heavy screens the way PIVAA does:

- **`_check_tapjacking_layouts` and `_check_network_security_config` were silently broken.**
  Both used `str(AXMLPrinter(raw).get_xml_obj())` to get the layout/NSC XML as text — but
  `str()` on an lxml Element returns a Python repr like `<Element Button at 0x7f...>`, not
  the actual serialized markup. Every regex search against that string was checking a
  near-empty repr, not real XML content, so these checks always silently found nothing —
  no crash, no error, just quietly useless. Fixed by using `etree.tostring(obj,
  encoding="unicode")` instead. Re-verified against pivaa.apk: both now fire correctly.
- Once fixed, running the deep pass against PIVAA gave the first real, validated positive
  hits for checks that were previously untested (InsecureBankv2 doesn't exercise them):
  - `checkServerTrusted()` in `com.htbridge.pivaa.handlers.API$2` confirmed to accept all
    certificates (Untrusted CA / MITM) — the exact check I'd previously flagged as "built
    but not validated against a real positive case."
  - `rawQuery()` in `DatabaseHelper.getRecord()` confirmed built via `StringBuilder`
    (register-traced SQL injection signal).
  - `MODE_WORLD_WRITEABLE` passed to `openFileOutput()` — same check as before, now
    confirmed on a second, independent app.
  - Tapjacking: confirmed no layout sets `filterTouchesWhenObscured="true"` (now that the
    check actually parses real XML).

Self-signed-CA-in-WebView and the generic hardcoded-secret-comparison check still didn't
fire on PIVAA — verified as genuine true negatives (no `onReceivedSslError` override at
all; the app's real `.equals()` calls compare two variables, never a literal). Still no
positive test case in hand for the self-signed-CA-in-WebView check specifically.

## Hardcoded credentials — a third detection pattern, plus a real noise problem caught and fixed

Went back to PIVAA's actual source (not just the compiled APK) specifically looking for
hardcoded credentials, since "Hardcoded data" was the one category with no positive test
case at all. Found the real thing in `Configuration.java`:

```java
public String username = "test";
public String password = "verycomplicatedpassword";
```

Neither existing check could catch this — it's not compared via `.equals()` anywhere, and
it's not correlated with `SecretKeySpec`/`IvParameterSpec` construction. It's the simplest
and most common real-world pattern: a plain field with a literal assignment. Added
`_check_hardcoded_credential_fields`, which traces `const-string` → `iput-object`/
`sput-object` pairs for fields with credential-shaped names (`password`, `secret`,
`apikey`, `token`, etc. at high confidence; `username`/`login` at medium, only reported
alongside a strong-signal field in the same class to avoid noise). Verified against real
bytecode — it recovers the exact field names and literal values from `Configuration.java`.

**While regression-testing this against the two non-vulnerable-by-design sample apps
(jamendo, a2dp.Vol), the existing `.equals()`-comparison check turned out to be
significantly noisier than it looked when only tested against vulnerable-by-design apps:**
13 and 16 false positives respectively — Intent action strings
(`"android.intent.action.ACTION_POWER_CONNECTED"`), SQLite schema table names
(`"sqlite_sequence"`), and UI preference values (`"always"`, `"Custom"`) all match
"compares a variable to a string literal," which turns out to be one of the most common
patterns in Java generally, not a credential signal on its own. Fixed by requiring the
comparison's class or method name to contain an auth/security-related keyword (`login`,
`auth`, `password`, `token`, `verify`, `admin`, etc.) before reporting — re-tested and
confirmed **zero** false positives on both clean apps, while still catching the real
InsecureBankv2 backdoor-username case (`DoLogin$RequestTask.postData()` — the class name
itself contains "Login"). This is a blunt filter — a real backdoor check with an
innocuous-sounding method name would still be missed — but it's honestly better than a
category that cries wolf 13+ times per scan on ordinary apps.

**Deep bytecode pass now also covers** (added after further testing):
- `checkServerTrusted()` triviality — flags **high** if a custom `TrustManager` implementation has no throw/exception-validation logic (the classic accept-all-certs pattern), vs. **medium** (manual review) if it has some logic present. *Not yet validated against a real positive example — InsecureBankv2 doesn't have a custom TrustManager, so this is implemented and tested not to crash/false-positive, but not confirmed against real vulnerable code the way the other deep checks are.*
- `onReceivedSslError()` behavior — flags **high** if it calls `proceed()` (accepts the invalid cert unconditionally), **low** if it calls `cancel()` (correct behavior, flagged for visibility only), **medium** if neither is detected. *Same caveat — not yet validated against a real positive example.*
- SQL query arguments built via `StringBuilder` — register-level traced (not just "both exist in this method"). **This one has an honest failure story worth knowing:** the first version flagged `TrackUserContentProvider.query()` as SQL-concatenation risk because it contains both a SQL call and a `StringBuilder` — but on inspection, the `StringBuilder` was building an unrelated `IllegalArgumentException` message, not the query string. Fixed by tracing whether the `StringBuilder.toString()` result register actually feeds the sink call's argument, not just co-occurring in the method. Re-tested against InsecureBankv2 — the false positive is gone, and the app genuinely has no `StringBuilder`-built SQL argument, so no finding fires here (true negative, not another miss).

## What it checks

Structurally verified (from the manifest/cert — high confidence):
- `debuggable`, `allowBackup`, cleartext traffic allowed
- Dangerous permissions and known risky *combinations* (e.g. SMS read + internet — classic OTP-theft pattern)
- Exported Activities / Services / Broadcast Receivers / Content Providers with no permission guard
- Self-signed cert, debug-keystore signing
- Network Security Config trusting user-installed CAs (MITM-enabling), or explicit per-domain cleartext exceptions

Deep bytecode checks (high confidence — actual call-site tracing, opt-in):
- World-readable/writable files (`MODE_WORLD_READABLE`/`WRITEABLE`)
- Hardcoded encryption key/IV material (class-level correlation)

Presence-based code checks (found in compiled DEX strings — a signal to go *look*, not proof of exploitability; each finding says what to verify):

| Category | Detected | Confidence |
|---|---|---|
| Weak initialization vector | ✅ | presence |
| MITM / hostname verification | ✅ | presence |
| Remote URL in WebView | ✅ | presence |
| Object deserialization | ✅ | presence |
| User input in SQL queries | ✅ | presence |
| Tapjacking protection | ✅ | informational only |
| Application backup | ✅ | structural |
| Debug mode | ✅ | structural |
| Weak encryption (DES/RC4/ECB) | ✅ | presence |
| Hardcoded encryption keys | ✅ | **deep pass: confirmed** / fast pass: presence |
| Dynamic code loading | ✅ | presence |
| World-readable/writable files | ✅ | **deep pass only** — fast pass can't see it (see above) |
| HTTP usage | ✅ | structural |
| Weak hashing (MD5/SHA-1) | ✅ | presence |
| Predictable RNG | ✅ | presence |
| Exported Content Provider | ✅ | structural |
| Exported Broadcast Receiver | ✅ | structural |
| Exported Service | ✅ | structural |
| JavaScript enabled in WebView | ✅ | presence |
| Deprecated `setPluginState` | ✅ | presence |
| Temporary files | ✅ | presence |
| Hardcoded data (AWS/Google/GitHub/Slack key formats, embedded PEM keys) | ✅ | presence, format-matched |
| Untrusted CA | ✅ | structural (via Network Security Config XML) |
| Banned APIs (rollup of weak-crypto/hash/RNG + Runtime.exec correlation) | ✅ | presence/correlation |
| Self-signed CA in WebView | ✅ | presence |
| Path traversal | ✅ | presence |
| Cleartext SQLite | ✅ | presence |

Validated against [InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2),
a well-known intentionally-vulnerable test app — the fast pass correctly flags its exported
content provider, WebView JS + JS-bridge, raw SQL calls, `Runtime.exec`, path-traversal
strings, debug signing, and cleartext HTTP. The deep pass additionally found:
- `MyBroadCastReceiver.onReceive()` calling `getSharedPreferences()` with a world-readable
  mode flag — confirmed by reading the app's actual source, this is real and the fast pass
  genuinely cannot see it (compiler-inlined constant).
- The literal hardcoded AES key string in `CryptoClass` — again confirmed against real source.

**Important caveat on the presence-based code-pattern checks:** these work by searching
for class/method name strings in the compiled DEX's string table — real signal (that's
how tools like this typically bootstrap detection), but a presence hit doesn't prove the
code path is reachable or exploitable, and heavy string-encryption/obfuscation could hide
a token from this pass. Treat every presence-based finding as "go read this call site,"
not a confirmed vulnerability. The deep-pass findings are meaningfully stronger evidence
since they trace real call sites and literal values, but still aren't full taint analysis
(they don't yet prove *external* user input reaches a SQL/WebView sink — see the tool's
SQL-injection/XSS limitations below).

**What's still not covered, honestly:** true taint analysis (tracing whether external/
attacker-controlled input — not just any input — reaches a dangerous sink like
`execSQL`/`loadUrl`), dynamic/runtime behavior, native `.so` code, and detection of
string-encrypted/heavily obfuscated APKs where API names never appear in cleartext at all.

Each finding gets a severity (info/low/medium/high) and rolls up into an overall
Low/Medium/High risk score — this is a heuristic, not ground truth.

## Files

- `app.py` — Streamlit UI
- `apk_analyzer.py` — the actual analysis engine (usable standalone /
  scriptable without the UI — see `analyze_apk(path, filename)`)
- `requirements.txt`

## Before you host this publicly

This was built for local use. Before putting it on the internet:

1. **Isolate the analysis step.** `androguard` parses untrusted, potentially
   malicious input — run it in a locked-down container/subprocess with
   CPU/memory/time limits, not directly in your web server process.
2. **Add file-size caps and real upload validation** (magic-byte checks, not
   just the `.apk` extension) — already stubbed in `app.py` via
   `MAX_UPLOAD_MB`, but tighten it for prod.
3. **Rate-limit and auth-gate** uploads — public malware-scanning endpoints
   are an abuse magnet.
4. **Clean up temp files** aggressively (already done per-scan, but audit
   under concurrent load).
5. Consider adding a **VirusTotal hash lookup** as a second opinion — cheap
   to add, meaningfully improves signal for known-malware families.

Happy to help with any of these when you're ready to move past local testing.

## Self-signed CA in WebView — finally validated (third real vulnerable app)

Neither InsecureBankv2 nor PIVAA has this vulnerability — confirmed via their actual
source (`WebviewActivity` in PIVAA never overrides `WebViewClient` at all). Found and
downloaded [InsecureShop](https://github.com/hax0rgb/InsecureShop) (prebuilt APK via
[optiv/InsecureShop releases](https://github.com/optiv/InsecureShop/releases)) — its
public writeups specifically document `CustomWebViewClient.onReceivedSslError()` calling
`handler.proceed()`. Ran the scanner against it: both the presence-based fast-pass check
and the deep-pass bytecode check fired correctly, naming the exact class
(`com.insecureshop.util.CustomWebViewClient`) that the independent public writeup names.
First real, validated positive for this check.

## Hardcoded credentials — a fourth pattern found, and a systemic Kotlin blind spot fixed

Went looking specifically for "Hardcoded data" in InsecureShop (a Kotlin app) since it's
explicitly one of its documented vulnerabilities, and found the real credential in
`Util.kt`:

```kotlin
private fun getUserCreds(): HashMap<String,String> {
    val userCreds = HashMap<String, String>()
    userCreds["shopuser"] = "!ns3csh0p"
    return userCreds
}
```

None of the three existing hardcoded-data checks caught this — it's not a field
assignment, and it's not compared via `.equals()` at the literal's call site (the value is
retrieved from the map first, then compared). This compiles to `Map.put("shopuser",
"!ns3csh0p")` with both arguments as literal `const-string` operands — a fourth distinct
pattern. Added `_check_hardcoded_credential_map`, restricted to `put()` calls in
methods/classes with credential-suggestive names, and verified it recovers the exact
key/value pair from real bytecode.

**While building this, found something more significant:** Kotlin's `.equals()`/`==` on
strings does NOT compile to `java.lang.String.equals()` the way Java's does — it compiles
to `kotlin.jvm.internal.Intrinsics.areEqual()` or `kotlin.text.StringsKt.equals$default()`
depending on the exact source pattern. The existing `_check_hardcoded_secret_comparison`
only ever searched for `java.lang.String.equals`/`equalsIgnoreCase`, meaning it was
**categorically blind to every string comparison in every Kotlin app** — not a tuning
problem, a structural one, the same category of issue as the `MODE_WORLD_READABLE`
compiler-inlining case from earlier testing. Given Kotlin is Android's default language
for new apps, this was a meaningful gap. Fixed by also tracing `Intrinsics.areEqual` and
`StringsKt.equals`/`equals$default` call sites the same way, checking all argument
positions (Kotlin's various equals helpers put the literal in different argument slots
depending on which one gets used) rather than just the last argument.

Regression-tested across all six sample apps after these two additions: zero crashes,
zero new false positives on the two clean (non-vulnerable-by-design) apps, and all three
vulnerable test apps (InsecureBankv2, PIVAA, InsecureShop) now have a validated
"Hardcoded data" hit via three genuinely different detection mechanisms — field
assignment, `.equals()` comparison, and Map storage.

## Hardcoded key/IV as byte-array literals — a fifth pattern, caught and self-corrected before shipping

Comparing scanner output against PIVAA's real `Encryption.java` line by line surfaced one
more gap: `byte[] key = {1, 2, 3, 4, 5, 6, 7, 8, 8, 7, 6, 5, 4, 3, 2, 1};` is a hardcoded
AES key — but as a **numeric byte-array literal**, not a string. Java compiles this to
`new-array` + `fill-array-data` (pointing at a `fill-array-data-payload` pseudo-instruction
holding the actual bytes), a completely different bytecode shape than `const-string`. None
of the four existing hardcoded-data checks could see it.

Added `_check_hardcoded_key_bytes`, which extracts the real byte payload and register-
traces it forward to whichever constructor (`SecretKeySpec` or `IvParameterSpec`) actually
consumes it — with a specific reason for that precision: **the first version of this
check was method-level only, and PIVAA's methods construct both a key and an IV in the
same method, so it cross-attributed every byte array to every category present** —
reporting the all-zero IV bytes as "hardcoded key" too. Caught by inspecting the raw
instruction sequence before shipping, not by luck: `invoke-direct` on a constructor lists
the receiver object (`this`) as its first register and the actual argument second, and the
first version of the fix used the wrong index (checked register 0, the receiver, instead
of register 1, the array) — this initially caused the check to silently find nothing at
all, then after correcting the index, correctly separated the two categories.

Verified byte-for-byte against source: extracts exactly `00 00 00 ... 00` for the IV
(correctly flagged as **degenerate/all-zero, high severity**) and exactly
`01 02 03 04 05 06 07 08 08 07 06 05 04 03 02 01` for the key from three different methods
in `Encryption.java`, matching the method count and structure in the real source exactly
(two methods declare both a key and IV; one declares only a key — the finding count
matches this precisely). Regression-tested across all six sample apps: zero false
positives on the five apps that don't have this pattern, zero crashes.

## Severity/confidence audit — fixed mislabeled structural facts, downgraded an overstated heuristic, de-duplicated overlapping findings

Went through every HIGH and MEDIUM severity finding across all six sample apps looking
specifically for two things: findings whose confidence label understated how certain they
actually are, and findings whose severity overstates how certain they actually are.

**Confidence mislabeling (structural facts wrongly marked "heuristic"):** `debuggable`,
`allowBackup`, cleartext traffic, exported-component, and certificate/signing findings are
all parsed directly from the manifest/certificate — deterministic facts, not string-search
guesses. They'd never been explicitly marked `confidence="confirmed"` (the confidence field
was added later, only applied to the new deep-scan bytecode checks) — fixed so the "how
sure are we" label in the UI now matches reality for these.

**A genuinely overstated heuristic, caught by tracing real source:**
`Runtime.exec` + `Ljava/lang/Runtime;` co-occurrence was flagged **high** severity. Traced
the actual call site in InsecureBankv2's real source: `Runtime.getRuntime().exec(new
String[]{"/system/bin/which", "su"})` — a hardcoded root-detection check with no
attacker-controlled input anywhere near it, not command injection. This exact pattern
(checking for `su`/root) is extremely common and mostly benign in real apps. Downgraded to
**medium** and reworded to name this as the common real-world cause.

**A real attribution gap, not a false positive exactly, but a false-confidence risk:**
traced an `addJavascriptInterface` finding in InsecureBankv2 back to its actual definition —
it's entirely inside `com.google.android.gms.internal.zzig`, a bundled Google Play Services
class, not the app's own code at all. This exposed a structural limitation: the fast pass
scans the whole compiled APK's string pool with **no per-class attribution**, so every
fast-pass finding could be coming from a bundled third-party SDK rather than the app's own
code — the deep pass (which filters to the app's own package) doesn't have this problem.
Added an explicit caveat to every fast-pass code-pattern/deep-check-heuristic/correlation
finding's detail text stating this limitation plainly, using the real confirmed example as
evidence rather than a hypothetical.

**De-duplication:** when the deep pass gets a confirmed answer for self-signed-CA-in-WebView
(`onReceivedSslError` calling `proceed()` vs `cancel()`), the vaguer fast-pass "override
found, go check it" finding for the same category is now removed — same pattern already
used for tapjacking. Verified on InsecureShop: was 2 findings for this category (1 generic
presence note + 1 specific confirmed answer), now correctly just the 1 confirmed one.

Regression-tested across all six sample apps after these changes: zero crashes, correct
dedup counts, no unintended findings lost.

## Play Store listing lookup (metadata only — not a substitute for scanning the APK)

Added a third input mode: paste a Play Store URL and see the **public listing** — developer
info, ratings, disclosed permission categories, content rating, ad/IAP status, etc. Built on
[`google-play-scraper`](https://pypi.org/project/google-play-scraper/), a real maintained
library (not hand-rolled HTML scraping) that parses the JSON data Google embeds in the
listing page's initial HTML.

**Honest testing caveat:** this sandbox's network policy blocks `play.google.com` outright
(confirmed via a direct 403 with `host_not_allowed`), so I could not run this feature
fully end-to-end here. What I *did* verify:
- Fetched real Play Store listing HTML via a separate tool with different network access
  (web search + fetch) to confirm the page structure and field availability before writing
  any code against it, rather than guessing at Google's internal JSON layout blind.
- Confirmed `google-play-scraper` is a real, actively maintained PyPI package with a stable
  documented field schema (`title`, `developer`, `score`, `installs`, `contentRating`,
  `permissions()`, etc.) rather than writing fragile custom regex/JSON-blob parsing myself.
- Verified the exact same network failure mode (403, `host_not_allowed`) confirms this is a
  sandbox restriction, not a library or code problem — it will work normally on the user's
  own machine with real internet access.
- Tested URL parsing against the real URL formats Google actually uses (confirmed two
  different real shapes via the live fetch above), plus `market://details?id=...` URIs.
- Tested the render function against a mocked response matching the *exact* field schema
  read from the library's own source code, and confirmed it renders without error.
- Tested error handling: an unreachable/blocked fetch correctly surfaces as a clean
  `ValueError` with a readable message rather than a raw stack trace.

**Deliberately scoped to metadata only.** This does not attempt to download the actual APK
from the Play Store — there's no legitimate way to do that outside the official Play Store
app/Console, and building that would cross into APK-piracy-adjacent territory. The Play
Store tab includes a "Compare to a scanned APK" section with manual cross-check guidance
(package name match, signing consistency, permission count sanity-check) for when you scan
the real APK separately via Upload or Fetch from URL.

## Full HIGH/MEDIUM audit pass — one real false positive fixed, two findings correctly reworded, everything else verified genuine

Pulled every HIGH and MEDIUM finding across all six sample apps into one list and checked
each category against real evidence rather than trusting the output looked plausible.

**Real false positive, fixed:** `getDeviceId` (labeled "Reads device IMEI —
fingerprinting/tracking") was a bare single-token string match — confirmed it also matches
`android.view.KeyEvent.getDeviceId()` (an input-device ID for key/controller events,
nothing to do with IMEI) and coincidental hits inside bundled Google Play Services classes.
Moved it from a single-token check into a correlation check requiring
`Landroid/telephony/TelephonyManager;` co-occurrence, the same technique already used for
`Runtime.exec`. Re-tested: PIVAA's finding for this category **disappeared entirely** —
proof it was 100% a false positive there (no TelephonyManager token anywhere in that app at
all). InsecureBankv2 and InsecureShop still show it, now on firmer ground.

**A "confirmed" finding on a real (non-vulnerable-by-design) app, investigated in full:**
a2dp.Vol — a real music player, not a test app — got a `high/confirmed` SQL-injection
finding on `DataXmlExporter.exportTable()`. Traced the actual bytecode and its caller:
`export()` enumerates the app's **own local SQLite schema** via `sqlite_master`, filters out
system tables, and calls `exportTable()` once per table name **it already owns** — a local
backup/export feature, not attacker-reachable. The concatenation pattern is real; the
practical exploitability is not. Rather than either quietly downgrading this (based on one
manually-reasoned example) or leaving an unqualified "confirmed... exploitable" claim, added
`_describe_caller_arg_pattern`: a one-hop-up trace that reports whether a method's known
callers pass only literal strings (lower real-world risk) or non-literal values (unresolved,
could carry external input), or states plainly when no callers could be found via static
analysis at all (common for ContentProvider dispatch — PIVAA's `getRecord()` hit exactly
this case). Reworded the finding text to separate what's actually confirmed (a concatenation
pattern exists) from what isn't (that it's exploitable) — the tool now gives the reader real,
specific context instead of a blanket "verify manually," without asserting a verdict it
can't back up. Interesting honest result: a2dp.Vol's own caller check reports "non-literal"
(technically true — it's a variable, not a hardcoded string) even though the deeper truth
is it's internally sourced two hops up — the one-hop check is honest about its own limits
rather than overclaiming a "safe" verdict it can't fully prove either.

**Verified as a genuine true positive, not a false positive:** "Predictable RNG" on PIVAA
traced to `Encryption.rng()` — and PIVAA's actual source has a doc comment reading literally
`/** Weak random number generator */` directly above that method. Confirms this check is
working exactly as intended on real deliberately-vulnerable code.

Regression-tested across all six apps after every fix in this pass: zero crashes, findings
counts changed only where a real fix (getDeviceId false-positive removal) or real
enhancement (SQL caller-context) applied — nothing else moved.

## Formal pipeline: Risk Engine (priority ranking), Native branch, broader dedup

Restructured around the requested pipeline shape (Manifest/DEX/Native → Pattern Detection →
Source/Sink → Context → Evidence → Confidence×Impact → Risk Engine → ranked Final Findings).
Most stages already existed under different names (Source/Sink = the SQL/file-mode call-site
tracing; Context = the caller-arg-pattern check; Evidence = the `detail` text) — three stages
were real gaps, closed here:

**Risk Engine — per-finding priority ranking (the actual "rank findings by priority" ask).**
Previously there was only an aggregate app-level score (sum of severities → Low/Medium/High),
no per-finding ranking at all. Added `priority_score = impact_weight(severity) ×
confidence_multiplier(confidence)` on every `Finding`, and `ScanResult.ranked_findings()` to
sort by it. Deliberately NOT just sorting by severity: a `confirmed/medium` finding (60 → 40
after weighting) now correctly outranks an `unconfirmed/high` one (60 → 30) — an unverified
"high" claim isn't automatically more urgent than a proven "medium" one, which is the entire
point of the confidence system built in earlier rounds. New "Priority ranked" tab in the UI
shows this ordering directly, with the score visible so the ranking logic isn't a black box.

**Native code branch — previously a complete gap**, not a false-positive issue but an honest
absence: `.so` files were noted as "loadLibrary() present" via string search but never
inventoried at all. Added `_check_native_libraries`: lists bundled native libs grouped by
ABI/architecture, flags debug/test/instrumentation-looking filenames (e.g. a bundled Frida
gadget), and is explicit that this is inventory only — no disassembly, matching how every
other boundary in this tool has been disclosed rather than silently implied as covered.
Tested against a real APK with bundled native code (an androguard test fixture with
`lib/armeabi/fake.so`) — correctly grouped by arch, correctly did NOT false-positive the
debug-name check on an unrelated filename.

**Broader false-positive/duplication dedup**, extending the pattern already proven working
on tapjacking and self-signed-CA-in-WebView to every other category where testing showed a
heuristic and a confirmed finding both firing for the same underlying issue: hardcoded
encryption keys, weak IV, SQL-query concatenation, and — the one genuinely new case — a
cross-category rule where a confirmed "Untrusted CA" accept-all finding now also suppresses
the generic "Custom TrustManager.checkServerTrusted found" note filed under the *different*
category "MITM / hostname verification," since both stem from the same method. Verified on
PIVAA: findings dropped from 48 to 43, every category left with only its confirmed evidence
where confirmation exists, and the one legitimately distinct heuristic finding (a *different*
class's `HostnameVerifier`) correctly stayed rather than being over-aggressively removed.

**Performance — profiled honestly rather than claiming an unearned win.** Timed androguard's
own `AnalyzeAPK()` call in isolation: ~15-26s on InsecureBankv2, which is effectively the
entire deep-scan runtime. Confirmed there's no redundant work on this tool's side (`dx` is
built exactly once per scan and reused across all ~15 deep checks) — the cost is androguard's
own DEX cross-reference construction, which scales with app code size and isn't something
this tool's own logic can speed up without changing what data gets computed. The real,
already-shipped performance lever remains what it was: the deep pass stays opt-in rather than
running by default, so a quick scan stays sub-second.

Full regression suite re-run after all of the above: zero crashes across all seven test
files (including the new native-lib fixture), finding counts dropped only where genuine
dedup applied, ranking verified correct on real output.

## Full severity recalibration against an explicit review table

Recalibrated severity across ~30 finding types against an explicit review table (not an
ad-hoc pass) that separates two things this tool had been conflating: **confidence** (is
this fact true?) and **impact** (how bad is it if true?). A lot of "high" severities were
really just "confirmed true," not "confirmed dangerous" — e.g. `debuggable=true` is a
100%-certain fact from the manifest, but the table's own reasoning is exactly right: "true,
but not automatically exploitable." Confidence and impact are different questions.

**Downgraded** (bare API/pattern presence without established impact — the "API alone
proves nothing" theme running through nearly every row): `SecretKeySpec`/`IvParameterSpec`
construction (medium→low), `Random` (medium→low), `checkServerTrusted` presence (medium→
low), `setJavaScriptEnabled` (medium→low), `ObjectInputStream`/`readObject` (medium→low),
bare `rawQuery`/`execSQL` presence (medium→low), `DexClassLoader`/`PathClassLoader`
(medium→low), dangerous permissions in isolation (medium→low), Exported Activity/Service/
Receiver (medium→low), Tapjacking-missing (medium→low), `loadUrl`/`createTempFile`/
`SQLiteOpenHelper`/`'../'` literal (low→info), `debuggable`/debug-signing-key (high→
medium), World-writable files even when bytecode-confirmed (high→medium — impact still
depends on what's stored, confirmation of the flag isn't confirmation of the data),
confirmed hardcoded IV even when degenerate/all-zero (high→medium, per the table's explicit
reasoning that severity "depends on cryptographic construction/reuse" beyond just knowing
it's static), and confirmed SQL-built-via-StringBuilder (high→medium — bytecode confirms
the *pattern*, not that the value is attacker-controlled, which is the actual thing that
would justify high).

**Kept high** where the table agrees or the signal has no benign reading: hardcoded
password/key (confirmed, in any form — string, byte-array, or Map — a real embedded secret
is a real embedded secret regardless of how it's stored), `TrustManager` confirmed to
accept all certificates, `ALLOW_ALL_HOSTNAME_VERIFIER` and `addJavascriptInterface`
(unlike most bare-presence findings, these two APIs exist specifically to do the dangerous
thing — there's no "maybe it's used safely" reading the way there is for e.g. a bare
`SecretKeySpec` call).

**Implemented, not just downgraded — a real escalation heuristic for Exported Content
Provider**, per the table's explicit "High only if sensitive data/operations are
accessible" rather than leaving it as a flat medium. Checks two concrete signals: does the
app hold sensitive-data permissions (contacts/location/camera/mic/SMS/call log) elsewhere,
and does the provider's own class name suggest sensitive content (user/account/payment/
credential/token/etc.). Neither is proof on its own, but together they're a real basis for
escalation rather than a guess. Verified on PIVAA (which does request several of those
permissions): its exported provider correctly escalates to high, with the specific reason
stated in the finding text rather than just asserting the severity.

**Caught and fixed a gap in this very pass**: `DexClassLoader` is explicitly named in the
table as needing Medium→Low, but the first version of this recalibration missed it entirely
— it lives in a different, separately-defined pattern table (`SUSPICIOUS_CODE_PATTERNS`)
than the one I was systematically editing (`DEEP_CODE_CHECKS`), and that whole table shared
one flat hardcoded "medium" severity for every entry regardless of pattern. Restructured it
to carry a per-pattern severity like the others, and gave each entry (`DexClassLoader`,
`PathClassLoader`, `loadLibrary`, `getSubscriberId`, `sendTextMessage`) its own calibrated
level consistent with the same reasoning applied everywhere else, rather than leaving it as
a separate inconsistent flat-medium bucket.

Regression-tested across all six apps after every change: zero crashes. Two apps
(`debug.apk`, `jamendo.apk`) — the ones with the fewest genuinely severe confirmed
findings — dropped from an aggregate "High" risk rating to "Medium." That's a meaningful
signal on its own: before this recalibration, every single app in the test set scored
"High" regardless of how much was actually wrong with it, which was itself evidence of the
over-alarming problem this table was written to fix.

## Store listing inspection (Google Play + Apple App Store)

The scanner now has three entry points:

- **Upload APK / ZIP** — runs the existing Android binary static analyzer.
- **Google Play listing** — fetches public listing metadata and exposed permission declarations.
- **Apple App Store listing** — fetches public listing metadata through Apple's public lookup endpoint.

Both store listing modes include basic metadata-presence checks and a downloadable JSON summary. These checks are informational only: a public store URL does not expose the full app binary, and this feature does not certify Google Play/App Store policy compliance or predict approval. To scan app binaries, upload an APK (Android); iOS IPA analysis requires a separate iOS-capable analyzer and access to the IPA.

### Secrets setup

Do not commit or share `.streamlit/secrets.toml`. Copy `.streamlit/secrets.example.toml` to `.streamlit/secrets.toml` and fill in your own credentials. If credentials from an existing secrets file were shared outside your trusted environment, rotate them with the corresponding providers.

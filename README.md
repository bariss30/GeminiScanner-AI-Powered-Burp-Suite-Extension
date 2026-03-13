# GeminiScanner

A Burp Suite extension that uses **Google Gemini** to automatically analyze HTTP requests and responses, identify vulnerabilities, generate targeted payloads, and actively verify findings.

> **Best results on API endpoints.** GeminiScanner was built with API security in mind — it reasons about the full request/response context rather than matching static signatures, which makes it significantly more effective at finding API-specific vulnerabilities (BOLA/IDOR, Mass Assignment, BFLA, Broken Auth) that traditional scanners routinely miss.

---

## How It Works

```
1. Right-click any request → GeminiScanner — Scan This Request
2. Phase 1: Gemini analyzes the full request + response
             → identifies parameters, reflection points, auth mechanism
             → generates targeted payloads per parameter and attack type
             → flags tests that require manual follow-up (Repeater / Intruder)
3. Phase 2: Each payload is sent via Burp's HTTP engine
             → Gemini verifies whether the response confirms exploitation
4. Results are routed to:
             → Confirmed tab   — verified vulnerabilities with evidence
             → Suspected tab   — ambiguous findings worth manual review
             → Manual Actions  — tests that require Repeater / Intruder / Browser
```

---

## Why API Security

Most Burp extensions and scanners rely on known signatures and pattern matching. They work reasonably well for classic web vulnerabilities but struggle with:

- **BOLA / IDOR** — requires understanding object ownership context
- **Mass Assignment** — requires knowing which fields *should not* be writable
- **BFLA** — requires understanding the difference between user and admin functions
- **Business Logic** — requires reasoning about what the application is *supposed* to do

GeminiScanner sends the complete HTTP exchange to Gemini, which can reason about all of the above. In testing, it consistently outperformed signature-based tools on API targets.

---

## Features

- Two-phase scan: **AI analysis → active verification**
- Covers: XSS, SQLi, SSTI, Path Traversal, IDOR, SSRF, Command Injection, Host Header Injection, Business Logic, OWASP API Top 10
- Context-aware XSS payload generation (HTML body / attribute / JS string)
- Header injection testing: Host, X-Forwarded-For, X-Forwarded-Host, Origin, Referer
- Smart routing: tries everything automatically first, only sends to Manual Actions when automation is insufficient or inconclusive
- AI-verified findings — reduces false positives
- Recommendations generated per scan
- Configurable toggles: Auto-send, Suspected findings, Recommendations, Debug log
- Custom payload lists (XSS / SQLi / Other) used as AI hints
- Custom system prompt support (appended to default, not replacing it)
- Persistent settings and payload lists across sessions
- Native Burp color scheme

---

## Requirements

- Burp Suite Professional or Community (Montoya API — version 2022.9+)
- Java 17+
- Google Gemini API key — [get one free at Google AI Studio](https://aistudio.google.com/app/apikey)

---

## Installation

### Build from source

```bash
git clone https://github.com/YOUR_USERNAME/GeminiScanner.git
cd GeminiScanner
./gradlew clean jar
```

On Windows:
```cmd
gradlew.bat clean jar
```

JAR will be at `build/libs/gemini-scanner-1.0.jar`.

### Load in Burp

1. Burp Suite → **Extensions** → **Add**
2. Extension type: **Java**
3. Select the JAR file
4. Open the **GeminiScanner** tab → enter your Gemini API key → **Save Settings**

---

## Usage

1. Browse or proxy traffic through Burp as normal
2. In **Proxy History** or **Repeater**, right-click a request that has a response
3. Select **GeminiScanner — Scan This Request**
4. Watch the **Scan Log** tab for real-time progress
5. Check results in **Confirmed**, **Suspected**, or **Manual Actions** tabs

**Tips:**
- Always capture a response before scanning — right-click in Proxy History, not just the request
- For API endpoints returning JSON, the full response body is analyzed
- Use the **Payloads** tab to add custom payloads as hints for the AI
- The **Custom Prompt** field appends to the default prompt — use it to add target-specific instructions (e.g. "also test the X-Internal-Token header")
- `gemini-2.5-flash` is recommended for speed; use `gemini-1.5-pro` for deeper analysis on complex targets

---

## Settings

| Setting | Description |
|---|---|
| Gemini API Key | Your Google AI Studio API key |
| Model | AI model to use for analysis |
| Auto-send payloads | Enable/disable Phase 2 active verification |
| Show suspected findings | Show low-confidence results in Suspected tab |
| Show recommendations | Print remediation advice in Scan Log |
| Debug log | Verbose logging for troubleshooting |
| Custom System Prompt | Extra instructions appended to the default prompt |
| XSS / SQLi / Other Payloads | Hint lists provided to Gemini alongside its own generated payloads |

---

## Project Structure

```
src/main/java/
  MyAiScanner.java      Extension entry point (BurpExtension)
  AiSettingsTab.java    UI — Settings, Scan Log, Confirmed, Suspected, Manual Actions, Payloads
  ApiAnalyzer.java      Gemini API client, Phase 1/2 logic, request modification
  EndpointMenu.java     Right-click context menu, scan orchestration, result routing
  AiScannerCheck.java   Burp ScanCheck integration (active scanner)
build.gradle.kts
```

---

## Known Limitations

- XSS confirmation is based on response reflection analysis — Gemini cannot execute JavaScript in a browser, so DOM-only XSS may not be confirmed automatically (routed to Manual Actions instead)
- Time-based SQLi (SLEEP, WAITFOR) confirmation may be unreliable due to network latency variance
- Very large responses (> ~100KB) are truncated before sending to Gemini
- Each scan makes approximately `1 + (N × 2)` Gemini API calls where N is the number of payloads tested — use `gemini-2.5-flash` to keep costs low

---

## License

MIT

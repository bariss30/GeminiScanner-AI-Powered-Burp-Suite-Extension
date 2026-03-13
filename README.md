# GeminiScanner — AI-Powered Burp Suite Extension

A Burp Suite extension that uses 'Google Gemini' to automatically analyze HTTP requests and responses, identify vulnerabilities, generate targeted payloads, and actively verify findings.

---

## What Makes This Different

Most Burp extensions rely on static pattern matching or known signatures. GeminiScanner uses a large language model to reason about the full request/response context, making it especially effective for:

- **Business logic vulnerabilities** — price manipulation, role escalation, workflow bypass
- **API security (OWASP API Top 10)** — BOLA/IDOR, broken auth, mass assignment, BFLA
- **Context-aware XSS** — detects reflection context (HTML body, attribute, JS string) and generates appropriate payloads
- **Novel or chained vulnerabilities** that static tools miss

---

## How It Works

```
1. Right-click any request → GeminiScanner — Scan This Request
2. Phase 1: Gemini analyzes the request + response
             → identifies parameters, reflection points, attack surface
             → generates targeted payloads per parameter
3. Phase 2: Each payload is sent via Burp's HTTP engine
             → Gemini verifies whether the response confirms exploitation
4. Confirmed findings appear in the Confirmed tab with evidence and reproduction steps
```

---

## Features

- Two-phase scan: **analysis → active verification**
- Covers: XSS, SQLi, SSTI, Path Traversal, IDOR, SSRF, Command Injection, Business Logic, OWASP API Top 10
- Context-aware XSS payload generation (HTML body / attribute / JS string)
- Encoding bypass payloads included automatically
- Gemini-verified findings only — reduces false positives
- Recommendations generated per scan
- Four-tab UI: Settings, Scan Log, Confirmed, Payloads
- Custom payload lists (XSS / SQLi / Other) used as AI hints
- Persistent settings and payload lists
- Native Burp color scheme — no custom theming
- Integrates with Burp's active scanner (`ScanCheck`)

---

## Requirements

- Burp Suite Professional or Community (with Montoya API support — version 2022.9+)
- Java 17+
- Google Gemini API key — [get one free](https://aistudio.google.com/app/apikey)

---

## Installation

### Build from source

```bash
git clone https://github.com/YOUR_USERNAME/GeminiScanner.git
cd GeminiScanner
./gradlew clean jar
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
2. In **Proxy History** or **Repeater**, right-click a request with a response
3. Select **GeminiScanner — Scan This Request**
4. Watch the **Scan Log** tab for real-time progress
5. Check the **Confirmed** tab for verified vulnerabilities

**Tips:**
- Requests with responses give better results — send a normal request first, then scan
- Add custom payloads in the **Payloads** tab to guide AI toward specific attack types
- For API endpoints returning JSON, the full response body is analyzed

---

## Configuration

| Setting | Description |
|---|---|
| Gemini API Key | Your Google AI Studio API key |
| Model | `gemini-2.5-flash` recommended for speed; `gemini-1.5-pro` for depth |
| Custom System Prompt | Override the default analysis prompt entirely |
| XSS / SQLi / Other Payloads | Hints provided to Gemini alongside its own generated payloads |

---

## Known Limitations

- Gemini cannot execute JavaScript — XSS confirmation is based on response reflection analysis, not browser execution
- Time-based SQLi (SLEEP, WAITFOR) confirmation may be unreliable due to network variance
- Very large responses (> ~100KB) are truncated before sending to Gemini
- Each scan makes 1 + (N × 2) Gemini API calls where N is the number of payloads tested

---

## Project Structure

```
src/main/java/
  MyAiScanner.java      Extension entry point
  AiSettingsTab.java    UI — four-tab panel
  ApiAnalyzer.java      Gemini API client, phase 1/2 logic, request modification
  EndpointMenu.java     Right-click context menu, scan orchestration
  AiScannerCheck.java   Burp ScanCheck integration
build.gradle.kts
```

---

## License

MIT

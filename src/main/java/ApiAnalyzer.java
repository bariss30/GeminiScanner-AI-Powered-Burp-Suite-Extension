import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.*;
import okhttp3.*;
import java.io.IOException;
import java.util.concurrent.TimeUnit;
import java.util.regex.*;

public class ApiAnalyzer {

    private final MontoyaApi    api;
    private final AiSettingsTab settings;
    private final OkHttpClient  client;

    private static final String PHASE1_PROMPT =
            "You are an elite web application and API security researcher.\n\n" +
                    "Analyze the HTTP request and response below.\n" +
                    "Identify ALL exploitable vulnerabilities and generate precise, targeted payloads.\n\n" +

                    "== PARAMETER IDENTIFICATION ==\n" +
                    "  - Identify parameters from: query string, request body (form or JSON), URL path segments, HTTP headers\n" +
                    "  - Use EXACT parameter names / header names as they appear\n" +
                    "  - For path-based identifiers (e.g. /api/user/{value}), set location=path, parameter=current value\n" +
                    "  - For header injection, set location=header, parameter=Header-Name\n" +
                    "  - Do NOT invent parameters that are not present\n" +
                    "  - For headers: ONLY test security-relevant headers:\n" +
                    "    Host, X-Forwarded-For, X-Forwarded-Host, X-Real-IP, Origin, Referer,\n" +
                    "    Authorization, X-Custom-IP-Authorization, X-Originating-IP, Content-Type\n" +
                    "  - IGNORE: User-Agent, Accept, Accept-Language, Accept-Encoding,\n" +
                    "    Sec-Fetch-*, Upgrade-Insecure-Requests, Priority, Te, Connection\n\n" +

                    "== VULNERABILITY SCOPE ==\n" +
                    "Test ALL applicable categories:\n\n" +

                    "  Web:\n" +
                    "    - XSS: reflected, stored, DOM-based\n" +
                    "    - SQLi: error-based, blind, time-based, UNION\n" +
                    "    - SSTI: template injection (Jinja2, Twig, FreeMarker, etc.)\n" +
                    "    - Path Traversal: directory traversal, file read\n" +
                    "    - Open Redirect: redirect parameter manipulation\n" +
                    "    - Command Injection: OS command execution\n" +
                    "    - SSRF: internal network access via user-controlled URL\n\n" +

                    "  Headers (ALWAYS check these regardless of body/query params):\n" +
                    "    - Host header injection: supply different host, check redirect/link generation\n" +
                    "    - X-Forwarded-For / X-Real-IP: IP spoofing, access control bypass\n" +
                    "    - X-Forwarded-Host: cache poisoning, redirect hijacking\n" +
                    "    - Origin: CORS bypass, cross-origin data leak\n" +
                    "    - Referer: CSRF protection bypass, referer-based access control\n" +
                    "    - X-Custom-IP-Authorization / X-Originating-IP: admin bypass\n" +
                    "    - Content-Type: type confusion, parser switching\n\n" +

                    "  API (OWASP API Top 10):\n" +
                    "    - API1  BOLA/IDOR: object-level access control bypass\n" +
                    "    - API2  Broken Authentication: token reuse, weak secrets, missing auth\n" +
                    "    - API3  Mass Assignment: extra fields, over-posted properties\n" +
                    "    - API4  Unrestricted Resource Consumption: large payloads, no rate limit\n" +
                    "    - API5  BFLA: function-level access control bypass\n" +
                    "    - API6  SSRF: server-side request forgery\n" +
                    "    - API7  Security Misconfiguration: verbose errors, debug endpoints, open CORS\n" +
                    "    - API8  Injection: NoSQL, LDAP, GraphQL injection\n" +
                    "    - API9  Improper Inventory: deprecated /v1/ endpoints, hidden paths\n" +
                    "    - API10 Unsafe API Consumption: dependency injection\n\n" +

                    "  Business Logic:\n" +
                    "    - Price/quantity manipulation, negative values, integer overflow\n" +
                    "    - Role escalation, privilege bypass\n" +
                    "    - Workflow skip, step bypass, race conditions\n" +
                    "    - Coupon/voucher abuse\n\n" +

                    "== XSS PAYLOAD RULES ==\n" +
                    "  - Carefully read the response and determine the EXACT reflection context\n" +
                    "  - HTML body: inject <script>, <img>, <svg> tags\n" +
                    "  - Inside attribute value (e.g. value=\"INPUT\"): break with \" then inject event handler\n" +
                    "  - Inside single-quoted attribute: break with ' then inject\n" +
                    "  - Inside JS string (e.g. var x='INPUT'): break with '; inject code //\n" +
                    "  - Always include one case-bypass or encoding-bypass variant\n" +
                    "  - If reflection context is unclear, generate payloads for ALL contexts\n\n" +

                    "== MANUAL ACTION FLAG ==\n" +
                    "Set needs_manual=true when automated single-request testing is insufficient:\n" +
                    "  - Intruder: brute force, rate limit testing, fuzzing large wordlists\n" +
                    "  - Repeater: multi-step flows, chained requests, session manipulation\n" +
                    "  - Browser: CSRF, stored XSS verification, OAuth flows, clickjacking\n" +
                    "  - Manual: race conditions, timing attacks, anything needing human judgment\n" +
                    "  Even if needs_manual=true, STILL generate payloads — automated attempt runs first.\n\n" +

                    "== FREE REQUESTS ==\n" +
                    "Leave free_requests as an EMPTY array [] in almost all cases.\n" +
                    "Only populate it if the request/response contains a STRONG indicator that warrants it:\n" +
                    "  - Response explicitly mentions an admin panel path\n" +
                    "  - Version number visible suggesting deprecated endpoint (e.g. /v1/ → try /v2/)\n" +
                    "  - Response header reveals an internal path\n" +
                    "Do NOT probe generic paths like /admin, /.env, /robots.txt on every scan.\n\n" +

                    "RESPOND ONLY with valid JSON, no markdown, no extra text:\n" +
                    "{\n" +
                    "  \"attack_surface\": {\n" +
                    "    \"parameters\": [\"<param>\"],\n" +
                    "    \"auth_mechanism\": \"cookie|bearer|none\",\n" +
                    "    \"data_returned\": \"<brief description>\"\n" +
                    "  },\n" +
                    "  \"test_cases\": [\n" +
                    "    {\n" +
                    "      \"parameter\": \"<exact name or current path value>\",\n" +
                    "      \"location\": \"body|query|path|header\",\n" +
                    "      \"current_value\": \"<current value in request, or empty if header not present>\",\n" +
                    "      \"attack_type\": \"<XSS|SQLi|BOLA|HostHeaderInjection|etc>\",\n" +
                    "      \"severity\": \"HIGH|MEDIUM|LOW\",\n" +
                    "      \"owasp\": \"<e.g. A03:2021|API1:2023>\",\n" +
                    "      \"reasoning\": \"<why this parameter/header is vulnerable>\",\n" +
                    "      \"reflection_context\": \"<html_body|html_attribute|js_string|json|header_value|none>\",\n" +
                    "      \"needs_manual\": false,\n" +
                    "      \"manual_tool\": \"\",\n" +
                    "      \"manual_reason\": \"\",\n" +
                    "      \"manual_instructions\": \"\",\n" +
                    "      \"payloads\": [\n" +
                    "        {\"value\": \"<payload>\", \"detection_hint\": \"<what confirms success in response>\"}\n" +
                    "      ]\n" +
                    "    }\n" +
                    "  ],\n" +
                    "  \"free_requests\": [\n" +
                    "    {\n" +
                    "      \"method\": \"GET\",\n" +
                    "      \"path\": \"/api/v1/admin\",\n" +
                    "      \"headers\": {},\n" +
                    "      \"body\": \"\",\n" +
                    "      \"reason\": \"<why this request is needed>\"\n" +
                    "    }\n" +
                    "  ],\n" +
                    "  \"recommendations\": [\"<actionable fix>\"],\n" +
                    "  \"overall_risk\": \"HIGH|MEDIUM|LOW|NONE\",\n" +
                    "  \"notes\": \"<brief analyst notes>\"\n" +
                    "}\n\n";

    private static final String PHASE2_PROMPT =
            "You are a web security analyst verifying whether a payload triggered a vulnerability.\n\n" +
                    "Test details:\n" +
                    "  Parameter    : %s\n" +
                    "  Attack type  : %s\n" +
                    "  Payload sent : %s\n" +
                    "  Expected sign: %s\n\n" +

                    "== CONFIRMATION CRITERIA ==\n\n" +

                    "XSS — confirmed=true if ANY of the following is present in the response:\n" +
                    "  • An executable tag is reflected unencoded: <script>, <img>, <svg>, <iframe>, <body>, <input>\n" +
                    "  • An event handler attribute is reflected: onerror, onload, onmouseover, onclick, etc.\n" +
                    "  • alert(1) or any JS expression appears unencoded in the HTML\n" +
                    "  • The payload or a meaningful portion of it appears in the response without HTML encoding\n" +
                    "  IMPORTANT: The full payload does NOT need to match verbatim.\n" +
                    "  If the server stripped '\">' but reflected <script>alert(1)</script> → still CONFIRMED.\n" +
                    "  If the server reflected onerror=alert(1) anywhere in the HTML → still CONFIRMED.\n" +
                    "  Only mark false if the payload is completely absent or fully HTML-encoded (&lt; &gt; &amp;).\n\n" +

                    "SQLi — confirmed=true if:\n" +
                    "  • SQL error message visible (syntax error, mysql_fetch, ORA-, MSSQL, etc.)\n" +
                    "  • Login succeeded without valid credentials\n" +
                    "  • Unexpected data rows returned\n" +
                    "  • Response time significantly longer (> 2s for time-based)\n\n" +

                    "BOLA/IDOR — confirmed=true if:\n" +
                    "  • Another user's data is returned (different username, email, id in response)\n" +
                    "  • 200 OK returned for a resource belonging to a different user\n\n" +

                    "Mass Assignment — confirmed=true if:\n" +
                    "  • Injected field is reflected or accepted in the response\n" +
                    "  • Role/privilege change reflected\n\n" +

                    "SSTI — confirmed=true if:\n" +
                    "  • Math expression is evaluated ({{7*7}} → 49, ${7*7} → 49)\n\n" +

                    "Path Traversal — confirmed=true if:\n" +
                    "  • File system content visible (root:, [boot loader], etc.)\n\n" +

                    "SSRF — confirmed=true if:\n" +
                    "  • Response from internal host received\n" +
                    "  • Out-of-band DNS/HTTP interaction detected\n\n" +

                    "Host Header Injection — confirmed=true if:\n" +
                    "  • Injected host value appears in response (redirect URL, link href, email)\n" +
                    "  • Password reset link contains attacker-controlled domain\n\n" +

                    "Header Injection (X-Forwarded-For etc.) — confirmed=true if:\n" +
                    "  • Access control decision changed (admin page accessible)\n" +
                    "  • IP reflected in response or logs\n\n" +

                    "Business Logic — confirmed=true if:\n" +
                    "  • Price, quantity, role, or workflow behaves contrary to expected business rules\n\n" +

                    "Be precise: provide the exact text from the response as evidence.\n" +
                    "If payload is partially reflected → confirmed=true with explanation.\n" +
                    "If fully HTML-encoded → confirmed=false.\n\n" +

                    "RESPOND ONLY with valid JSON, no markdown:\n" +
                    "{\n" +
                    "  \"confirmed\": false,\n" +
                    "  \"confidence\": \"HIGH|MEDIUM|LOW\",\n" +
                    "  \"evidence\": \"<exact excerpt from response proving the finding>\",\n" +
                    "  \"explanation\": \"<concise technical reasoning>\"\n" +
                    "}\n\n" +
                    "HTTP Response to analyze:\n";

    public ApiAnalyzer(MontoyaApi api, AiSettingsTab settings) {
        this.api      = api;
        this.settings = settings;
        this.client   = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(90,  TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .build();
    }

    // ── Phase 1 ───────────────────────────────────────────────────

    public JsonObject phase1Analyze(HttpRequest request, HttpResponse response) {
        StringBuilder prompt = new StringBuilder(effectivePrompt());
        prompt.append("== HTTP REQUEST ==\n").append(request.toString()).append("\n\n");

        if (response != null) {
            prompt.append("== HTTP RESPONSE ==\n");
            prompt.append("Status: ").append(response.statusCode()).append("\n");
            prompt.append(extractRelevantParts(response));
        } else {
            prompt.append("== HTTP RESPONSE ==\n(unavailable — request-only analysis)\n");
        }

        appendPayloadHints(prompt);
        return parseResponse(sendToGemini(prompt.toString()));
    }

    // ── Phase 2 ───────────────────────────────────────────────────

    public JsonObject phase2Verify(String parameter, String attackType,
                                   String payload, String detectionHint,
                                   HttpResponse response) {
        // For phase 2, send full response body so Gemini has complete picture
        String respStr = response != null ? fullResponseBody(response) : "(no response)";
        String prompt = String.format(PHASE2_PROMPT, parameter, attackType, payload, detectionHint)
                + respStr;
        return parseResponse(sendToGemini(prompt));
    }

    // ── Send modified request ─────────────────────────────────────

    public HttpResponse sendModifiedRequest(HttpRequest original,
                                            String parameter,
                                            String payloadValue,
                                            String location) {
        try {
            HttpRequest modified = replaceParameterValue(original, parameter, payloadValue, location);
            if (modified == null) return null;

            settings.logDebug("Sending [" + location + "] " + parameter + " = " + payloadValue);

            var result = api.http().sendRequest(modified);
            if (result == null || result.response() == null) {
                settings.log("  [!] No response from server");
                return null;
            }

            settings.log("  [<] HTTP " + result.response().statusCode()
                    + " (" + result.response().body().length() + " bytes)");
            return result.response();

        } catch (Exception e) {
            settings.log("  [!] Request failed: " + e.getClass().getSimpleName()
                    + " — " + e.getMessage());
            api.logging().logToError("sendModifiedRequest: " + e);
            return null;
        }
    }

    // ── Send free exploratory request ─────────────────────────────

    public HttpResponse sendFreeRequest(HttpRequest base, JsonObject freeReq) {
        try {
            String method = gs(freeReq, "method");
            String path   = gs(freeReq, "path");
            String body   = gs(freeReq, "body");
            String reason = gs(freeReq, "reason");

            settings.log("  [FREE] " + method + " " + path + " — " + reason);

            HttpRequest req = base.withMethod(method).withPath(path);
            if (!body.isEmpty()) req = req.withBody(body);

            if (freeReq.has("headers")) {
                JsonObject headers = freeReq.getAsJsonObject("headers");
                for (String name : headers.keySet())
                    req = req.withHeader(name, headers.get(name).getAsString());
            }

            var result = api.http().sendRequest(req);
            if (result == null || result.response() == null) {
                settings.log("  [FREE] No response");
                return null;
            }

            settings.log("  [FREE] HTTP " + result.response().statusCode()
                    + " (" + result.response().body().length() + " bytes)");
            return result.response();

        } catch (Exception e) {
            settings.log("  [!] Free request failed: " + e.getMessage());
            return null;
        }
    }

    // ── Parameter / header replacement ───────────────────────────

    private HttpRequest replaceParameterValue(HttpRequest request,
                                              String parameter,
                                              String newValue,
                                              String location) {
        try {
            String body   = request.bodyToString();
            String method = request.method();
            String path   = request.path();

            // ── HEADER injection ──────────────────────────────────
            if ("header".equalsIgnoreCase(location)) {
                settings.logDebug("Injecting header: " + parameter + ": " + newValue);
                return request.withHeader(parameter, newValue);
            }

            // ── PATH segment ──────────────────────────────────────
            if ("path".equalsIgnoreCase(location) && path != null) {
                String escaped  = Pattern.quote(parameter);
                String replaced = Matcher.quoteReplacement(newValue);

                // /segment/currentValue → /segment/newValue
                String newPath = path.replaceAll(
                        "(?<=/)" + escaped + "(?=/|$|\\?|#)", replaced);
                if (!newPath.equals(path)) {
                    settings.logDebug("Path: " + path + " → " + newPath);
                    return request.withPath(newPath);
                }

                // /paramName/currentValue → /paramName/newValue
                newPath = path.replaceAll(
                        "(?i)(/" + escaped + "/)[^/?#]*", "$1" + replaced);
                if (!newPath.equals(path)) {
                    settings.logDebug("Path (named): " + path + " → " + newPath);
                    return request.withPath(newPath);
                }

                settings.log("  [!] Could not locate '" + parameter + "' in path: " + path);
                return null;
            }

            // ── URL-encoded body ──────────────────────────────────
            if ((method.equals("POST") || method.equals("PUT") || method.equals("PATCH"))
                    && body != null && !body.isEmpty()
                    && !body.trim().startsWith("{")
                    && body.contains(parameter + "=")) {

                String encoded = java.net.URLEncoder.encode(newValue, "UTF-8").replace("+", "%20");
                String newBody = body.replaceAll(
                        "(?i)" + Pattern.quote(parameter) + "=[^&]*",
                        parameter + "=" + encoded);
                return request.withBody(newBody);
            }

            // ── JSON body ─────────────────────────────────────────
            if ((method.equals("POST") || method.equals("PUT") || method.equals("PATCH"))
                    && body != null && body.trim().startsWith("{")) {

                String escaped = newValue.replace("\\", "\\\\").replace("\"", "\\\"");
                String newBody = body.replaceAll(
                        "\"" + Pattern.quote(parameter) + "\"\\s*:\\s*\"[^\"]*\"",
                        "\"" + parameter + "\": \"" + escaped + "\"");
                if (newBody.equals(body)) {
                    // Numeric value
                    newBody = body.replaceAll(
                            "\"" + Pattern.quote(parameter) + "\"\\s*:\\s*[0-9.]+",
                            "\"" + parameter + "\": \"" + escaped + "\"");
                }
                return request.withBody(newBody);
            }

            // ── Query string ──────────────────────────────────────
            if (path != null && path.contains(parameter + "=")) {
                String encoded = java.net.URLEncoder.encode(newValue, "UTF-8")
                        .replace("+",   "%20")
                        .replace("%21", "!")
                        .replace("%27", "'")
                        .replace("%28", "(")
                        .replace("%29", ")")
                        .replace("%7E", "~");
                String newPath = path.replaceAll(
                        "(?i)" + Pattern.quote(parameter) + "=[^&#]*",
                        parameter + "=" + encoded);
                return request.withPath(newPath);
            }

            // ── Raw fallback ──────────────────────────────────────
            String raw = request.toString();
            if (raw.contains(parameter + "=")) {
                String encoded = java.net.URLEncoder.encode(newValue, "UTF-8").replace("+", "%20");
                String newRaw  = raw.replaceAll(
                        "(?i)" + Pattern.quote(parameter) + "=[^&# \\r\\n]*",
                        parameter + "=" + encoded);
                return HttpRequest.httpRequest(request.httpService(), newRaw);
            }

            settings.log("  [!] Parameter '" + parameter + "' not found in request");
            return null;

        } catch (Exception e) {
            settings.log("  [!] Replacement error: " + e.getMessage());
            return null;
        }
    }

    // ── Extract relevant response parts (Phase 1 — token-saving) ─

    public String extractRelevantParts(HttpResponse response) {
        String body = response.bodyToString();
        if (body == null || body.isEmpty()) return "(empty body)\n";

        String ct = "";
        try { ct = response.headerValue("Content-Type"); } catch (Exception ignored) {}
        if (ct == null) ct = "";

        // JSON — send as-is
        if (ct.contains("application/json") || body.trim().startsWith("{") || body.trim().startsWith("["))
            return "[JSON]:\n" + body.substring(0, Math.min(body.length(), 2500)) + "\n";

        // HTML — extract actionable parts only
        StringBuilder out = new StringBuilder("[HTML]:\n");
        String[] patterns = {
                "<form[^>]*>[\\s\\S]*?</form>",
                "<input[^>]*>",
                "<textarea[^>]*>[\\s\\S]*?</textarea>",
                "<script[^>]*>[\\s\\S]*?</script>",
                "(?i)(error|warning|exception|fatal|sql|mysql|syntax|traceback)[^<]{0,400}"
        };

        int total = 0;
        for (String pattern : patterns) {
            if (total > 3000) break;
            try {
                Matcher m = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(body);
                while (m.find() && total < 3000) {
                    String match = m.group().trim();
                    if (match.length() > 500) match = match.substring(0, 500) + " …[truncated]";
                    out.append(match).append("\n");
                    total += match.length();
                }
            } catch (Exception ignored) {}
        }

        if (total < 100)
            out.append(body, 0, Math.min(body.length(), 1200));

        return out.toString();
    }

    // ── Full response body for Phase 2 (Gemini needs complete view) ─

    private String fullResponseBody(HttpResponse response) {
        StringBuilder out = new StringBuilder();
        // Include response headers — important for header injection confirmation
        try {
            out.append("[Response Headers]:\n");
            for (var header : response.headers())
                out.append(header.name()).append(": ").append(header.value()).append("\n");
            out.append("\n");
        } catch (Exception ignored) {}

        String body = response.bodyToString();
        if (body == null || body.isEmpty()) {
            out.append("[Body]: (empty)\n");
            return out.toString();
        }

        // Send full body up to 4000 chars so Gemini sees exact reflection
        out.append("[Body]:\n");
        out.append(body, 0, Math.min(body.length(), 4000));
        if (body.length() > 4000) out.append("\n…[truncated]");
        return out.toString();
    }

    // ── Gemini API call ───────────────────────────────────────────

    private String sendToGemini(String prompt) {
        String apiKey = settings.getApiKey();
        if (apiKey == null || apiKey.isEmpty()) {
            settings.log("  [!] Gemini API key is not configured");
            return null;
        }

        String url = "https://generativelanguage.googleapis.com/v1beta/models/"
                + settings.getModel() + ":generateContent?key=" + apiKey;

        JsonObject textPart = new JsonObject();
        textPart.addProperty("text", prompt);
        JsonArray parts = new JsonArray();
        parts.add(textPart);
        JsonObject content = new JsonObject();
        content.add("parts", parts);
        JsonArray contents = new JsonArray();
        contents.add(content);
        JsonObject genConfig = new JsonObject();
        genConfig.addProperty("temperature", 0.15);
        JsonObject root = new JsonObject();
        root.add("contents", contents);
        root.add("generationConfig", genConfig);

        RequestBody body = RequestBody.create(
                root.toString(), MediaType.parse("application/json; charset=utf-8"));
        Request req = new Request.Builder().url(url).post(body).build();

        try (Response resp = client.newCall(req).execute()) {
            if (!resp.isSuccessful()) {
                String err = resp.body() != null ? resp.body().string() : "empty";
                settings.log("  [!] Gemini HTTP " + resp.code() + ": " + extractApiError(err));
                return null;
            }
            return resp.body() != null ? resp.body().string() : null;
        } catch (IOException e) {
            settings.log("  [!] Gemini connection error: " + e.getMessage());
            return null;
        }
    }

    // ── Parse Gemini response ─────────────────────────────────────

    public JsonObject parseResponse(String raw) {
        if (raw == null || raw.isEmpty()) return null;
        try {
            JsonObject wrapper = JsonParser.parseString(raw).getAsJsonObject();
            if (wrapper.has("error")) {
                settings.log("  [!] Gemini API error: " +
                        wrapper.getAsJsonObject("error").get("message").getAsString());
                return null;
            }
            JsonArray candidates = wrapper.getAsJsonArray("candidates");
            if (candidates == null || candidates.isEmpty()) {
                settings.log("  [!] Gemini: no candidates in response");
                return null;
            }
            JsonObject first = candidates.get(0).getAsJsonObject();
            if (first.has("finishReason")
                    && !first.get("finishReason").getAsString().equals("STOP")) {
                settings.log("  [!] Gemini finishReason: "
                        + first.get("finishReason").getAsString());
                return null;
            }
            String text = first.getAsJsonObject("content")
                    .getAsJsonArray("parts").get(0).getAsJsonObject()
                    .get("text").getAsString();
            text = text.replaceAll("(?s)```json", "").replaceAll("(?s)```", "").trim();
            int start = text.indexOf("{");
            int end   = text.lastIndexOf("}");
            if (start == -1 || end <= start) {
                settings.log("  [!] No JSON found in Gemini response");
                return null;
            }
            return JsonParser.parseString(text.substring(start, end + 1)).getAsJsonObject();
        } catch (Exception e) {
            settings.log("  [!] Response parse error: " + e.getMessage());
            return null;
        }
    }

    // ── Helpers ───────────────────────────────────────────────────

    private void appendPayloadHints(StringBuilder prompt) {
        String xss   = settings.getXssPayloads().trim();
        String sqli  = settings.getSqliPayloads().trim();
        String other = settings.getOtherPayloads().trim();
        if (xss.isEmpty() && sqli.isEmpty() && other.isEmpty()) return;
        prompt.append("\n== ADDITIONAL PAYLOAD HINTS ==\n");
        if (!xss.isEmpty())   prompt.append("XSS:\n").append(xss).append("\n");
        if (!sqli.isEmpty())  prompt.append("SQLi:\n").append(sqli).append("\n");
        if (!other.isEmpty()) prompt.append("Other:\n").append(other).append("\n");
    }

    private String effectivePrompt() {
        String custom = settings.getCustomPrompt().trim();
        if (custom.isEmpty()) return PHASE1_PROMPT;
        return PHASE1_PROMPT + "== ADDITIONAL INSTRUCTIONS ==\n" + custom + "\n\n";
    }

    private String extractApiError(String body) {
        try {
            JsonObject obj = JsonParser.parseString(body).getAsJsonObject();
            if (obj.has("error"))
                return obj.getAsJsonObject("error").get("message").getAsString();
        } catch (Exception ignored) {}
        return body.substring(0, Math.min(200, body.length()));
    }

    private String gs(JsonObject obj, String key) {
        return obj != null && obj.has(key) && !obj.get(key).isJsonNull()
                ? obj.get(key).getAsString() : "";
    }
}
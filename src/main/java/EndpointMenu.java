import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.google.gson.*;

import javax.swing.*;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

public class EndpointMenu implements ContextMenuItemsProvider {

    private final MontoyaApi    api;
    private final AiSettingsTab settings;

    public EndpointMenu(MontoyaApi api, AiSettingsTab settings) {
        this.api      = api;
        this.settings = settings;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();
        if (event.selectedRequestResponses() == null
                || event.selectedRequestResponses().isEmpty()) return items;

        JMenuItem item = new JMenuItem("GeminiScanner — Scan This Request");
        item.addActionListener(e -> handleScan(event));
        items.add(item);
        return items;
    }

    private void handleScan(ContextMenuEvent event) {
        if (settings.getApiKey().isEmpty()) {
            settings.log("[ERROR] API key not configured — open GeminiScanner > Settings.");
            JOptionPane.showMessageDialog(null,
                    "Please enter your Gemini API key in GeminiScanner > Settings.",
                    "API Key Required", JOptionPane.WARNING_MESSAGE);
            return;
        }
        HttpRequestResponse rr;
        try {
            rr = event.selectedRequestResponses().get(0);
        } catch (Exception ex) {
            settings.log("[ERROR] Could not read selected request: " + ex.getMessage());
            return;
        }
        new Thread(() -> runFullScan(rr.request(), rr.response())).start();
    }

    // ─────────────────────────────────────────────────────────────
    //  Main scan flow
    // ─────────────────────────────────────────────────────────────

    private void runFullScan(HttpRequest req, HttpResponse resp) {
        ApiAnalyzer analyzer = new ApiAnalyzer(api, settings);

        settings.log("╔══════════════════════════════════════════════╗");
        settings.log("  SCAN STARTED");
        settings.log("  Target   : " + req.method() + " " + req.url());
        settings.log("  Model    : " + settings.getModel());
        settings.log("  AutoSend : " + settings.isAutoSendEnabled()
                + "   Suspected: " + settings.isSuspectedEnabled()
                + "   Reco: " + settings.isRecommendationsEnabled());
        settings.log("  Response : " + (resp != null
                ? "HTTP " + resp.statusCode() + " (" + resp.body().length() + " bytes)"
                : "none"));
        settings.log("╚══════════════════════════════════════════════╝");
        settings.log("");

        // ── Phase 1 ───────────────────────────────────────────────

        settings.log("[Phase 1] Sending to Gemini for analysis…");

        JsonObject phase1 = analyzer.phase1Analyze(req, resp);
        if (phase1 == null) {
            settings.log("[Phase 1] Analysis failed — check errors above.");
            return;
        }

        logAttackSurface(phase1);

        // Recommendations
        if (settings.isRecommendationsEnabled() && phase1.has("recommendations")) {
            settings.log("[Phase 1] Recommendations:");
            for (JsonElement r : phase1.getAsJsonArray("recommendations"))
                settings.log("           • " + r.getAsString());
        }

        // Free exploratory requests AI wants to send
        sendFreeRequests(analyzer, req, phase1);

        if (!phase1.has("test_cases") || phase1.getAsJsonArray("test_cases").isEmpty()) {
            settings.log("[Phase 1] No testable parameters found.");
            printScanComplete(0, 0, 0);
            return;
        }

        JsonArray testCases = phase1.getAsJsonArray("test_cases");
        settings.log("[Phase 1] Test cases : " + testCases.size());
        settings.log("");
        logTestCaseSummary(testCases);

        // ── Phase 2 ───────────────────────────────────────────────

        if (!settings.isAutoSendEnabled()) {
            settings.log("[Phase 2] Skipped — Auto-send is OFF in Settings.");
            printScanComplete(0, 0, 0);
            return;
        }

        settings.log("[Phase 2] Starting active payload verification…");
        settings.log("");

        int confirmedCount = 0;
        int suspectedCount = 0;
        int manualCount    = 0;

        for (JsonElement tc : testCases) {
            JsonObject testCase = tc.getAsJsonObject();
            String parameter    = gs(testCase, "parameter");
            String attackType   = gs(testCase, "attack_type");
            String severity     = gs(testCase, "severity");
            String location     = gs(testCase, "location");
            boolean aiSaysManual = testCase.has("needs_manual")
                    && testCase.get("needs_manual").getAsBoolean();

            // If AI says manual but has no payloads at all → nothing to try, straight to manual
            if (aiSaysManual && (!testCase.has("payloads")
                    || testCase.getAsJsonArray("payloads").isEmpty())) {
                settings.log("[Manual] " + attackType + " on '" + parameter
                        + "' — no payloads generated, requires: " + gs(testCase, "manual_tool"));
                addManualAction(testCase, parameter, attackType, "-", req.url(),
                        "AI generated no automated payloads for this attack type.");
                manualCount++;
                continue;
            }

            // Skip structurally incompatible locations
            if (!isCompatibleLocation(req.method(), location)) {
                settings.log("[Phase 2] Skip '" + parameter + "' — ["
                        + location + "] incompatible with " + req.method());
                continue;
            }

            if (!testCase.has("payloads")) continue;

            JsonArray payloads = testCase.getAsJsonArray("payloads");
            boolean anySucceeded = false;

            for (JsonElement pe : payloads) {
                JsonObject payloadObj = pe.getAsJsonObject();
                String payloadValue   = gs(payloadObj, "value");
                String hint           = gs(payloadObj, "detection_hint");

                settings.log("[Phase 2] " + attackType
                        + " — [" + location + "] " + parameter + " = " + payloadValue);
                settings.log("          Expected : " + hint);

                // Try to send the request
                HttpResponse testResp = analyzer.sendModifiedRequest(
                        req, parameter, payloadValue, location);

                if (testResp == null) {
                    // Request failed — if AI flagged manual, queue it
                    settings.log("          Result   : no response");
                    if (aiSaysManual) {
                        settings.log("          → Manual Actions: " + gs(testCase, "manual_tool"));
                        addManualAction(testCase, parameter, attackType, payloadValue, req.url(),
                                "Automated request failed — requires manual interaction.");
                        manualCount++;
                    }
                    settings.log("");
                    continue;
                }

                // Ask Gemini to verify
                settings.log("[Phase 2] Verifying with Gemini…");
                JsonObject verification = analyzer.phase2Verify(
                        parameter, attackType, payloadValue, hint, testResp);

                if (verification == null) {
                    settings.log("          Verify   : Gemini verification failed");
                    settings.log("");
                    continue;
                }

                boolean confirmed  = verification.has("confirmed")
                        && verification.get("confirmed").getAsBoolean();
                String  confidence = gs(verification, "confidence");
                String  evidence   = gs(verification, "evidence");
                String  explanation = gs(verification, "explanation");

                JsonObject vuln = buildVuln(parameter, attackType, severity,
                        payloadValue, confidence, evidence, explanation, req.url());

                if (confirmed) {
                    // ✔ Confirmed
                    settings.log("          Result   : ✔ CONFIRMED [" + confidence + "]");
                    settings.log("          Evidence : " + evidence);
                    settings.addConfirmedVuln(vuln);
                    confirmedCount++;
                    anySucceeded = true;

                } else if (isHighConfidenceSuspect(confidence, explanation)) {
                    // ~ Suspected — automated test inconclusive but looks promising
                    settings.log("          Result   : ~ SUSPECTED [" + confidence + "] — " + explanation);
                    settings.addSuspectedVuln(vuln);
                    suspectedCount++;

                    // If AI also flagged as needing manual follow-up, add to manual too
                    if (aiSaysManual) {
                        settings.log("          → Also queued in Manual Actions for follow-up");
                        addManualAction(testCase, parameter, attackType, payloadValue, req.url(),
                                "Automated result inconclusive (" + confidence + "): " + explanation);
                        manualCount++;
                    }

                } else {
                    // ✘ Not confirmed
                    settings.log("          Result   : ✘ not confirmed — " + explanation);

                    // AI specifically said this needs manual and automated attempt didn't confirm →
                    // queue in Manual Actions so human can try with Repeater/Intruder
                    if (aiSaysManual) {
                        settings.log("          → Manual Actions: automated attempt inconclusive, "
                                + "try with " + gs(testCase, "manual_tool"));
                        addManualAction(testCase, parameter, attackType, payloadValue, req.url(),
                                "Automated attempt did not confirm. Manual verification with "
                                        + gs(testCase, "manual_tool") + " recommended: " + explanation);
                        manualCount++;
                    }
                }
                settings.log("");
            }

            // If AI flagged manual and none of the payloads were confirmed/suspected,
            // make sure at least one manual entry exists for the human to follow up
            if (aiSaysManual && !anySucceeded && manualCount == 0) {
                addManualAction(testCase, parameter, attackType,
                        "(see payloads above)", req.url(),
                        "All automated attempts inconclusive — "
                                + gs(testCase, "manual_reason"));
                manualCount++;
            }
        }

        printScanComplete(confirmedCount, suspectedCount, manualCount);
    }

    // ─────────────────────────────────────────────────────────────
    //  Helpers
    // ─────────────────────────────────────────────────────────────

    private void sendFreeRequests(ApiAnalyzer analyzer, HttpRequest base, JsonObject phase1) {
        if (!phase1.has("free_requests")) return;
        JsonArray freeReqs = phase1.getAsJsonArray("free_requests");
        if (freeReqs.isEmpty()) return;
        settings.log("[FREE] AI requested " + freeReqs.size() + " exploratory request(s)…");
        for (JsonElement fe : freeReqs)
            analyzer.sendFreeRequest(base, fe.getAsJsonObject());
        settings.log("");
    }

    private void logAttackSurface(JsonObject phase1) {
        if (phase1.has("attack_surface")) {
            JsonObject as = phase1.getAsJsonObject("attack_surface");
            settings.log("[Phase 1] Auth       : " + gs(as, "auth_mechanism"));
            settings.log("[Phase 1] Parameters : " +
                    (as.has("parameters") ? as.getAsJsonArray("parameters").toString() : "none"));
            settings.log("[Phase 1] Response   : " + gs(as, "data_returned"));
        }
        settings.log("[Phase 1] Risk       : " + gs(phase1, "overall_risk"));
        settings.log("[Phase 1] Notes      : " + gs(phase1, "notes"));
    }

    private void logTestCaseSummary(JsonArray testCases) {
        for (JsonElement tc : testCases) {
            JsonObject t = tc.getAsJsonObject();
            boolean manual = t.has("needs_manual") && t.get("needs_manual").getAsBoolean();
            settings.log("  ┌─ " + gs(t, "attack_type")
                    + " on [" + gs(t, "location") + "] '" + gs(t, "parameter") + "'");
            settings.log("  │  Severity  : " + gs(t, "severity")
                    + "  OWASP: " + gs(t, "owasp"));
            settings.log("  │  Context   : " + gs(t, "reflection_context"));
            String reasoning = gs(t, "reasoning");
            if (reasoning.length() > 120) reasoning = reasoning.substring(0, 120) + "…";
            settings.log("  │  Reasoning : " + reasoning);
            settings.log("  │  Payloads  : "
                    + (t.has("payloads") ? t.getAsJsonArray("payloads").size() : 0)
                    + (manual ? "  ⚠ AI suggests manual follow-up: " + gs(t, "manual_tool") : ""));
            settings.log("  └─────────────────────────────────────────");
            settings.log("");
        }
    }

    /**
     * Determines whether a test case location is structurally compatible
     * with the HTTP method. Returns false only for clear structural mismatches.
     * Path params are always compatible.
     */
    private boolean isCompatibleLocation(String method, String location) {
        if (location.equalsIgnoreCase("path")) return true;
        if (method.equals("GET") && location.equalsIgnoreCase("body")) return false;
        if ((method.equals("POST") || method.equals("PUT") || method.equals("PATCH"))
                && location.equalsIgnoreCase("query")) return false;
        return true;
    }

    /**
     * Returns true if the result is ambiguous enough that a human should look at it.
     * MEDIUM or HIGH confidence from Gemini on a not-confirmed finding = worth flagging.
     */
    private boolean isHighConfidenceSuspect(String confidence, String explanation) {
        if (confidence == null) return false;
        String c = confidence.toUpperCase();
        // High confidence not-confirmed = likely a partial finding or indirect evidence
        return c.equals("HIGH") || c.equals("MEDIUM");
    }

    private JsonObject buildVuln(String parameter, String attackType, String severity,
                                 String payload, String confidence,
                                 String evidence, String explanation, String url) {
        JsonObject v = new JsonObject();
        v.addProperty("parameter",   parameter);
        v.addProperty("attack_type", attackType);
        v.addProperty("severity",    severity);
        v.addProperty("payload",     payload);
        v.addProperty("confidence",  confidence);
        v.addProperty("evidence",    evidence);
        v.addProperty("explanation", explanation);
        v.addProperty("url",         url);
        return v;
    }

    private void addManualAction(JsonObject testCase, String parameter, String attackType,
                                 String payload, String url, String reason) {
        JsonObject action = new JsonObject();
        action.addProperty("action",       attackType + " on '" + parameter + "'");
        action.addProperty("tool",         gs(testCase, "manual_tool"));
        action.addProperty("parameter",    parameter);
        action.addProperty("payload",      payload);
        action.addProperty("url",          url);
        action.addProperty("instructions", gs(testCase, "manual_instructions"));
        action.addProperty("reason",       reason);
        settings.addManualAction(action);
    }

    private void printScanComplete(int confirmed, int suspected, int manual) {
        settings.log("╔══════════════════════════════════════════════╗");
        settings.log("  SCAN COMPLETE");
        settings.log("  Confirmed  : " + confirmed
                + (confirmed > 0 ? "  → Confirmed tab" : ""));
        settings.log("  Suspected  : " + suspected
                + (suspected > 0 ? "  → Suspected tab" : ""));
        settings.log("  Manual     : " + manual
                + (manual > 0 ? "  → Manual Actions tab" : ""));
        settings.log("╚══════════════════════════════════════════════╝");
    }

    private String gs(JsonObject obj, String key) {
        return obj != null && obj.has(key) && !obj.get(key).isJsonNull()
                ? obj.get(key).getAsString() : "-";
    }
}
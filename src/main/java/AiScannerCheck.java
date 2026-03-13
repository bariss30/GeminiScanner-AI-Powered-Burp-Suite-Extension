import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.*;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.*;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class AiScannerCheck implements ScanCheck {

    private final MontoyaApi  api;
    private final ApiAnalyzer analyzer;

    public AiScannerCheck(MontoyaApi api, AiSettingsTab settings) {
        this.api      = api;
        this.analyzer = new ApiAnalyzer(api, settings);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        return existingIssue.name().equals(newIssue.name())
                ? ConsolidationAction.KEEP_EXISTING
                : ConsolidationAction.KEEP_BOTH;
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse,
                                   AuditInsertionPoint insertionPoint) {

        JsonObject analysis = analyzer.phase1Analyze(
                baseRequestResponse.request(),
                baseRequestResponse.response()
        );

        if (analysis == null) return AuditResult.auditResult(Collections.emptyList());
        if (!analysis.has("test_cases")) return AuditResult.auditResult(Collections.emptyList());

        String risk = analysis.has("overall_risk")
                ? analysis.get("overall_risk").getAsString() : "UNKNOWN";
        if (risk.equalsIgnoreCase("NONE")) return AuditResult.auditResult(Collections.emptyList());

        List<AuditIssue> issues = new ArrayList<>();

        for (JsonElement el : analysis.getAsJsonArray("test_cases")) {
            JsonObject tc = el.getAsJsonObject();

            String attackType = gs(tc, "attack_type");
            String parameter  = gs(tc, "parameter");
            String severity   = gs(tc, "severity");
            String reasoning  = gs(tc, "reasoning");
            String owasp      = gs(tc, "owasp");
            boolean manual    = tc.has("needs_manual") && tc.get("needs_manual").getAsBoolean();

            StringBuilder payloadBlock = new StringBuilder();
            if (tc.has("payloads")) {
                for (JsonElement pe : tc.getAsJsonArray("payloads")) {
                    JsonObject p = pe.getAsJsonObject();
                    payloadBlock.append("  • ").append(gs(p, "value"))
                            .append("\n    ↳ ").append(gs(p, "detection_hint")).append("\n");
                }
            }

            StringBuilder recoBlock = new StringBuilder();
            if (analysis.has("recommendations")) {
                for (JsonElement r : analysis.getAsJsonArray("recommendations"))
                    recoBlock.append("  • ").append(r.getAsString()).append("\n");
            }

            String manualNote = manual
                    ? "\n⚠ Manual verification required — use " + gs(tc, "manual_tool") + "\n"
                    + gs(tc, "manual_instructions") + "\n"
                    : "";

            AuditIssueSeverity issueSeverity = switch (severity.toUpperCase()) {
                case "HIGH"   -> AuditIssueSeverity.HIGH;
                case "MEDIUM" -> AuditIssueSeverity.MEDIUM;
                case "LOW"    -> AuditIssueSeverity.LOW;
                default       -> AuditIssueSeverity.INFORMATION;
            };

            issues.add(AuditIssue.auditIssue(
                    "GeminiScanner: " + attackType + " — '" + parameter + "'",
                    "Gemini AI identified a potential " + attackType + " vulnerability.\n\n"
                            + "Parameter    : " + parameter + "\n"
                            + "OWASP        : " + owasp + "\n"
                            + "Reasoning    : " + reasoning + "\n\n"
                            + "Suggested Payloads:\n" + payloadBlock
                            + manualNote
                            + "\nRecommendations:\n" + recoBlock,
                    "Verify using GeminiScanner right-click scan or Burp Repeater with the payloads above.",
                    baseRequestResponse.request().url(),
                    issueSeverity,
                    AuditIssueConfidence.TENTATIVE,
                    null, null, null,
                    baseRequestResponse
            ));
        }

        return AuditResult.auditResult(issues);
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        return AuditResult.auditResult(Collections.emptyList());
    }

    private String gs(JsonObject obj, String key) {
        return obj != null && obj.has(key) && !obj.get(key).isJsonNull()
                ? obj.get(key).getAsString() : "-";
    }
}
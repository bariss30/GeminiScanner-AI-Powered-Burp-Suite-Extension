import burp.api.montoya.MontoyaApi;
import com.google.gson.JsonObject;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class AiSettingsTab {

    private final MontoyaApi api;

    private JTextField        apiKeyField;
    private JComboBox<String> modelSelector;
    private JTextArea         customPromptArea;

    private JCheckBox toggleAutoSend;
    private JCheckBox toggleSuspected;
    private JCheckBox toggleRecommendations;
    private JCheckBox toggleDebugLog;

    private JTextArea logArea;

    private DefaultTableModel confirmedModel;
    private JTable            confirmedTable;
    private JTextArea         confirmedDetail;
    private List<JsonObject>  confirmedData = new ArrayList<>();

    private DefaultTableModel suspectedModel;
    private JTable            suspectedTable;
    private JTextArea         suspectedDetail;
    private List<JsonObject>  suspectedData = new ArrayList<>();

    private DefaultTableModel manualModel;
    private JTable            manualTable;
    private JTextArea         manualDetail;
    private List<JsonObject>  manualData = new ArrayList<>();

    private JTextArea xssPayloadArea;
    private JTextArea sqliPayloadArea;
    private JTextArea otherPayloadArea;

    private static final String PREF_API_KEY         = "gemini_api_key";
    private static final String PREF_MODEL           = "gemini_model";
    private static final String PREF_PROMPT          = "gemini_custom_prompt";
    private static final String PREF_XSS             = "payload_xss";
    private static final String PREF_SQLI            = "payload_sqli";
    private static final String PREF_OTHER           = "payload_other";
    private static final String PREF_AUTO_SEND       = "toggle_auto_send";
    private static final String PREF_SUSPECTED       = "toggle_suspected";
    private static final String PREF_RECOMMENDATIONS = "toggle_recommendations";
    private static final String PREF_DEBUG           = "toggle_debug";

    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm:ss");

    public AiSettingsTab(MontoyaApi api) {
        this.api = api;
    }

    public Component createTab() {
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Settings",       buildSettingsPanel());
        tabs.addTab("Scan Log",       buildScanLogPanel());
        tabs.addTab("Confirmed",      buildConfirmedPanel());
        tabs.addTab("Suspected",      buildSuspectedPanel());
        tabs.addTab("Manual Actions", buildManualActionsPanel());
        tabs.addTab("Payloads",       buildPayloadPanel());
        return tabs;
    }

    // ── Settings ──────────────────────────────────────────────────

    private JPanel buildSettingsPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(5, 4, 5, 4);
        g.anchor = GridBagConstraints.WEST;
        g.fill   = GridBagConstraints.HORIZONTAL;

        g.gridx = 0; g.gridy = 0; g.gridwidth = 2; g.weightx = 1.0;
        JLabel title = new JLabel("GeminiScanner — Settings");
        title.setFont(new Font("Dialog", Font.BOLD, 14));
        p.add(title, g);
        g.gridwidth = 1;

        g.gridx = 0; g.gridy = 1; g.weightx = 0;
        p.add(new JLabel("Gemini API Key"), g);
        apiKeyField = new JTextField(45);
        loadPref(PREF_API_KEY, s -> apiKeyField.setText(s));
        g.gridx = 1; g.weightx = 1.0;
        p.add(apiKeyField, g);

        g.gridx = 0; g.gridy = 2; g.weightx = 0;
        p.add(new JLabel("Model"), g);
        modelSelector = new JComboBox<>(new String[]{
                "gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro"});
        loadPref(PREF_MODEL, s -> modelSelector.setSelectedItem(s));
        g.gridx = 1; g.weightx = 1.0;
        p.add(modelSelector, g);

        g.gridx = 0; g.gridy = 3; g.gridwidth = 2;
        p.add(new JSeparator(), g);

        g.gridy = 4;
        JPanel togglePanel = new JPanel(new GridLayout(2, 2, 12, 6));
        togglePanel.setBorder(titledBorder("Scan Behaviour"));

        toggleAutoSend        = new JCheckBox("Auto-send payloads (Phase 2 active verification)");
        toggleSuspected       = new JCheckBox("Show suspected findings (low confidence)");
        toggleRecommendations = new JCheckBox("Show recommendations in Scan Log");
        toggleDebugLog        = new JCheckBox("Debug log");

        loadPrefBool(PREF_AUTO_SEND,       b -> toggleAutoSend.setSelected(b),        true);
        loadPrefBool(PREF_SUSPECTED,       b -> toggleSuspected.setSelected(b),       true);
        loadPrefBool(PREF_RECOMMENDATIONS, b -> toggleRecommendations.setSelected(b), true);
        loadPrefBool(PREF_DEBUG,           b -> toggleDebugLog.setSelected(b),        false);

        togglePanel.add(toggleAutoSend);
        togglePanel.add(toggleSuspected);
        togglePanel.add(toggleRecommendations);
        togglePanel.add(toggleDebugLog);
        p.add(togglePanel, g);
        g.gridwidth = 1;

        g.gridx = 0; g.gridy = 5; g.gridwidth = 2;
        p.add(new JSeparator(), g);

        g.gridy = 6;
        p.add(new JLabel("Custom System Prompt (optional — leave empty for default)"), g);
        customPromptArea = new JTextArea(12, 0);
        customPromptArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        customPromptArea.setLineWrap(true);
        customPromptArea.setWrapStyleWord(true);
        loadPref(PREF_PROMPT, s -> customPromptArea.setText(s));
        g.gridy = 7; g.weighty = 1.0; g.fill = GridBagConstraints.BOTH;
        p.add(new JScrollPane(customPromptArea), g);

        g.gridy = 8; g.weighty = 0; g.fill = GridBagConstraints.NONE;
        g.anchor = GridBagConstraints.EAST;
        JButton saveBtn = new JButton("Save Settings");
        saveBtn.addActionListener(e -> { saveSettings(); log("[INFO] Settings saved."); });
        p.add(saveBtn, g);

        return p;
    }

    // ── Scan Log ──────────────────────────────────────────────────

    private JPanel buildScanLogPanel() {
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 12));

        JButton clearBtn = new JButton("Clear Log");
        clearBtn.addActionListener(e -> logArea.setText(""));

        JPanel top = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 4));
        top.add(clearBtn);

        JPanel p = new JPanel(new BorderLayout());
        p.add(top, BorderLayout.NORTH);
        p.add(new JScrollPane(logArea), BorderLayout.CENTER);
        return p;
    }

    // ── Confirmed ─────────────────────────────────────────────────

    private JSplitPane buildConfirmedPanel() {
        confirmedModel = buildVulnModel();
        confirmedTable = buildTable(confirmedModel);
        confirmedDetail = buildDetailArea();
        confirmedTable.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                showVulnDetail(confirmedTable, confirmedData, confirmedDetail);
            }
        });
        JButton clear = new JButton("Clear");
        clear.addActionListener(e -> { confirmedModel.setRowCount(0); confirmedData.clear(); confirmedDetail.setText(""); });
        return buildSplit(confirmedTable, confirmedDetail,
                "Confirmed Vulnerabilities — click row for details", clear);
    }

    // ── Suspected ─────────────────────────────────────────────────

    private JSplitPane buildSuspectedPanel() {
        suspectedModel = buildVulnModel();
        suspectedTable = buildTable(suspectedModel);
        suspectedDetail = buildDetailArea();
        suspectedTable.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                showVulnDetail(suspectedTable, suspectedData, suspectedDetail);
            }
        });
        JButton clear = new JButton("Clear");
        clear.addActionListener(e -> { suspectedModel.setRowCount(0); suspectedData.clear(); suspectedDetail.setText(""); });
        return buildSplit(suspectedTable, suspectedDetail,
                "Suspected Findings — low confidence, manual verification needed", clear);
    }

    // ── Manual Actions ────────────────────────────────────────────

    private JSplitPane buildManualActionsPanel() {
        String[] cols = {"Action", "Tool", "Parameter", "Payload", "URL"};
        manualModel = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        manualTable = buildTable(manualModel);
        manualTable.getColumnModel().getColumn(0).setPreferredWidth(140);
        manualTable.getColumnModel().getColumn(1).setPreferredWidth(80);
        manualDetail = buildDetailArea();
        manualTable.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) { showManualDetail(); }
        });
        JButton clear = new JButton("Clear");
        clear.addActionListener(e -> { manualModel.setRowCount(0); manualData.clear(); manualDetail.setText(""); });
        return buildSplit(manualTable, manualDetail,
                "Manual Actions — AI flagged these as requiring Repeater / Intruder / human interaction", clear);
    }

    // ── Payload Lists ─────────────────────────────────────────────

    private JPanel buildPayloadPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        GridBagConstraints g = new GridBagConstraints();
        g.fill = GridBagConstraints.BOTH;
        g.insets = new Insets(4, 4, 4, 4);
        g.weightx = 1.0;

        g.gridx = 0; g.gridy = 0; g.weighty = 0;
        p.add(new JLabel("XSS Payloads — one per line, used as AI hints"), g);
        xssPayloadArea = new JTextArea(6, 0);
        xssPayloadArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        try {
            String s = api.persistence().extensionData().getString(PREF_XSS);
            if (s != null) xssPayloadArea.setText(s);
            else xssPayloadArea.setText(
                    "<script>alert(1)</script>\n<img src=x onerror=alert(1)>\n" +
                            "\"><script>alert(1)</script>\n'><svg onload=alert(1)>\n<svg/onload=alert(1)>");
        } catch (Exception ignored) {}
        g.gridy = 1; g.weighty = 0.33;
        p.add(new JScrollPane(xssPayloadArea), g);

        g.gridy = 2; g.weighty = 0;
        p.add(new JLabel("SQLi Payloads"), g);
        sqliPayloadArea = new JTextArea(6, 0);
        sqliPayloadArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        try {
            String s = api.persistence().extensionData().getString(PREF_SQLI);
            if (s != null) sqliPayloadArea.setText(s);
            else sqliPayloadArea.setText(
                    "' OR '1'='1\n' OR 1=1--\nadmin'--\n' UNION SELECT null,null--\n' AND SLEEP(3)--");
        } catch (Exception ignored) {}
        g.gridy = 3; g.weighty = 0.33;
        p.add(new JScrollPane(sqliPayloadArea), g);

        g.gridy = 4; g.weighty = 0;
        p.add(new JLabel("Other — IDOR, SSTI, Path Traversal, Business Logic"), g);
        otherPayloadArea = new JTextArea(6, 0);
        otherPayloadArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        try {
            String s = api.persistence().extensionData().getString(PREF_OTHER);
            if (s != null) otherPayloadArea.setText(s);
            else otherPayloadArea.setText("../../../etc/passwd\n{{7*7}}\n${7*7}\n; ls -la\n| whoami");
        } catch (Exception ignored) {}
        g.gridy = 5; g.weighty = 0.33;
        p.add(new JScrollPane(otherPayloadArea), g);

        g.gridy = 6; g.weighty = 0; g.fill = GridBagConstraints.NONE;
        g.anchor = GridBagConstraints.EAST;
        JButton saveBtn = new JButton("Save Payload Lists");
        saveBtn.addActionListener(e -> savePayloads());
        p.add(saveBtn, g);

        return p;
    }

    // ── Public API ────────────────────────────────────────────────

    public void log(String message) {
        String line = "[" + LocalTime.now().format(TIME_FMT) + "]  " + message + "\n";
        SwingUtilities.invokeLater(() -> {
            if (logArea == null) return;
            logArea.append(line);
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    public void logDebug(String msg)  { if (isDebugEnabled()) log("[DEBUG] " + msg); }
    public void logError(String msg)  { log("[ERROR] " + msg); }

    public void addConfirmedVuln(JsonObject v) {
        SwingUtilities.invokeLater(() -> {
            confirmedData.add(v);
            confirmedModel.addRow(new Object[]{
                    gs(v,"parameter"), gs(v,"attack_type"),
                    gs(v,"severity"),  gs(v,"confidence"),
                    gs(v,"payload"),   gs(v,"url")});
        });
    }

    public void addSuspectedVuln(JsonObject v) {
        if (!isSuspectedEnabled()) return;
        SwingUtilities.invokeLater(() -> {
            suspectedData.add(v);
            suspectedModel.addRow(new Object[]{
                    gs(v,"parameter"), gs(v,"attack_type"),
                    gs(v,"severity"),  gs(v,"confidence"),
                    gs(v,"payload"),   gs(v,"url")});
        });
    }

    public void addManualAction(JsonObject a) {
        SwingUtilities.invokeLater(() -> {
            manualData.add(a);
            manualModel.addRow(new Object[]{
                    gs(a,"action"), gs(a,"tool"),
                    gs(a,"parameter"), gs(a,"payload"), gs(a,"url")});
        });
    }

    public boolean isAutoSendEnabled()        { return toggleAutoSend        != null && toggleAutoSend.isSelected(); }
    public boolean isSuspectedEnabled()       { return toggleSuspected       != null && toggleSuspected.isSelected(); }
    public boolean isRecommendationsEnabled() { return toggleRecommendations != null && toggleRecommendations.isSelected(); }
    public boolean isDebugEnabled()           { return toggleDebugLog        != null && toggleDebugLog.isSelected(); }

    public String getApiKey()       { return apiKeyField     == null ? "" : apiKeyField.getText().trim(); }
    public String getModel()        { return modelSelector   == null ? "gemini-2.5-flash" : (String) modelSelector.getSelectedItem(); }
    public String getCustomPrompt() { return customPromptArea == null ? "" : customPromptArea.getText().trim(); }
    public String getXssPayloads()  { return xssPayloadArea   == null ? "" : xssPayloadArea.getText(); }
    public String getSqliPayloads() { return sqliPayloadArea  == null ? "" : sqliPayloadArea.getText(); }
    public String getOtherPayloads(){ return otherPayloadArea == null ? "" : otherPayloadArea.getText(); }

    // ── Private ───────────────────────────────────────────────────

    private void saveSettings() {
        try {
            api.persistence().extensionData().setString(PREF_API_KEY, apiKeyField.getText().trim());
            api.persistence().extensionData().setString(PREF_MODEL, (String) modelSelector.getSelectedItem());
            api.persistence().extensionData().setString(PREF_PROMPT, customPromptArea.getText().trim());
            api.persistence().extensionData().setString(PREF_AUTO_SEND,       String.valueOf(toggleAutoSend.isSelected()));
            api.persistence().extensionData().setString(PREF_SUSPECTED,       String.valueOf(toggleSuspected.isSelected()));
            api.persistence().extensionData().setString(PREF_RECOMMENDATIONS, String.valueOf(toggleRecommendations.isSelected()));
            api.persistence().extensionData().setString(PREF_DEBUG,           String.valueOf(toggleDebugLog.isSelected()));
        } catch (Exception e) {
            api.logging().logToError("Settings save error: " + e.getMessage());
        }
    }

    private void savePayloads() {
        try {
            api.persistence().extensionData().setString(PREF_XSS,   xssPayloadArea.getText());
            api.persistence().extensionData().setString(PREF_SQLI,  sqliPayloadArea.getText());
            api.persistence().extensionData().setString(PREF_OTHER, otherPayloadArea.getText());
            log("[INFO] Payload lists saved.");
        } catch (Exception e) {
            api.logging().logToError("Payload save error: " + e.getMessage());
        }
    }

    private void showVulnDetail(JTable table, List<JsonObject> data, JTextArea detail) {
        int row = table.getSelectedRow();
        if (row < 0 || row >= data.size()) return;
        JsonObject v = data.get(row);
        detail.setText(
                "══════════════════════════════════════════════════════\n" +
                        "  " + gs(v,"attack_type") + "  [" + gs(v,"severity") + "]\n" +
                        "══════════════════════════════════════════════════════\n\n" +
                        "URL         : " + gs(v,"url")         + "\n" +
                        "Parameter   : " + gs(v,"parameter")   + "\n" +
                        "Confidence  : " + gs(v,"confidence")  + "\n\n" +
                        "EVIDENCE:\n  "    + gs(v,"evidence")    + "\n\n" +
                        "EXPLANATION:\n  " + gs(v,"explanation") + "\n\n" +
                        "PAYLOAD:\n  "     + gs(v,"payload")     + "\n\n" +
                        "REPRODUCTION:\n" +
                        "  1. Open request in Burp Repeater\n" +
                        "  2. Set '" + gs(v,"parameter") + "' to the payload above\n" +
                        "  3. Send and observe response\n"
        );
        detail.setCaretPosition(0);
    }

    private void showManualDetail() {
        int row = manualTable.getSelectedRow();
        if (row < 0 || row >= manualData.size()) return;
        JsonObject a = manualData.get(row);
        manualDetail.setText(
                "══════════════════════════════════════════════════════\n" +
                        "  MANUAL ACTION REQUIRED\n" +
                        "══════════════════════════════════════════════════════\n\n" +
                        "Action      : " + gs(a,"action")       + "\n" +
                        "Suggested Tool: " + gs(a,"tool")       + "\n" +
                        "URL         : " + gs(a,"url")          + "\n" +
                        "Parameter   : " + gs(a,"parameter")    + "\n" +
                        "Payload     : " + gs(a,"payload")      + "\n\n" +
                        "INSTRUCTIONS:\n" + gs(a,"instructions") + "\n\n" +
                        "WHY MANUAL:\n  " + gs(a,"reason")      + "\n"
        );
        manualDetail.setCaretPosition(0);
    }

    private DefaultTableModel buildVulnModel() {
        String[] cols = {"Parameter", "Type", "Severity", "Confidence", "Payload", "URL"};
        return new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
    }

    private JTable buildTable(DefaultTableModel model) {
        JTable t = new JTable(model);
        t.setFont(new Font("Monospaced", Font.PLAIN, 12));
        t.setRowHeight(22);
        t.getColumnModel().getColumn(0).setPreferredWidth(90);
        t.getColumnModel().getColumn(1).setPreferredWidth(90);
        t.getColumnModel().getColumn(2).setPreferredWidth(65);
        t.getColumnModel().getColumn(3).setPreferredWidth(65);
        return t;
    }

    private JTextArea buildDetailArea() {
        JTextArea ta = new JTextArea();
        ta.setEditable(false);
        ta.setFont(new Font("Monospaced", Font.PLAIN, 12));
        ta.setLineWrap(true);
        ta.setWrapStyleWord(true);
        return ta;
    }

    private JSplitPane buildSplit(JTable table, JTextArea detail, String title, JButton clearBtn) {
        JPanel top = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 4));
        top.add(clearBtn);
        JPanel tablePanel = new JPanel(new BorderLayout());
        tablePanel.add(top, BorderLayout.NORTH);
        tablePanel.add(new JScrollPane(table), BorderLayout.CENTER);
        tablePanel.setBorder(titledBorder(title));
        JScrollPane detailScroll = new JScrollPane(detail);
        detailScroll.setBorder(titledBorder("Details"));
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tablePanel, detailScroll);
        split.setDividerLocation(200);
        return split;
    }

    private void loadPref(String key, java.util.function.Consumer<String> fn) {
        try { String s = api.persistence().extensionData().getString(key); if (s != null) fn.accept(s); }
        catch (Exception ignored) {}
    }

    private void loadPrefBool(String key, java.util.function.Consumer<Boolean> fn, boolean def) {
        try {
            String s = api.persistence().extensionData().getString(key);
            fn.accept(s != null ? Boolean.parseBoolean(s) : def);
        } catch (Exception ignored) { fn.accept(def); }
    }

    private Border titledBorder(String title) {
        TitledBorder tb = BorderFactory.createTitledBorder(title);
        tb.setTitleFont(new Font("Dialog", Font.PLAIN, 11));
        return tb;
    }

    private String gs(JsonObject obj, String key) {
        return obj != null && obj.has(key) ? obj.get(key).getAsString() : "-";
    }
}
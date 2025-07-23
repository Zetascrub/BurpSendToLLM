package burp;

import java.util.List;
import java.util.ArrayList;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.ITab;

import java.net.URL;
import java.net.HttpURLConnection;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;


import com.formdev.flatlaf.FlatDarkLaf;
import org.json.JSONObject;
import org.json.JSONArray;

import net.miginfocom.swing.MigLayout;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;

// AWT layout & geometry classes
import java.awt.Rectangle;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;

// Swing widgets for advanced UI
import javax.swing.JTextArea;
import javax.swing.JComboBox;
import javax.swing.JSplitPane;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;



public class BurpExtender implements burp.IBurpExtender, burp.IContextMenuFactory, burp.ITab {
    private IBurpExtenderCallbacks callbacks;
    private IContextMenuInvocation lastInvocation;
    private IHttpRequestResponse lastSelectedMessage;
    private IExtensionHelpers helpers;

    // UI components
    private JPanel mainPanel;
    private JTabbedPane tabbedPane;
    private DefaultTableModel tableModel;
    private JTable resultsTable;
    private TableRowSorter<DefaultTableModel> sorter;
    private JTextField filterField;
    private JProgressBar progressBar;

    
    // SendToLLM components
    private JTextArea promptArea;
    private JTextArea responseArea;
    private JButton sendButton;

    
    // split your URL into host:port + suffix
    private JTextField serverField;
    private JLabel suffixLabel;

    private JTextField modelField;

    // Settings
    private String serverUrl = "http://localhost:8000";
    private String modelName = "llama3.2";

    // Templates
    private final Map<String, String> templates = new LinkedHashMap<>();
    private final Map<String, String> pentestTemplates = new LinkedHashMap<>();

    // For your historical view
    private DefaultTableModel historyModel;
    private JTable          historyTable;
    private List<String>    fullResponses = new ArrayList<>();
    private JTextArea       detailArea;

    // For the template editor tab
    private JComboBox<String> templateCombo;
    private JTextArea         templateEditor;

    // For your pentest‑tools tab
    private JComboBox<String>    toolSelector;
    private JTextArea            toolPromptEditor;
    private JTextArea            toolResponseArea;


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.printOutput("SendToLLM loaded—version 2025.07.23.2");
        callbacks.setExtensionName("Send to LLM Enhanced");
        callbacks.registerContextMenuFactory(this);

        // Load persisted settings
        String savedUrl = callbacks.loadExtensionSetting("serverUrl");
        if (savedUrl != null) serverUrl = savedUrl;
        String savedModel = callbacks.loadExtensionSetting("modelName");
        if (savedModel != null) modelName = savedModel;

        // Initialize templates
        templates.put("Basic Analysis",
            "Analyze the following HTTP request and return structured JSON.\n{{ request }}");
        templates.put("Security Review",
            "You are a security auditor. Review this request and return vulnerabilities as JSON.\n{{ request }}");
        // Pentest tools templates
        pentestTemplates.put("Header Analyzer",
            "Analyze the following HTTP headers and return ONLY a valid JSON object listing vulnerabilities.\nHeaders:\n{{ headers }}");
        pentestTemplates.put("Param Guess Helper",
            "Suggest hidden parameters to fuzz. Return JSON:\n{ \"parameters\": [ ... ] }\nRequest:\n{{ request }}");
        pentestTemplates.put("Vuln Suggestor",
            "Analyze the request for vulnerabilities. Return JSON.\n{{ request }}");

        applyLookAndFeel();
        SwingUtilities.invokeLater(() -> {
        createUi();
        callbacks.addSuiteTab(this);
    });
    }


    private void applyLookAndFeel() {
        try {
            
        } catch (Exception e) {
            callbacks.printError("Failed to apply Look & Feel: " + e.getMessage());
        }
    }


    private void initUi() {
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(new EmptyBorder(5,5,5,5));
        tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Main", createMainPanel());
        tabbedPane.addTab("Settings", createSettingsPanel());
        mainPanel.add(tabbedPane, BorderLayout.CENTER);
    }

    private JPanel createMainPanel() {
        JPanel panel = new JPanel(new MigLayout("fill, insets 5", "[grow,fill]", "[][grow][]"));
        JToolBar toolbar = new JToolBar(); toolbar.setFloatable(false);
        toolbar.add(new JButton(new AbstractAction("Clear") {
            @Override public void actionPerformed(ActionEvent e) { tableModel.setRowCount(0); }
        }));
        panel.add(toolbar, "dock north, wrap");

        panel.add(new JLabel("Filter:"));
        filterField = new JTextField(15); panel.add(filterField, "wrap");

        tableModel = new DefaultTableModel(new String[]{"Prompt","Response"}, 0);
        resultsTable = new JTable(tableModel);
        resultsTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object v, boolean s, boolean f, int r, int c) {
                Component comp = super.getTableCellRendererComponent(t,v,s,f,r,c);
                if (!s) comp.setBackground(r % 2 == 0 ? Color.WHITE : new Color(240,240,240));
                return comp;
            }
        });
        sorter = new TableRowSorter<>(tableModel);
        resultsTable.setRowSorter(sorter);
        filterField.getDocument().addDocumentListener(new DocumentListener() {
            private void update() {
                String t = filterField.getText();
                sorter.setRowFilter(t.trim().isEmpty() ? null : RowFilter.regexFilter("(?i)" + t));
            }
            public void insertUpdate(DocumentEvent e) { update(); }
            public void removeUpdate(DocumentEvent e) { update(); }
            public void changedUpdate(DocumentEvent e) { update(); }
        });
        panel.add(new JScrollPane(resultsTable), "grow, wrap");

        progressBar = new JProgressBar(); progressBar.setStringPainted(true);
        panel.add(progressBar, "growx");
        return panel;
    }

    @Override
    public java.util.List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] msgs = invocation.getSelectedMessages();
        if (msgs == null || msgs.length == 0) return Collections.emptyList();
        lastInvocation = invocation;
        lastSelectedMessage = msgs[0];
        JMenu menu = new JMenu("Send to →");
        JMenuItem basic = new JMenuItem("Basic Analysis");
        basic.addActionListener(e -> runLLMWithTemplate("Basic Analysis", msgs[0]));
        menu.add(basic);
        JMenuItem sec = new JMenuItem("Security Review");
        sec.addActionListener(e -> sendWithTemplate("Security Review", msgs[0]));
        menu.add(sec);
        menu.addSeparator();
        for (String key : pentestTemplates.keySet()) {
            JMenuItem item = new JMenuItem(key);
            item.addActionListener(e -> runPentesterTool(key, msgs[0]));
            menu.add(item);
        }
        return Arrays.asList(menu);
    }

    private JPanel createSettingsPanel() {
        JPanel panel = new JPanel(new MigLayout("fill, insets 5", "[][grow]", "[]10[]"));
        
        // user only edits host:port
        panel.add(new JLabel("Server (IP:Port):"), "right");
        serverField = new JTextField("127.0.0.1:11434", 30);
        suffixLabel = new JLabel("/v1/chat/completions");
        suffixLabel.setEnabled(false);
        panel.add(serverField, "growx");
        panel.add(suffixLabel, "wrap");

        panel.add(new JLabel("Model Name:"), "right");
        modelField = new JTextField(modelName); panel.add(modelField, "growx, wrap");
        JButton save = new JButton("Save");
        save.addActionListener(e -> saveSettings());
        panel.add(save, "span 2, center");
        return panel;
    }

    private void saveSettings() {
        String server = serverField.getText().trim();
        // simply store the scheme + host:port
        serverUrl = "http://" + server;

        modelName = modelField.getText().trim();
        callbacks.saveExtensionSetting("serverUrl", serverUrl);
        callbacks.saveExtensionSetting("modelName", modelName);
        JOptionPane.showMessageDialog(mainPanel, "Settings saved.", "Settings", JOptionPane.INFORMATION_MESSAGE);
    }

    private void runLLMWithTemplate(String templateName, IHttpRequestResponse message) {
        // Build the exact endpoint and hand it to sendPromptToLLM
        callbacks.printOutput("▶️ runLLMWithTemplate(template=" + templateName + ")");
        String rawReq   = helpers.bytesToString(message.getRequest());
        String template = templates.getOrDefault(templateName, "{{ request }}");
        String prompt   = template.replace("{{ request }}", rawReq);

        sendPromptToLLM(prompt);
    }

    private void runPentesterTool(String toolName, IHttpRequestResponse message) {
        callbacks.printOutput("▶️ runPentesterTool(tool=" + toolName + ")");
        String rawReq   = helpers.bytesToString(message.getRequest());
        String headers  = rawReq.split("\r\n\r\n")[0];

        String template = pentestTemplates.getOrDefault(toolName, "{{ request }}");
        String prompt   = template
                            .replace("{{ request }}", rawReq)
                            .replace("{{ headers }}", headers);

        sendPromptToLLM(prompt);
    }

    private void sendPromptToLLM(String promptText) {
        String host   = serverField != null ? serverField.getText().trim() : "127.0.0.1:11434";
        String suffix = suffixLabel != null ? suffixLabel.getText() : "/v1/chat/completions";
        String targetEndpoint = "http://" + host + suffix;
        String modelName      = modelField != null ? modelField.getText().trim() : "ollama";
        callbacks.printOutput("▶️ sendPromptToLLM called. endpoint=" + targetEndpoint + " model=" + modelName);
        HttpURLConnection conn = null;
        String finalResponse = "";
        try {
            // Build JSON payload using built-in org.json
            JSONObject payload = new JSONObject();
            payload.put("model", modelName);
            JSONArray messages = new JSONArray();
            JSONObject message = new JSONObject();
            message.put("role", "user");
            message.put("content", promptText);
            messages.put(message);
            payload.put("messages", messages);
            String jsonBody = payload.toString();
            callbacks.printOutput("🔍 JSON payload: " + jsonBody);

            // HTTP POST
            URL url = new URL(targetEndpoint);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
            }

            int status = conn.getResponseCode();
            callbacks.printOutput("ℹ️ HTTP status: " + status);
            InputStream in = status < 400 ? conn.getInputStream() : conn.getErrorStream();
            String response = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            callbacks.printOutput("✅ LLM raw response: " + response);

            // Parse and extract content using org.json
            JSONObject root = new JSONObject(response);
            JSONArray choices = root.optJSONArray("choices");
            if (choices != null && choices.length() > 0) {
                JSONObject choice = choices.getJSONObject(0).getJSONObject("message");
                finalResponse = choice.optString("content", "");
            }
        } catch (Exception e) {
            callbacks.printError("❌ sendPromptToLLM exception: " + e.getClass().getSimpleName() + " – " + e.getMessage());
            finalResponse = "Error: " + e.getMessage();
        } finally {
            if (conn != null) conn.disconnect();
        }

        final String capturePrompt = promptText;
        final String captureResponse = finalResponse;
        SwingUtilities.invokeLater(() -> {
            promptArea.setText(capturePrompt);
            responseArea.setText(captureResponse);
            tableModel.addRow(new Object[]{capturePrompt, captureResponse});
        });
    }




    private String escapeJson(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }





    private void sendWithTemplate(String name, IHttpRequestResponse msg) {
        runLLMWithTemplate(name, msg);
    }

    private String extractStructuredContent(String json) {
        try {
            org.json.JSONObject root = new org.json.JSONObject(json);
            if (root.has("content")) return root.getString("content");
            org.json.JSONArray choices = root.getJSONArray("choices");
            return choices.getJSONObject(0).getJSONObject("message").getString("content");
        } catch (Exception e) {
            return json;
        }
    }

    private String formatVulnsAsText(String fullJson) {
        try {
            org.json.JSONObject root = new org.json.JSONObject(fullJson);
            org.json.JSONArray choices = root.getJSONArray("choices");
            String content = choices.getJSONObject(0).getJSONObject("message").getString("content");

            String jsonPart = extractJsonBlock(content);
            if (jsonPart == null) {
                jsonPart = content.trim(); // no code block, use the whole thing
            }

            // Try parsing as JSONObject first
            try {
                org.json.JSONObject parsed = new org.json.JSONObject(jsonPart);
                org.json.JSONArray vulns = parsed.optJSONArray("vulnerabilities");

                if (vulns == null || vulns.length() == 0) {
                    return "✅ No vulnerabilities found.";
                }

                return formatVulnArray(vulns);
            } catch (org.json.JSONException ex) {
                // Not an object — try as raw array
                org.json.JSONArray array = new org.json.JSONArray(jsonPart);
                return formatVulnArray(array);
            }

        } catch (Exception e) {
            return "⚠️ Could not parse JSON content:\n" + e.getMessage();
        }
    }


    private String formatVulnArray(org.json.JSONArray vulns) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < vulns.length(); i++) {
            org.json.JSONObject vuln = vulns.getJSONObject(i);

            String name = vuln.optString("vulnerability",
                        vuln.optString("type",
                        vuln.optString("name", "N/A")));

            String desc = vuln.optString("description", "N/A");
            String severity = vuln.optString("severity",
                            vuln.optString("risk_level", "N/A"));
            String recommendation = vuln.optString("recommendation", "N/A");

            sb.append("• Vulnerability: ").append(name).append("\n");
            sb.append("  Description: ").append(desc).append("\n");
            if (!severity.equals("N/A")) {
                sb.append("  Severity: ").append(severity).append("\n");
            }

            sb.append("  Recommendation: ").append(recommendation).append("\n\n");
        }
        return sb.toString().trim();
    }


    private void sendPentestTool(String key, IHttpRequestResponse msg) {
        runPentesterTool(key, msg);
    }

    private void sendPrompt(String prompt, String url, String model) {
        new SwingWorker<String, Void>() {
            @Override protected String doInBackground() throws Exception {
                progressBar.setIndeterminate(true);
                String payload = String.format(
                    "{\"model\":\"%s\",\"messages\":[{\"role\":\"user\",\"content\":\"%s\"}],\"options\":{}}",
                    model, prompt.replace("\\", "\\\\").replace("\"", "\\\"")
                );
                return httpPost(url, payload);
            }
            @Override protected void done() {
                try {
                    String res = get();
                    progressBar.setIndeterminate(false);
                    tableModel.addRow(new Object[]{prompt, res});
                } catch (InterruptedException | ExecutionException ex) {
                    callbacks.issueAlert("Error: " + ex.getMessage());
                }
            }
        }.execute();
    }



    private String httpPost(String url, String body) throws Exception {
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection)
            new java.net.URL(url).openConnection();
        conn.setRequestMethod("POST"); conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/json");
        byte[] out = body.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        conn.setRequestProperty("Content-Length", String.valueOf(out.length));
        try (java.io.OutputStream os = conn.getOutputStream()) { os.write(out); }
        try (java.io.InputStream is = conn.getResponseCode() < 300 ? conn.getInputStream() : conn.getErrorStream();
             java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(is))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) sb.append(line).append('\n');
            return sb.toString().trim();
        }
    }

    private void showResponse(String rawJson) {
        SwingUtilities.invokeLater(() -> {
            String formatted = formatVulnsAsText(rawJson);
            JTextArea area = new JTextArea(formatted);
            area.setEditable(false);
            area.setLineWrap(true);
            area.setWrapStyleWord(true);
            JOptionPane.showMessageDialog(null, new JScrollPane(area), "LLM Response", JOptionPane.PLAIN_MESSAGE);
        });
    }

    private String extractJsonBlock(String text) {
        try {
            int start = text.indexOf("```");
            if (start == -1) return null;

            int end = text.indexOf("```", start + 3);
            if (end == -1) return null;

            String block = text.substring(start + 3, end).trim();

            // Remove leading "json" if present
            if (block.toLowerCase().startsWith("json")) {
                block = block.substring(4).trim();
            }

            // Remove all lines with JavaScript-style comments (//)
            String[] lines = block.split("\n");
            StringBuilder cleaned = new StringBuilder();
            for (String line : lines) {
                String trimmed = line.trim();
                if (!trimmed.startsWith("//")) {
                    // Also remove inline comments (e.g. "description": "...", // hint)
                    int commentIndex = trimmed.indexOf("//");
                    if (commentIndex != -1) {
                        trimmed = trimmed.substring(0, commentIndex).trim();
                    }
                    cleaned.append(trimmed).append("\n");
                }
            }

            return cleaned.toString().trim();
        } catch (Exception e) {
            return null;
        }
    }


    private void standardizeComponentSize(JComponent... components) {
        Dimension size = new Dimension(250, 25); // Consistent width & height
        for (JComponent comp : components) {
            comp.setPreferredSize(size);
            comp.setMaximumSize(size);
            comp.setMinimumSize(size);
        }
    }
    
    private void createUi() {
        // ======== Root panel & tabbed pane ========
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
        tabbedPane = new JTabbedPane();

        // ======== 1) Main Tab ========
        tabbedPane.addTab("Main", createMainPanel());

        // ======== 2) Settings Tab ========
        tabbedPane.addTab("Settings", createSettingsPanel());

        // ======== 3) Pentester Tools Tab ========
        JPanel pentestPanel = new JPanel(new BorderLayout(10, 10));
        pentestPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        // … copy your pentestPanel UI and sendButton ActionListener here …
        tabbedPane.addTab("Pentester Tools", pentestPanel);

        // ======== 4) SendToLLM Tab ========
        JPanel llmPanel = new JPanel(new BorderLayout(5,5));
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        split.setResizeWeight(0.5);

        // Prompt area
        promptArea = new JTextArea();
        promptArea.setLineWrap(true);
        promptArea.setWrapStyleWord(true);
        // Allow the user to edit the prompt before sending
        promptArea.setEditable(true);
        JScrollPane promptScroll = new JScrollPane(promptArea);
        promptScroll.setBorder(BorderFactory.createTitledBorder("Prompt"));

        // Response area
        responseArea = new JTextArea();
        responseArea.setLineWrap(true);
        responseArea.setWrapStyleWord(true);
        responseArea.setEditable(false);
        JScrollPane responseScroll = new JScrollPane(responseArea);
        responseScroll.setBorder(BorderFactory.createTitledBorder("Response"));

        split.setTopComponent(promptScroll);
        split.setBottomComponent(responseScroll);
        llmPanel.add(split, BorderLayout.CENTER);

        // Send button so users can manually dispatch prompts
        sendButton = new JButton("Send");
        sendButton.addActionListener(e -> sendPromptToLLM(promptArea.getText()));
        JPanel sendPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        sendPanel.add(sendButton);
        llmPanel.add(sendPanel, BorderLayout.SOUTH);

        tabbedPane.addTab("SendToLLM", llmPanel);

        // ======== Finish up ========
        mainPanel.add(tabbedPane, BorderLayout.CENTER);
    }


        private void showSettingsDialog() {
        // TODO: implement settings UI (e.g., API key input)
        JOptionPane.showMessageDialog(mainPanel, "Settings not yet implemented.", "Settings", JOptionPane.INFORMATION_MESSAGE);
    }

    // Example of running a long task without freezing UI
    private void performLongTask() {
        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                progressBar.setIndeterminate(true);
                // TODO: replace with actual logic (e.g., send request, parse response)
                Thread.sleep(2000);
                return null;
            }

            @Override
            protected void done() {
                progressBar.setIndeterminate(false);
                // TODO: populate tableModel with results
                tableModel.addRow(new Object[]{"SampleReq", "SampleResp", "SampleData"});
            }
        }.execute();
    }

    @Override public String getTabCaption() { return "SendToLLM"; }

    
    public Component getUiComponent() {
        if (mainPanel == null) {
            mainPanel = new JPanel(new BorderLayout());
            JTabbedPane tabbedPane = new JTabbedPane();

            // Main Tab
            JPanel tablePanel = createMainPanel();
            tabbedPane.addTab("Main", tablePanel);

            // Send Tab
            JPanel sendPanel = createSendPanel();
            tabbedPane.addTab("Send", sendPanel);

            mainPanel.add(tabbedPane, BorderLayout.CENTER);
        }
        return mainPanel;

    }


    private JPanel createSendPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));

        // Prompt area
        promptArea = new JTextArea(5, 40);
        promptArea.setBorder(BorderFactory.createTitledBorder("Prompt"));
        panel.add(new JScrollPane(promptArea), BorderLayout.NORTH);

        // Send button
        sendButton = new JButton("Send");
        sendButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String prompt = promptArea.getText();
                sendPromptToLLM(prompt);
            }
        });
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.add(sendButton);
        panel.add(buttonPanel, BorderLayout.CENTER);

        // Response area
        responseArea = new JTextArea(10, 40);
        responseArea.setBorder(BorderFactory.createTitledBorder("Response"));
        responseArea.setEditable(false);
        panel.add(new JScrollPane(responseArea), BorderLayout.SOUTH);

        return panel;
    }

}

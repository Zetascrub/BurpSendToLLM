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
import java.nio.charset.StandardCharsets;

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
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public class BurpExtender implements burp.IBurpExtender, burp.IContextMenuFactory, burp.ITab {
    private IBurpExtenderCallbacks callbacks;
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

    // Settings components
    private JTextField serverField;
    private JLabel suffixLabel;
    private JTextField modelField;

    // Settings
    private String serverUrl = "http://localhost:11434";  // Fixed default Ollama port
    private String modelName = "llama3.2";

    // Templates
    private final Map<String, String> templates = new LinkedHashMap<>();
    private final Map<String, String> pentestTemplates = new LinkedHashMap<>();

    // Background task management
    private SwingWorker<String, Void> currentWorker;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.printOutput("SendToLLM loaded—version 2025.01.05.1");
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

        SwingUtilities.invokeLater(() -> {
            createUi();
            callbacks.addSuiteTab(this);
        });
    }

    private void createUi() {
        // Root panel & tabbed pane
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
        tabbedPane = new JTabbedPane();

        // 1) Main Tab
        tabbedPane.addTab("Main", createMainPanel());

        // 2) Settings Tab
        tabbedPane.addTab("Settings", createSettingsPanel());

        // 3) SendToLLM Tab
        tabbedPane.addTab("SendToLLM", createSendToLLMPanel());

        mainPanel.add(tabbedPane, BorderLayout.CENTER);
    }

    private JPanel createMainPanel() {
        JPanel panel = new JPanel(new MigLayout("fill, insets 5", "[grow,fill]", "[][grow][]"));

        // Toolbar
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);
        toolbar.add(new JButton(new AbstractAction("Clear") {
            @Override
            public void actionPerformed(ActionEvent e) {
                tableModel.setRowCount(0);
            }
        }));
        toolbar.add(new JButton(new AbstractAction("Cancel") {
            @Override
            public void actionPerformed(ActionEvent e) {
                cancelCurrentRequest();
            }
        }));
        panel.add(toolbar, "dock north, wrap");

        // Filter
        panel.add(new JLabel("Filter:"));
        filterField = new JTextField(15);
        panel.add(filterField, "wrap");

        // Table
        tableModel = new DefaultTableModel(new String[]{"Prompt", "Response"}, 0);
        resultsTable = new JTable(tableModel);
        resultsTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object v, boolean s, boolean f, int r, int c) {
                Component comp = super.getTableCellRendererComponent(t, v, s, f, r, c);
                if (!s) comp.setBackground(r % 2 == 0 ? Color.WHITE : new Color(240, 240, 240));
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

        // Progress bar
        progressBar = new JProgressBar();
        progressBar.setStringPainted(true);
        progressBar.setString("Ready");
        panel.add(progressBar, "growx");

        return panel;
    }

    private JPanel createSettingsPanel() {
        JPanel panel = new JPanel(new MigLayout("fill, insets 5", "[][grow]", "[]10[]10[]"));

        // Server field
        panel.add(new JLabel("Server (IP:Port):"), "right");
        serverField = new JTextField("localhost:11434", 30);
        suffixLabel = new JLabel("/v1/chat/completions");
        suffixLabel.setEnabled(false);
        panel.add(serverField, "growx");
        panel.add(suffixLabel, "wrap");

        // Model field
        panel.add(new JLabel("Model Name:"), "right");
        modelField = new JTextField(modelName);
        panel.add(modelField, "growx, wrap");

        // Save button
        JButton save = new JButton("Save");
        save.addActionListener(e -> saveSettings());
        panel.add(save, "skip 1, split 2");

        // Test connection button
        JButton test = new JButton("Test Connection");
        test.addActionListener(e -> testConnection());
        panel.add(test, "wrap");

        return panel;
    }

    private JPanel createSendToLLMPanel() {
        JPanel llmPanel = new JPanel(new BorderLayout(5, 5));
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        split.setResizeWeight(0.5);

        // Prompt area
        promptArea = new JTextArea();
        promptArea.setLineWrap(true);
        promptArea.setWrapStyleWord(true);
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

        // Send button
        sendButton = new JButton("Send");
        sendButton.addActionListener(e -> sendPromptToLLM(promptArea.getText()));
        JPanel sendPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        sendPanel.add(sendButton);
        llmPanel.add(sendPanel, BorderLayout.SOUTH);

        return llmPanel;
    }

    @Override
    public java.util.List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] msgs = invocation.getSelectedMessages();
        if (msgs == null || msgs.length == 0) return Collections.emptyList();

        JMenu menu = new JMenu("Send to →");

        // Basic templates
        JMenuItem basic = new JMenuItem("Basic Analysis");
        basic.addActionListener(e -> runLLMWithTemplate("Basic Analysis", msgs[0]));
        menu.add(basic);

        JMenuItem sec = new JMenuItem("Security Review");
        sec.addActionListener(e -> runLLMWithTemplate("Security Review", msgs[0]));
        menu.add(sec);

        menu.addSeparator();

        // Pentest tools
        for (String key : pentestTemplates.keySet()) {
            JMenuItem item = new JMenuItem(key);
            item.addActionListener(e -> runPentesterTool(key, msgs[0]));
            menu.add(item);
        }

        return Arrays.asList(menu);
    }

    private void saveSettings() {
        String server = serverField.getText().trim();
        serverUrl = "http://" + server;
        modelName = modelField.getText().trim();

        callbacks.saveExtensionSetting("serverUrl", serverUrl);
        callbacks.saveExtensionSetting("modelName", modelName);

        JOptionPane.showMessageDialog(mainPanel, "Settings saved.", "Settings", JOptionPane.INFORMATION_MESSAGE);
    }

    private void testConnection() {
        String server = serverField.getText().trim();
        String model = modelField.getText().trim();
        String endpoint = "http://" + server + "/v1/chat/completions";

        progressBar.setIndeterminate(true);
        progressBar.setString("Testing connection...");

        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                JSONObject payload = new JSONObject();
                payload.put("model", model);
                JSONArray messages = new JSONArray();
                JSONObject message = new JSONObject();
                message.put("role", "user");
                message.put("content", "test");
                messages.put(message);
                payload.put("messages", messages);

                HttpURLConnection conn = (HttpURLConnection) new URL(endpoint).openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setDoOutput(true);
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);

                try (OutputStream os = conn.getOutputStream()) {
                    os.write(payload.toString().getBytes(StandardCharsets.UTF_8));
                }

                int status = conn.getResponseCode();
                conn.disconnect();

                if (status < 400) {
                    return "Connection successful! (HTTP " + status + ")";
                } else {
                    return "Connection failed with HTTP " + status;
                }
            }

            @Override
            protected void done() {
                progressBar.setIndeterminate(false);
                progressBar.setString("Ready");
                try {
                    String result = get();
                    JOptionPane.showMessageDialog(mainPanel, result, "Connection Test",
                        result.contains("successful") ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.WARNING_MESSAGE);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(mainPanel,
                        "Connection failed: " + ex.getMessage(),
                        "Connection Test",
                        JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    private void runLLMWithTemplate(String templateName, IHttpRequestResponse message) {
        callbacks.printOutput("▶️ runLLMWithTemplate(template=" + templateName + ")");
        String rawReq = helpers.bytesToString(message.getRequest());
        String template = templates.getOrDefault(templateName, "{{ request }}");
        String prompt = template.replace("{{ request }}", rawReq);
        sendPromptToLLM(prompt);
    }

    private void runPentesterTool(String toolName, IHttpRequestResponse message) {
        callbacks.printOutput("▶️ runPentesterTool(tool=" + toolName + ")");
        String rawReq = helpers.bytesToString(message.getRequest());

        // Extract headers safely
        String headers = rawReq;
        int bodyStart = rawReq.indexOf("\r\n\r\n");
        if (bodyStart != -1) {
            headers = rawReq.substring(0, bodyStart);
        }

        String template = pentestTemplates.getOrDefault(toolName, "{{ request }}");
        String prompt = template
            .replace("{{ request }}", rawReq)
            .replace("{{ headers }}", headers);

        sendPromptToLLM(prompt);
    }

    private void sendPromptToLLM(String promptText) {
        // Cancel any existing request
        cancelCurrentRequest();

        String host = serverField != null ? serverField.getText().trim() : "localhost:11434";
        String suffix = suffixLabel != null ? suffixLabel.getText() : "/v1/chat/completions";
        String targetEndpoint = "http://" + host + suffix;
        String model = modelField != null ? modelField.getText().trim() : modelName;

        callbacks.printOutput("▶️ sendPromptToLLM called. endpoint=" + targetEndpoint + " model=" + model);

        // Update UI state
        progressBar.setIndeterminate(true);
        progressBar.setString("Sending request to LLM...");
        sendButton.setEnabled(false);

        currentWorker = new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                // Build JSON payload
                JSONObject payload = new JSONObject();
                payload.put("model", model);
                JSONArray messages = new JSONArray();
                JSONObject message = new JSONObject();
                message.put("role", "user");
                message.put("content", promptText);
                messages.put(message);
                payload.put("messages", messages);
                String jsonBody = payload.toString();

                callbacks.printOutput("🔍 JSON payload: " + jsonBody);

                // HTTP POST with timeout
                HttpURLConnection conn = null;
                try {
                    URL url = new URL(targetEndpoint);
                    conn = (HttpURLConnection) url.openConnection();
                    conn.setRequestMethod("POST");
                    conn.setRequestProperty("Content-Type", "application/json");
                    conn.setDoOutput(true);
                    conn.setConnectTimeout(10000);  // 10 second connect timeout
                    conn.setReadTimeout(120000);     // 2 minute read timeout

                    try (OutputStream os = conn.getOutputStream()) {
                        os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
                    }

                    int status = conn.getResponseCode();
                    callbacks.printOutput("ℹ️ HTTP status: " + status);

                    InputStream in = status < 400 ? conn.getInputStream() : conn.getErrorStream();
                    String response = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                    callbacks.printOutput("✅ LLM raw response: " + response);

                    // Parse response
                    JSONObject root = new JSONObject(response);
                    JSONArray choices = root.optJSONArray("choices");
                    if (choices != null && choices.length() > 0) {
                        JSONObject choice = choices.getJSONObject(0).getJSONObject("message");
                        return choice.optString("content", "");
                    }

                    return "Error: Unexpected response format";
                } finally {
                    if (conn != null) conn.disconnect();
                }
            }

            @Override
            protected void done() {
                progressBar.setIndeterminate(false);
                progressBar.setString("Ready");
                sendButton.setEnabled(true);

                if (isCancelled()) {
                    callbacks.printOutput("⚠️ Request cancelled by user");
                    responseArea.setText("Request cancelled");
                    return;
                }

                try {
                    String finalResponse = get();
                    promptArea.setText(promptText);
                    responseArea.setText(finalResponse);
                    tableModel.addRow(new Object[]{promptText, finalResponse});
                    callbacks.printOutput("✅ Request completed successfully");
                } catch (java.util.concurrent.CancellationException e) {
                    callbacks.printOutput("⚠️ Request cancelled");
                    responseArea.setText("Request cancelled");
                } catch (java.net.SocketTimeoutException e) {
                    String errorMsg = "Timeout: LLM server did not respond in time";
                    callbacks.printError("❌ " + errorMsg);
                    responseArea.setText("Error: " + errorMsg);
                    tableModel.addRow(new Object[]{promptText, "Error: " + errorMsg});
                } catch (java.net.ConnectException e) {
                    String errorMsg = "Connection refused: Cannot connect to " + targetEndpoint;
                    callbacks.printError("❌ " + errorMsg);
                    responseArea.setText("Error: " + errorMsg);
                    tableModel.addRow(new Object[]{promptText, "Error: " + errorMsg});
                } catch (java.io.IOException e) {
                    String errorMsg = "Network error: " + e.getMessage();
                    callbacks.printError("❌ " + errorMsg);
                    responseArea.setText("Error: " + errorMsg);
                    tableModel.addRow(new Object[]{promptText, "Error: " + errorMsg});
                } catch (org.json.JSONException e) {
                    String errorMsg = "Invalid JSON response from LLM";
                    callbacks.printError("❌ " + errorMsg + ": " + e.getMessage());
                    responseArea.setText("Error: " + errorMsg);
                    tableModel.addRow(new Object[]{promptText, "Error: " + errorMsg});
                } catch (Exception e) {
                    String errorMsg = e.getClass().getSimpleName() + ": " + e.getMessage();
                    callbacks.printError("❌ sendPromptToLLM exception: " + errorMsg);
                    responseArea.setText("Error: " + errorMsg);
                    tableModel.addRow(new Object[]{promptText, "Error: " + errorMsg});
                }

                currentWorker = null;
            }
        };

        currentWorker.execute();
    }

    private void cancelCurrentRequest() {
        if (currentWorker != null && !currentWorker.isDone()) {
            callbacks.printOutput("⚠️ Cancelling current request...");
            currentWorker.cancel(true);
            currentWorker = null;
            progressBar.setIndeterminate(false);
            progressBar.setString("Cancelled");
        }
    }

    @Override
    public String getTabCaption() {
        return "SendToLLM";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
}

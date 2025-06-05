import burp.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.ExecutionException;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, ITab {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private JTextField urlField;
    private JTextField modelField;

    private Map<String, String> templates = new LinkedHashMap<>();
    private final Map<String, String> pentestTemplates = new LinkedHashMap<>() {{
        put("Header Analyzer", "Analyze these headers:\n{{ headers }}");
        put("Param Guess Helper", "Here is a request. Suggest hidden or interesting parameters to fuzz:\n{{ request }}");
        put("Vuln Suggestor", "Identify potential vulnerabilities in this HTTP request:\n{{ request }}");
        put("Payload Generator", "Generate a payload for possible XSS injection in this request:\n{{ request }}");
    }};

    private JComboBox<String> templateCombo;
    private JTextArea templateEditor;

    private DefaultTableModel historyModel;
    private JTable historyTable;
    private List<String> fullResponses = new ArrayList<>();
    private JTextArea detailArea;

    private IHttpRequestResponse lastSelectedMessage;

    private JPanel mainPanel;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Send to LLM Enhanced");

        templates.put("Basic Analysis", "Analyze the following HTTP request:\n{{ request }}");
        templates.put("Security Review", "You are a security auditor. Review this request and list any vulnerabilities:\n{{ request }}");

        buildUi();
        callbacks.registerContextMenuFactory(this);
        callbacks.addSuiteTab(this);
    }

    @Override
    public java.util.List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] msgs = invocation.getSelectedMessages();
        if (msgs == null || msgs.length == 0) return Collections.emptyList();

        IHttpRequestResponse message = msgs[0];
        lastSelectedMessage = message;

        JMenu mainMenu = new JMenu("Send to →");

        JMenuItem defaultItem = new JMenuItem("Analyze Request");
        defaultItem.addActionListener(e -> runLLMWithTemplate("Security Review", message));
        mainMenu.add(defaultItem);

        for (String key : pentestTemplates.keySet()) {
            JMenuItem item = new JMenuItem(key);
            item.addActionListener(e -> runPentesterTool(key, message));
            mainMenu.add(item);
        }

        return Collections.singletonList(mainMenu);
    }

    private void runLLMWithTemplate(String templateName, IHttpRequestResponse message) {
        String serverUrl = urlField.getText().trim();
        String modelName = modelField.getText().trim();
        String rawRequest = helpers.bytesToString(message.getRequest());

        String template = templates.getOrDefault(templateName, "{{ request }}");
        String prompt = template.replace("{{ request }}", rawRequest);
        sendPromptToLLM(prompt, serverUrl, modelName);
    }

    private void runPentesterTool(String toolName, IHttpRequestResponse message) {
        String serverUrl = urlField.getText().trim();
        String modelName = modelField.getText().trim();
        String rawRequest = helpers.bytesToString(message.getRequest());
        String headersOnly = rawRequest.split("\r\n\r\n")[0];

        String template = pentestTemplates.getOrDefault(toolName, "{{ request }}");
        String prompt = template.replace("{{ request }}", rawRequest).replace("{{ headers }}", headersOnly);
        sendPromptToLLM(prompt, serverUrl, modelName);
    }

    private void sendPromptToLLM(String prompt, String serverUrl, String modelName) {
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                String escaped = prompt.replace("\\", "\\\\")
                        .replace("\"", "\\\"")
                        .replace("\r", "\\r")
                        .replace("\n", "\\n");
                String payload = String.format(
                        "{\"model\":\"%s\",\"messages\":[{\"role\":\"user\",\"content\":\"%s\"}]}",
                        modelName, escaped
                );
                return httpPost(serverUrl, payload);
            }

            @Override
            protected void done() {
                try {
                    String fullJson = get();
                    String content = extractContent(fullJson);
                    int row = historyModel.getRowCount();
                    historyModel.addRow(new Object[]{System.currentTimeMillis(), prompt, content});
                    fullResponses.add(fullJson);
                    SwingUtilities.invokeLater(() -> {
                        Rectangle rect = historyTable.getCellRect(row, 0, true);
                        historyTable.scrollRectToVisible(rect);
                    });
                    showResponse(content);
                } catch (InterruptedException | ExecutionException ex) {
                    callbacks.issueAlert("[LLM] Error: " + ex.getMessage());
                }
            }
        }.execute();
    }

    private String extractContent(String json) {
        try {
            org.json.JSONObject root = new org.json.JSONObject(json);
            org.json.JSONArray choices = root.getJSONArray("choices");
            return choices.getJSONObject(0).getJSONObject("message").getString("content");
        } catch (Exception e) {
            return json;
        }
    }

    private String httpPost(String url, String payload) throws Exception {
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection)
                new java.net.URL(url).openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/json");
        byte[] out = payload.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        conn.setRequestProperty("Content-Length", String.valueOf(out.length));
        try (java.io.OutputStream os = conn.getOutputStream()) {
            os.write(out);
        }
        java.io.InputStream is = conn.getResponseCode() < 300 ? conn.getInputStream() : conn.getErrorStream();
        try (java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(is))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) sb.append(line).append("\n");
            return sb.toString();
        }
    }

    private void showResponse(String content) {
        SwingUtilities.invokeLater(() -> {
            JTextArea area = new JTextArea(content);
            area.setEditable(false);
            area.setLineWrap(true);
            area.setWrapStyleWord(true);
            JOptionPane.showMessageDialog(null, new JScrollPane(area), "LLM Response", JOptionPane.PLAIN_MESSAGE);
        });
    }

    @Override
    public String getTabCaption() {
        return "LLM Console";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    private void buildUi() {
        mainPanel = new JPanel(new BorderLayout());
        JTabbedPane tabs = new JTabbedPane();

        // ========== Config Tab ==========
        JPanel cfg = new JPanel(new BorderLayout(10, 10));
        cfg.setBorder(new EmptyBorder(10, 10, 10, 10));

        // Top input fields
        JPanel fields = new JPanel(new GridBagLayout());
        GridBagConstraints gc = new GridBagConstraints();
        gc.insets = new Insets(2, 2, 2, 2);
        gc.fill = GridBagConstraints.HORIZONTAL;

        gc.gridx = 0;
        gc.gridy = 0;
        fields.add(new JLabel("Server URL:"), gc);
        gc.gridx = 1;
        gc.weightx = 1.0;
        urlField = new JTextField("http://localhost:11434/v1/chat/completions");
        fields.add(urlField, gc);

        gc.gridx = 0;
        gc.gridy = 1;
        gc.weightx = 0;
        fields.add(new JLabel("Model:"), gc);
        gc.gridx = 1;
        gc.weightx = 1.0;
        modelField = new JTextField("llama3.2");
        fields.add(modelField, gc);

        cfg.add(fields, BorderLayout.NORTH);

        // Template list and editor
        JList<String> templateList = new JList<>(templates.keySet().toArray(new String[0]));
        templateEditor = new JTextArea(templates.values().iterator().next());
        templateEditor.setLineWrap(true);
        templateEditor.setWrapStyleWord(true);
        templateList.addListSelectionListener(e -> {
            String key = templateList.getSelectedValue();
            if (key != null) {
                templateEditor.setText(templates.get(key));
            }
        });

        JSplitPane templatePane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                new JScrollPane(templateList), new JScrollPane(templateEditor));
        templatePane.setResizeWeight(0.3);
        templatePane.setOneTouchExpandable(true);
        cfg.add(templatePane, BorderLayout.CENTER);

        JButton saveTemplate = new JButton("Save Template");
        saveTemplate.addActionListener(e -> {
            String sel = templateList.getSelectedValue();
            if (sel != null) {
                templates.put(sel, templateEditor.getText());
            }
        });
        cfg.add(saveTemplate, BorderLayout.SOUTH);

        // ========== History Tab ==========
        JPanel histPanel = new JPanel(new BorderLayout());
        historyModel = new DefaultTableModel(new Object[]{"Time", "Prompt", "Response"}, 0);
        historyTable = new JTable(historyModel);

        detailArea = new JTextArea();
        detailArea.setEditable(false);
        detailArea.setLineWrap(true);
        detailArea.setWrapStyleWord(true);
        JScrollPane detailScrollPane = new JScrollPane(detailArea);
        detailScrollPane.setPreferredSize(new Dimension(0, 150));

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(historyTable), detailScrollPane);
        splitPane.setResizeWeight(0.8);
        splitPane.setOneTouchExpandable(true);

        histPanel.add(splitPane, BorderLayout.CENTER);

        historyTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int idx = historyTable.getSelectedRow();
                if (idx >= 0 && idx < fullResponses.size()) {
                    String fullJson = fullResponses.get(idx);
                    detailArea.setText(extractContent(fullJson));
                }
            }
        });

        // ========== Pentester Tools Tab ==========
        JPanel pentestPanel = new JPanel(new BorderLayout(5, 5));
        JPanel controlPanel = new JPanel(new BorderLayout(5, 5));

        JComboBox<String> toolSelector = new JComboBox<>(pentestTemplates.keySet().toArray(new String[0]));
        JTextArea toolPromptEditor = new JTextArea(pentestTemplates.get(toolSelector.getItemAt(0)));
        toolPromptEditor.setLineWrap(true);
        toolPromptEditor.setWrapStyleWord(true);
        toolSelector.addActionListener(e -> toolPromptEditor.setText(pentestTemplates.get(toolSelector.getSelectedItem())));

        JButton sendButton = new JButton("Send to LLM");
        JTextArea toolResponseArea = new JTextArea();
        toolResponseArea.setEditable(false);

        JPanel selectorRow = new JPanel(new BorderLayout(5, 5));
        selectorRow.add(new JLabel("Select Tool:"), BorderLayout.WEST);
        selectorRow.add(toolSelector, BorderLayout.CENTER);
        controlPanel.add(selectorRow, BorderLayout.NORTH);
        controlPanel.add(new JScrollPane(toolPromptEditor), BorderLayout.CENTER);
        controlPanel.add(sendButton, BorderLayout.SOUTH);

        JSplitPane toolSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                controlPanel, new JScrollPane(toolResponseArea));
        toolSplit.setResizeWeight(0.5);
        toolSplit.setOneTouchExpandable(true);

        pentestPanel.add(toolSplit, BorderLayout.CENTER);

        sendButton.addActionListener(e -> {
            if (lastSelectedMessage == null) {
                callbacks.issueAlert("No previous request available. Right-click a request and use 'Send to →' first.");
                return;
            }

            String raw = helpers.bytesToString(lastSelectedMessage.getRequest());
            String headersOnly = raw.split("\r\n\r\n")[0];
            String template = pentestTemplates.get(toolSelector.getSelectedItem());
            String prompt = template.replace("{{ request }}", raw).replace("{{ headers }}", headersOnly);

            String serverUrl = urlField.getText().trim();
            String model = modelField.getText().trim();
            sendPromptToLLM(prompt, serverUrl, model);
        });

        // ========== Add All Tabs ==========
        tabs.addTab("Config", cfg);
        tabs.addTab("History", histPanel);
        tabs.addTab("Pentester Tools", pentestPanel);
        mainPanel.add(tabs, BorderLayout.CENTER);
    }
}

import sys
import os
from threading import Thread

from java.io import PrintWriter
from javax.swing import JButton, JPanel, JTextField, JLabel, JScrollPane, JTextPane, JSplitPane, \
                         BoxLayout, SwingConstants, SwingUtilities, BorderFactory, JCheckBox, JLabel, JTabbedPane
from javax.swing.border import EmptyBorder
from java.awt import BorderLayout, Font, Dimension, FlowLayout

# Manually specify the path to the modules directory
script_dir = '/home/kali/Desktop/Hacksclusive/DigiScan'
modules_dir = os.path.join(script_dir, 'modules')
sys.path.append(modules_dir)

from burp import IBurpExtender, ITab
import check_uwa05
import check_upw03
import check_upw05
import check_c09
import check_ports  # Assuming you'll create this module for network scans

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        print("Loading DigiScan...")
        self._callbacks = callbacks
        self._callbacks.setExtensionName('DigiScan')
        self._helpers = callbacks.getHelpers()
        self.initUI()
        callbacks.addSuiteTab(self)

    def initUI(self):
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._splitpane.setBorder(EmptyBorder(10, 10, 10, 10))

        titlePanel = JPanel()
        titlePanel.setLayout(BoxLayout(titlePanel, BoxLayout.Y_AXIS))
        titleLabel = JLabel("DigiScan")
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 18.0))
        creatorLabel = JLabel("by Rutger Harmers")
        creatorLabel.setFont(creatorLabel.getFont().deriveFont(Font.PLAIN, 14.0))
        titlePanel.add(titleLabel)
        titlePanel.add(creatorLabel)
        titlePanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 15, 0))

        setupPanel = JPanel(BorderLayout(5, 5))
        inputPanel = JPanel(BorderLayout(10, 0))
        inputPanel.add(JLabel("Target URL:"), BorderLayout.WEST)
        self.hostField = JTextField(30)
        inputPanel.add(self.hostField, BorderLayout.CENTER)

        normsPanel = JPanel(FlowLayout(FlowLayout.LEADING, 5, 5))
        self.selectAll = JCheckBox("Select All", actionPerformed=self.selectAllNorms)
        self.checkboxUWA05 = JCheckBox("U/WA.05")
        self.checkboxUPW03 = JCheckBox("U/PW.03")
        self.checkboxUPW05 = JCheckBox("U/PW.05")
        self.checkboxUC09 = JCheckBox("C.09")
        self.checkboxNetworkScan = JCheckBox("Network Scan")
        normsPanel.add(self.selectAll)
        normsPanel.add(self.checkboxUWA05)
        normsPanel.add(self.checkboxUPW03)
        normsPanel.add(self.checkboxUPW05)
        normsPanel.add(self.checkboxUC09)
        normsPanel.add(self.checkboxNetworkScan)

        inputAndNormsPanel = JPanel(BorderLayout())
        inputAndNormsPanel.add(inputPanel, BorderLayout.NORTH)
        inputAndNormsPanel.add(normsPanel, BorderLayout.CENTER)

        self.startButton = JButton('Start Scan', actionPerformed=self.startScan)
        self.startButton.setPreferredSize(Dimension(120, 30))
        setupPanel.add(inputAndNormsPanel, BorderLayout.CENTER)
        setupPanel.add(self.startButton, BorderLayout.EAST)

        self.statusBar = JLabel("Status: Ready to scan")
        self.statusBar.setHorizontalAlignment(SwingConstants.LEFT)

        controlPanel = JPanel(BorderLayout())
        controlPanel.add(titlePanel, BorderLayout.NORTH)
        controlPanel.add(setupPanel, BorderLayout.CENTER)
        controlPanel.add(self.statusBar, BorderLayout.SOUTH)

        self._splitpane.setTopComponent(controlPanel)

        self.resultTabs = JTabbedPane()
        self._splitpane.setBottomComponent(self.resultTabs)

        self.networkScanResults = JTextPane()
        self.networkScanResults.setContentType("text/html")
        self.networkScanResults.setEditable(False)
        self.networkScrollPane = JScrollPane(self.networkScanResults)

    def toggleNetworkScanTab(self, event):
        if self.checkboxNetworkScan.isSelected():
            self.resultTabs.addTab("Network Scan Results", self.networkScrollPane)
        else:
            self.resultTabs.remove(self.networkScrollPane)

    def selectAllNorms(self, event):
        is_selected = self.selectAll.isSelected()
        self.checkboxUWA05.setSelected(is_selected)
        self.checkboxUPW03.setSelected(is_selected)
        self.checkboxUPW05.setSelected(is_selected)
        self.checkboxUC09.setSelected(is_selected)
        self.checkboxNetworkScan.setSelected(is_selected)
        self.toggleNetworkScanTab(None)

    def startScan(self, event):
        host = self.hostField.getText().strip()
        if not host:
            self.statusBar.setText("Status: Please enter a valid URL to scan.")
            return

        # Clear all existing tabs at the beginning of a new scan
        self.resultTabs.removeAll()

        norms_to_check = [chk.getText() for chk in [self.checkboxUWA05, self.checkboxUPW03, self.checkboxUPW05, self.checkboxUC09, self.checkboxNetworkScan] if chk.isSelected()]
        if not norms_to_check:
            self.statusBar.setText("Status: Please select at least one norm to check.")
            return

        self.statusBar.setText("Status: Scanning...")
        scan_thread = Thread(target=self.runScan, args=(host, norms_to_check))
        scan_thread.start()

        # Add the network scan tab only if selected and start scanning
        if self.checkboxNetworkScan.isSelected():
            self.resultTabs.addTab("Port Scan", self.networkScrollPane)

    def runScan(self, host, norms_to_check):
        try:
            results = {}

            if 'U/WA.05' in norms_to_check:
                json_output_path = check_uwa05.run_testssl(host)
                if json_output_path:
                    results['U/WA.05'] = check_uwa05.filter_keys(json_output_path)
                    SwingUtilities.invokeLater(lambda: self.updateUI('U/WA.05', results['U/WA.05']))

            if 'U/PW.03' in norms_to_check:
                json_output_path = check_upw03.run_testssl(host)
                if json_output_path:
                    results['U/PW.03'] = check_upw03.filter_keys(json_output_path)
                    SwingUtilities.invokeLater(lambda: self.updateUI('U/PW.03', results['U/PW.03']))

                ffuf_output = check_upw03.run_ffuf_scan(host)
                if ffuf_output:
                    ffuf_results = check_upw03.parse_ffuf_output(ffuf_output)
                    if ffuf_results:
                        if 'U/PW.03' in results:
                            results['U/PW.03'].extend(ffuf_results)
                        else:
                            results['U/PW.03'] = ffuf_results
                        SwingUtilities.invokeLater(lambda: self.updateUI('U/PW.03', results['U/PW.03']))

            if 'U/PW.05' in norms_to_check:
                http_methods_results = check_upw05.run_http_method_checks(host)
                if http_methods_results:
                    results['U/PW.05'] = http_methods_results
                    SwingUtilities.invokeLater(lambda: self.updateUI('U/PW.05', results['U/PW.05']))

            if 'C.09' in norms_to_check:
                server_info_results = check_c09.run_server_check(host)
                if server_info_results:
                    results['C.09'] = server_info_results
                    SwingUtilities.invokeLater(lambda: self.updateUI('C.09', results['C.09']))

            if 'Network Scan' in norms_to_check:
                network_thread = Thread(target=self.runNetworkScan, args=(host,))
                network_thread.start()

        except Exception as e:
            SwingUtilities.invokeLater(lambda: self.showError("An error occurred: " + str(e)))

    def runNetworkScan(self, host):
        result = check_ports.run_network_scan(host)
        SwingUtilities.invokeLater(lambda: self.updateNetworkScanResults(result))

    def updateNetworkScanResults(self, result):
        if self.networkScanResults:
            self.networkScanResults.setText(self.formatResults(result))
            self.resultTabs.setSelectedComponent(self.networkScrollPane)
            self.statusBar.setText("Network Scan completed.")

    def updateUI(self, norm, data):
        if norm == "Network Scan":
            return

        tab_exists = False
        tab_index = -1
        for i in range(self.resultTabs.getTabCount()):
            if self.resultTabs.getTitleAt(i) == norm:
                tab_exists = True
                tab_index = i
                break

        if tab_exists and tab_index != -1:
            panel = self.resultTabs.getComponentAt(tab_index)
            if isinstance(panel, JScrollPane):
                text_pane = panel.getViewport().getView()
                if isinstance(text_pane, JTextPane):
                    text_pane.setText(self.formatResults(data))
        else:
            panel = JTextPane()
            panel.setContentType("text/html")
            panel.setText(self.formatResults(data))
            panel.setEditable(False)
            scrollPane = JScrollPane(panel)
            self.resultTabs.addTab(norm, scrollPane)

    def updateNetworkScanResults(self, result):
        if result:  
            self.networkScanResults.setText(result)
            self.networkScanResults.revalidate()  
        else:
            self.networkScanResults.setText("No results or scan failed.")
            self.statusBar.setText("Failed to complete network scan.")

    def formatResults(self, data):
        html_content = "<html><body>"
        if isinstance(data, list):
            for result in data:
                if "header" in result:
                    html_content += "<h3 style='margin-bottom: 0px;'>{}</h3>".format(result["header"])
                icon = '&#9989;' if result.get('status') == 'pass' else '&#9888;' if result.get('status') == 'warning' else '&#10060;'
                additional_info = '<br>Found: {}'.format(result.get('found')) if 'found' in result else ''
                html_content += "<p style='margin-bottom: 5px;'><span style='color: {}; font-weight: bold;'>{} </span>{}{}<br><i>Advice: {}<br></i></p>".format(
                    'green' if result.get('status') == 'pass' else 'orange' if result.get('status') == 'warning' else 'red', 
                    icon, result.get('description', 'No description provided'), additional_info, result.get('advice', 'No specific advice available.'))
        elif isinstance(data, dict) and "error" in data:
            html_content += "<p style='color: red;'>{}</p>".format(data["error"])
        html_content += "</body></html>"
        return html_content

    def showError(self, error_message):
        import traceback
        tb = traceback.format_exc()  # This captures the entire traceback.
        detailed_error = "Error: {}\nDetails: {}".format(error_message, tb)
        self.statusBar.setText(detailed_error)

    def getTabCaption(self):
        return "DigiScan"

    def getUiComponent(self):
        return self._splitpane

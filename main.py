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

        # Debug: Check if JTextPane is correctly added to the UI
        if self.networkScanResults.getParent() is None:
            print("networkScanResults JTextPane is not properly added to the UI.")
        else:
            print("networkScanResults JTextPane is properly integrated in the UI.")

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

                # Perform and handle FFUF scan
                ffuf_output = check_upw03.run_ffuf_scan(host)  # Ensure this is defined here
                if ffuf_output:
                    ffuf_results = check_upw03.parse_ffuf_output(ffuf_output)
                    if ffuf_results:
                        for result in ffuf_results:
                            result['type'] = 'ffuf'  # Mark as ffuf result
                        if 'U/PW.03' in results:
                            results['U/PW.03'].extend(ffuf_results)  # Combine with existing results
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
                json_output_path = check_ports.run_network_scan(host)
                if json_output_path:
                    network_results = check_ports.parse_nmap_json(json_output_path)
                    if network_results:
                        results['Network Scan'] = network_results
                        SwingUtilities.invokeLater(lambda: self.updateUI('Network Scan', results['Network Scan']))

        except Exception as e:
            SwingUtilities.invokeLater(lambda: self.showError("An error occurred: " + str(e)))

    def runNetworkScan(self, host):
        try:
            for result in check_ports.run_network_scan(host):
                if result:
                    # Ensure that the current result is correctly captured by the lambda
                    SwingUtilities.invokeLater(lambda r=result: self.updateNetworkScanResults(r))
        except Exception as e:
            print("Network scan failed with exception:", e)
            SwingUtilities.invokeLater(lambda: self.showError("An error occurred in network scanning: " + str(e)))

    def updateUI(self, norm, data, is_ffuf=False):
        text_pane = None

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
        else:
            new_text_pane = JTextPane()
            new_text_pane.setContentType("text/html")
            new_text_pane.setText(self.formatResults(data, is_ffuf))
            new_text_pane.setEditable(False)
            scrollPane = JScrollPane(new_text_pane)
            self.resultTabs.addTab(norm, scrollPane)
            text_pane = new_text_pane

        if text_pane is not None:
            formatted_data = self.formatResults(data, is_ffuf)
            def update_text_pane():
                text_pane.setText(formatted_data)
                text_pane.setCaretPosition(0)
            SwingUtilities.invokeLater(update_text_pane)
        else:
            print("Error: Text pane not found or initialized for norm:", norm)

    def updateNetworkScanResults(self, result):
        if result:
            # Initialize an attribute to accumulate results if it doesn't already exist
            if not hasattr(self, 'network_scan_accumulator'):
                self.network_scan_accumulator = ''

            # Append new result to the accumulator
            self.network_scan_accumulator += result

            # Check if the accumulated results are enough to update the JTextPane (e.g., update every 100 characters or when a certain condition is met)
            if len(self.network_scan_accumulator) > 100 or "\n" in result:  # You can adjust the condition based on your specific needs
                formatted_result = "<html><body><p>{}</p></body></html>".format(self.network_scan_accumulator)
                self.networkScanResults.setText(formatted_result)
                self.networkScanResults.revalidate()
                self.network_scan_accumulator = ''  # Reset accumulator after update

    def formatResults(self, data, is_ffuf=False):
        html_content = "<html><head><style>body {font-family: Arial, sans-serif;} .pass {color: green;} .warning {color: orange;} .fail {color: red;} .title {font-weight: bold; margin-top: 20px;}</style></head><body>"

        def format_individual_result(result):
            icon = '&#9888;' if result.get('status') == 'warning' else '&#9989;' if result.get('status') == 'pass' else '&#10060;'
            span_class = 'warning' if result.get('status') == 'warning' else 'pass' if result.get('status') == 'pass' else 'fail'
            return "<p><span class='{0}'>{1}</span> {2} <br><i>Advice: {3}</i></p>".format(
                span_class, icon, result['description'], result.get('advice', 'No specific advice available.'))
        
        # Start by adding non-ffuf results
        if not is_ffuf:
            for result in data:
                if 'ffuf' not in result.get('type', ''):
                    html_content += format_individual_result(result)
        
        # Add ffuf title and results if present
        if any('ffuf' in result.get('type', '') for result in data):
            html_content += "<div class='title'>Fuzzing Results:</div>"
            for result in data:
                if 'ffuf' in result.get('type', ''):
                    html_content += format_individual_result(result)
        
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

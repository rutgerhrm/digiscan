import sys
import os
import threading
import time
from threading import Thread, Lock

from java.io import PrintWriter
from javax.swing import JButton, JPanel, JTextField, JLabel, JScrollPane, JTextPane, JSplitPane, \
                         BoxLayout, SwingConstants, SwingUtilities, BorderFactory, JCheckBox, JLabel, JTabbedPane
from javax.swing.border import EmptyBorder
from java.awt import BorderLayout, Font, Dimension, FlowLayout

from urlparse import urlparse

# Manually specify the path to the modules directory
script_dir = '/home/kali/Desktop/Hacksclusive/DigiScan'
modules_dir = os.path.join(script_dir, 'modules')
sys.path.append(modules_dir)

from burp import IBurpExtender, ITab
import check_uwa05, check_upw03, check_upw05, check_c09, check_ports  

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
        self.checkboxNetworkScan = JCheckBox("Port Scan")
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
        self.active_scans = 0
        self.lock = Lock()
        self.file_ready_event = threading.Event()

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

    def selectAllNorms(self, event):
        is_selected = self.selectAll.isSelected()
        self.checkboxUWA05.setSelected(is_selected)
        self.checkboxUPW03.setSelected(is_selected)
        self.checkboxUPW05.setSelected(is_selected)
        self.checkboxUC09.setSelected(is_selected)
        self.checkboxNetworkScan.setSelected(is_selected)

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
        with self.lock:
            self.active_scans = len(norms_to_check)

        # Reset the flag
        self.ui_updated = False

        # Start each selected norm in a separate thread
        for norm in norms_to_check:
            if norm == "Port Scan":
                Thread(target=self.runPortScan, args=(host,)).start()
            else:
                Thread(target=self.runScan, args=(host, [norm])).start()

    def runPortScan(self, host):
        # Initial UI update to indicate scanning in progress
        SwingUtilities.invokeLater(lambda: self.updateUI('Port Scan', "Port scanning in progress..."))

        try:
            print("Starting port scan for host:", host)
            tcp_json_output_path, udp_json_output_path = check_ports.run_network_scan(host)

            tcp_results = check_ports.parse_nmap_json(tcp_json_output_path, "TCP") if tcp_json_output_path else []
            udp_results = check_ports.parse_nmap_json(udp_json_output_path, "UDP") if udp_json_output_path else []

            # Prepare results directly here to reduce function calls
            combined_results = [{'header': 'TCP Scan Results', 'type': 'title'}]
            if tcp_results:
                combined_results.extend(tcp_results)
            else:
                combined_results.append({'description': 'No open TCP ports found.', 'status': 'info', 'advice': ''})

            combined_results.append({'header': 'UDP Scan Results', 'type': 'title'})
            if udp_results:
                combined_results.extend(udp_results)
            else:
                combined_results.append({'description': 'No open UDP ports found.', 'status': 'info', 'advice': ''})

            print("Combined Results after adding:", combined_results)

            # Single point for updating UI with final results
            SwingUtilities.invokeLater(lambda: self.updateUI('Port Scan', combined_results))

        except Exception as e:
            print("Exception during port scan: {}".format(str(e)))
            SwingUtilities.invokeLater(lambda: self.showError("Port Scan error: " + str(e)))
        finally:
            self.decrementActiveScans()

    def runScan(self, host, norms_to_check):
        try:
            results = {}
            # Define the path for the testssl output file
            parsed_url = urlparse(host)
            safe_filename = parsed_url.netloc.replace(":", "_").replace("/", "_")
            json_filename = "testssl_output_{}.json".format(safe_filename)
            output_dir = "/home/kali/Desktop/Hacksclusive/DigiScan/output"
            json_file_path = os.path.join(output_dir, json_filename)

            run_testssl = False
            json_output_path = None

            if 'U/WA.05' in norms_to_check:
                run_testssl = True
                self.file_ready_event.clear()
                if not os.path.exists(json_file_path):
                    json_output_path = check_uwa05.run_testssl(host, self.lock, json_file_path)
                    self.file_ready_event.set()  # Signal that the file is ready
                else:
                    json_output_path = json_file_path
                    self.file_ready_event.set()  # Signal that the file is ready
                if json_output_path:
                    results['U/WA.05'] = check_uwa05.filter_keys(json_output_path)
                    SwingUtilities.invokeLater(lambda: self.updateUI('U/WA.05', results['U/WA.05']))

            if 'U/PW.03' in norms_to_check:
                if 'U/WA.05' not in norms_to_check:
                    run_testssl = True  # Ensure testssl runs if U/WA.05 is not selected
                else:
                    self.file_ready_event.wait()  # Wait until the file is created by U/WA.05
                if run_testssl:
                    if not os.path.exists(json_file_path):
                        json_output_path = check_upw03.run_testssl(host, self.lock, json_file_path)
                    else:
                        json_output_path = json_file_path

                if json_output_path:
                    results['U/PW.03'] = check_upw03.filter_keys(json_output_path)
                    SwingUtilities.invokeLater(lambda: self.updateUI('U/PW.03', results['U/PW.03']))

                # Perform and handle FFUF scan
                ffuf_output = check_upw03.run_ffuf_scan(host)
                if ffuf_output:
                    ffuf_results = check_upw03.parse_ffuf_output(ffuf_output)
                    if ffuf_results:
                        for result in ffuf_results:
                            result['type'] = 'ffuf'
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

        except Exception as e:
            SwingUtilities.invokeLater(lambda: self.showError("An error occurred: " + str(e)))
        finally:
            self.decrementActiveScans()

    def decrementActiveScans(self):
        with self.lock:
            self.active_scans -= 1
            if self.active_scans == 0:
                SwingUtilities.invokeLater(lambda: self.statusBar.setText("Status: Scanning completed"))

    def updateUI(self, norm, data):
        text_pane = None
        # Find if the tab for this norm already exists
        tab_index = next((i for i in range(self.resultTabs.getTabCount()) if self.resultTabs.getTitleAt(i) == norm), -1)

        if tab_index != -1:
            # Tab exists, get its content
            panel = self.resultTabs.getComponentAt(tab_index)
            if isinstance(panel, JScrollPane):
                text_pane = panel.getViewport().getView()
        else:
            # Create new tab for this norm
            text_pane = JTextPane()
            text_pane.setContentType("text/html")
            text_pane.setEditable(False)
            scrollPane = JScrollPane(text_pane)
            self.resultTabs.addTab(norm, scrollPane)

        if text_pane is not None:
            # Check if data is a string or results list
            if isinstance(data, str):
                formatted_data = "<html><body><p style='font-family: Arial;'>{}</p></body></html>".format(data)
            else:
                formatted_data = self.formatResults(data)

            def update_text_pane():
                text_pane.setText(formatted_data)  # Set the new content
                text_pane.setCaretPosition(0)

            SwingUtilities.invokeLater(update_text_pane)

    def formatResults(self, data):
        html_content = "<html><head><style>body {font-family: Arial, sans-serif;} .pass {color: green;} .warning {color: orange;} .fail {color: red;} .title {font-weight: bold; margin-top: 20px;}</style></head><body>"

        def format_individual_result(result):
            if result.get('type') == 'title':
                return "<div class='title'>{0}</div>".format(result['header'])
            
            icon = '&#9888;' if result.get('status') == 'warning' else '&#9989;' if result.get('status') == 'pass' else '&#10060;'
            span_class = 'warning' if result.get('status') == 'warning' else 'pass' if result.get('status') == 'pass' else 'fail'
            description = result.get('description', 'No description available.')
            advice = result.get('advice', 'No specific advice available.')
            found = result.get('found', '')

            # Include the found field if it is present
            found_text = "<br><b>Found:</b> {}".format(found) if found else ''

            return "<p><span class='{0}'>{1}</span> {2} <br><i>Advice: {3}</i>{4}</p>".format(
                span_class, icon, description, advice, found_text)

        # Process non-ffuf results
        non_ffuf_results = [r for r in data if 'ffuf' not in r.get('type', '')]
        for result in non_ffuf_results:
            html_content += format_individual_result(result)

        # Check and add ffuf results
        ffuf_results = [r for r in data if 'ffuf' in r.get('type', '')]
        if ffuf_results:
            html_content += "<div class='title'>Fuzzing Results:</div>"
            for result in ffuf_results:
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

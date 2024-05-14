import sys
import os

# Manually specify the path to the modules directory
script_dir = '/home/kali/Desktop/Hacksclusive/DigiScan'
modules_dir = os.path.join(script_dir, 'modules')
sys.path.append(modules_dir)

from burp import IBurpExtender, ITab
from java.io import PrintWriter
from javax.swing import (JButton, JPanel, JTextField, JLabel, JScrollPane, JTextPane, JSplitPane,
                         BoxLayout, SwingConstants, SwingUtilities, BorderFactory, JCheckBox, JLabel, JTabbedPane)
from javax.swing.border import EmptyBorder
from java.awt import BorderLayout, Font, Dimension, FlowLayout
import time
from threading import Thread
import check_uwa05
import check_upw03
import check_upw05
import check_c09

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
        normsPanel.add(self.selectAll)
        normsPanel.add(self.checkboxUWA05)
        normsPanel.add(self.checkboxUPW03)
        normsPanel.add(self.checkboxUPW05)
        normsPanel.add(self.checkboxUC09)

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

        # Initialize the JTabbedPane for displaying results
        self.resultTabs = JTabbedPane()
        self._splitpane.setBottomComponent(self.resultTabs)


    def selectAllNorms(self, event):
        is_selected = self.selectAll.isSelected()
        self.checkboxUWA05.setSelected(is_selected)
        self.checkboxUPW03.setSelected(is_selected)
        self.checkboxUPW05.setSelected(is_selected)
        self.checkboxUC09.setSelected(is_selected)

    def startScan(self, event):
        host = self.hostField.getText()
        if not host.strip():
            self.statusBar.setText("Status: Please enter a valid URL to scan.")
            return

        norms_to_check = [chk.getText() for chk in [self.checkboxUWA05, self.checkboxUPW03, self.checkboxUPW05, self.checkboxUC09] if chk.isSelected()]
        if not norms_to_check:
            self.statusBar.setText("Status: Please select at least one norm to check.")
            return

        self.statusBar.setText("Status: Scanning...")
        scan_thread = Thread(target=self.runScan, args=(host, norms_to_check))
        scan_thread.start()

    def runScan(self, host, norms_to_check):
        try:
            results = {}
            json_output_path = None

            if 'U/WA.05' in norms_to_check:
                json_output_path = check_uwa05.run_testssl(host)
                if json_output_path:
                    results['U/WA.05'] = check_uwa05.filter_keys(json_output_path)

            if 'U/PW.03' in norms_to_check:
                if not json_output_path:
                    json_output_path = check_upw03.run_testssl(host)
                if json_output_path:
                    results['U/PW.03'] = check_upw03.filter_keys(json_output_path)
                ffuf_output = check_upw03.run_ffuf_scan(host)
                if ffuf_output:
                    ffuf_results = check_upw03.parse_ffuf_output(ffuf_output)
                    if ffuf_results:
                        results['U/PW.03'].append({"header": "Fuzzing Results"})
                        results['U/PW.03'].extend(ffuf_results)
            
            if 'U/PW.05' in norms_to_check:
                http_methods_results = check_upw05.run_http_method_checks(host)
                if http_methods_results:
                    results['U/PW.05'] = http_methods_results  

            if 'C.09' in norms_to_check:
                server_info_results = check_c09.run_server_check(host)
                if server_info_results:
                    results['C.09 Server Info'] = server_info_results           

            SwingUtilities.invokeLater(lambda: self.updateUI(results))
        except Exception as e:
            error_message = "<html><body>An error occurred: {}</body></html>".format(str(e))
            SwingUtilities.invokeLater(lambda: self.showError(error_message))

    def updateUI(self, results):
        self.resultTabs.removeAll()  # Clear existing tabs if any
        for norm, data in results.items():
            panel = JTextPane()
            panel.setContentType("text/html")
            panel.setText(self.formatResults(data))  # Use one formatting function for all checks
            panel.setEditable(False)
            scrollPane = JScrollPane(panel)
            self.resultTabs.addTab(norm, scrollPane)
        self.statusBar.setText("Status: Scanning completed.")

    def formatResults(self, data):
        html_content = "<html><body>"
        for result in data:
            if isinstance(result, dict) and "header" in result:
                html_content += "<h3 style='margin-bottom: 0px;'>{}</h3>".format(result["header"])
            else:
                icon = '&#9989;' if result.get('status') == 'pass' else '&#9888;' if result.get('status') == 'warning' else '&#10060;'
                additional_info = '<br>Found: {}'.format(result.get('found')) if 'found' in result else ''
                html_content += "<p style='margin-bottom: 5px;'><span style='color: {}; font-weight: bold;'>{} </span>{}{}<br><i>Advice: {}<br></i></p>".format(
                    'green' if result.get('status') == 'pass' else 'orange' if result.get('status') == 'warning' else 'red', 
                    icon, result.get('description', 'No description provided'), additional_info, result.get('advice', 'No specific advice available.'))
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

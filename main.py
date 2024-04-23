import sys
import os

# Manually specify the path to the modules directory
script_dir = '/home/kali/Desktop/Hacksclusive/DigiScan'
modules_dir = os.path.join(script_dir, 'modules')
sys.path.append(modules_dir)

from burp import IBurpExtender, ITab
from java.io import PrintWriter
from javax.swing import (JButton, JPanel, JTextField, JLabel, JScrollPane, JTextPane, JSplitPane,
                         BoxLayout, SwingConstants, SwingUtilities, BorderFactory, JCheckBox)
from javax.swing.border import EmptyBorder
from java.awt import BorderLayout, Font, Dimension, FlowLayout
from threading import Thread

# Import your custom module
import check_uwa05

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

        self.resultTextPane = JTextPane()
        self.resultTextPane.setContentType("text/html")
        self.resultTextPane.setEditable(False)
        self.resultScrollPane = JScrollPane(self.resultTextPane)
        self._splitpane.setBottomComponent(self.resultScrollPane)

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
            self.resultTextPane.setText("<html><body>Please enter a valid URL to scan.</body></html>")
            return
        
        norms_to_check = [chk.getText() for chk in [self.checkboxUWA05, self.checkboxUPW03, self.checkboxUPW05, self.checkboxUC09] if chk.isSelected()]
        if not norms_to_check:
            self.statusBar.setText("Status: Please select at least one norm to check.")
            self.resultTextPane.setText("<html><body>Please select at least one norm to check.</body></html>")
            return

        self.statusBar.setText("Status: Scanning...")
        self.resultTextPane.setText("<html><body>Scanning in progress...</body></html>")
        scan_thread = Thread(target=self.runScan, args=(host, norms_to_check))
        scan_thread.start()

    def runScan(self, host, norms_to_check):
        try:
            results = {}
            if 'U/WA.05' in norms_to_check:
                json_output = check_uwa05.run_testssl(host)
                if json_output:
                    results['U/WA.05'] = check_uwa05.filter_keys(json_output)

            display_html = "<html><body>"
            for norm, data in results.items():
                display_html += "<h3>Results for {norm}</h3>".format(norm=norm)
                display_html += "<ul>"
                for key, value in data.items():
                    display_html += "<li>{key}: {value}</li>".format(key=key, value=value)
                display_html += "</ul>"
            display_html += "</body></html>"

            # Update UI in a thread-safe way
            SwingUtilities.invokeLater(Runnable(lambda: self.updateUI(display_html)))
        except Exception as e:
            error_message = "<html><body>An error occurred: {e}</body></html>".format(e=str(e))
            SwingUtilities.invokeLater(Runnable(lambda: self.showError(error_message)))

    def updateUI(self, display_html):
        self.resultTextPane.setText(display_html)
        self.statusBar.setText("Status: Scanning completed.")

    def showError(self, error_message):
        self.resultTextPane.setText(error_message)
        self.statusBar.setText("Status: An error occurred.")

    def getTabCaption(self):
        return "DigiScan"

    def getUiComponent(self):
        return self._splitpane

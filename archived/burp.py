from burp import (IBurpExtender, IScannerCheck, IExtensionStateListener, ITab, IMessageEditor,
                  IContextMenuFactory, IContextMenuInvocation, IHttpRequestResponse)
from java.io import PrintWriter, File, FileWriter
from java.lang import Runnable
from javax.swing import (JTable, JScrollPane, JSplitPane, JButton, JPanel, JTextField, JLabel,
                         SwingConstants, JDialog, Box, JCheckBox, JMenuItem, SwingUtilities,
                         JOptionPane, BoxLayout, JPopupMenu, JFileChooser, JTextPane)
from javax.swing.border import EmptyBorder
from javax.swing.table import AbstractTableModel
from java.awt import (GridLayout, BorderLayout, FlowLayout, Dimension, Point)
from java.net import URL, MalformedURLException
from java.util import ArrayList
from threading import Thread, Event
import sys
import os
import socket
import time
import json
import subprocess

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        print "Loading..."

        self._callbacks = callbacks
        self._callbacks.setExtensionName('DigiD-scanner')
        self._helpers = callbacks.getHelpers()

        # Initialize UI components
        self.initUI()

        callbacks.customizeUiComponent(self._splitpane)
        callbacks.addSuiteTab(self)

    def initUI(self):
        # Main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._splitpane.setBorder(EmptyBorder(20, 20, 20, 20))

        # Top panel
        self._topPanel = JPanel(BorderLayout(10, 10))
        self._topPanel.setBorder(EmptyBorder(0, 0, 10, 0))

        # Initialize resultTextPane
        self.resultTextPane = JTextPane()
        self.resultTextScrollPane = JScrollPane(self.resultTextPane)
        self.resultTextPane.setContentType("text/html")
        self.resultTextPane.setEditable(False)

        # Setup panel: [Target: ] [______________________] [START BUTTON]
        self.setupPanel = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
        self.setupPanel.add(
            JLabel("Target:", SwingConstants.LEFT), BorderLayout.LINE_START)
        self.hostField = JTextField('', 50)
        self.setupPanel.add(self.hostField)
        self.toggleButton = JButton(
            'Start scanning', actionPerformed=self.startScan)
        self.setupPanel.add(self.toggleButton)
        self._topPanel.add(self.setupPanel, BorderLayout.PAGE_START)

        # Status bar
        self.scanStatusPanel = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
        self.scanStatusPanel.add(JLabel("Status: ", SwingConstants.LEFT))
        self.scanStatusLabel = JLabel("Ready to scan", SwingConstants.LEFT)
        self.scanStatusPanel.add(self.scanStatusLabel)
        self._topPanel.add(self.scanStatusPanel, BorderLayout.LINE_START)
        self._splitpane.setTopComponent(self._topPanel)

        # Bottom panel
        self._bottomPanel = JPanel(BorderLayout(10, 10))
        self._bottomPanel.setBorder(EmptyBorder(10, 0, 0, 0))

        # Initialize resultTextPane with HTML content
        self.resultTextPane = JTextPane()
        self.resultTextScrollPane = JScrollPane(self.resultTextPane)
        self.resultTextPane.setContentType("text/html")
        self.resultTextPane.setEditable(False)
        
        # Add title and subtitle as HTML content
        title_and_subtitle = ('<h1 style="color: red;">DigiD-Scanner<br />'
                               'by Rutger Harmers</h1>')
        self.resultTextPane.setText(title_and_subtitle)
        self._bottomPanel.add(self.resultTextScrollPane, BorderLayout.CENTER)
        self.savePanel = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
        self.saveButton = JButton('Save to file', actionPerformed=self.saveToFile)
        self.saveButton.setEnabled(False)
        self.savePanel.add(self.saveButton)
        self._bottomPanel.add(self.savePanel, BorderLayout.PAGE_END)
        self._splitpane.setBottomComponent(self._bottomPanel)

    def startScan(self, ev):
        host = self.hostField.getText()
        if not host:
            self.scanStatusLabel.setText("Please enter a target URL.")
            return
        self.scanStatusLabel.setText("Scanning...")
        # Add your scanning logic here
        scan_thread = self.ScanThread(host, self._callbacks, self._helpers, self.scanStatusLabel, self.resultTextPane, self.saveButton)
        scan_thread.start()

    class ScanThread(Thread):
        def __init__(self, host, callbacks, helpers, scanStatusLabel, resultTextPane, saveButton):
            self.host = host
            self.callbacks = callbacks
            self.helpers = helpers
            self.scanStatusLabel = scanStatusLabel
            self.resultTextPane = resultTextPane
            self.saveButton = saveButton
            Thread.__init__(self)

        def run(self):
            try:
                parsed_url = URL(self.host)
                host = parsed_url.getHost()
                httpService = self.helpers.buildHttpService(host, 443, "https")
                response = self.callbacks.makeHttpRequest(httpService, self.helpers.buildHttpRequest(parsed_url))
                headers = self.helpers.analyzeResponse(response.getResponse()).getHeaders()
                
                # Check for HTTP headers in the responses
                filtered_headers = []
                for header in headers:
                    if header.lower().startswith("x-frame-options") or \
                       header.lower().startswith("strict-transport-security") or \
                       header.lower().startswith("x-content-type-options") or \
                       header.lower().startswith("referrer-policy") or \
                       header.lower().startswith("content-security-policy"):
                        filtered_headers.append(header)
                
                # Check for HttpOnly and Secure flags
                httpOnly_secure_flags = []
                for header in headers:
                    if header.lower().startswith("set-cookie"):
                        if "httponly" in header.lower() and "secure" in header.lower():
                            httpOnly_secure_flags.append(header)
                if httpOnly_secure_flags:
                    filtered_headers.extend(httpOnly_secure_flags)
                
                if filtered_headers:
                    self.resultTextPane.setText("<html><body><h2>HTTP Headers:</h2><ul>" + "".join("<li>" + header + "</li>" for header in filtered_headers) + "</ul></body></html>")
                    self.scanStatusLabel.setText("Scanning completed.")
                    self.saveButton.setEnabled(True)
                else:
                    self.resultTextPane.setText("No relevant headers found in the response.")
            except MalformedURLException as e:
                self.resultTextPane.setText("Malformed URL: " + str(e))
            except Exception as e:
                self.resultTextPane.setText("An error occurred: " + str(e))

    def saveToFile(self, event):
        # Add logic to save results to a file
        pass

    def getTabCaption(self):
        return "DigiD-Scanner"

    def getUiComponent(self):
        return self._splitpane
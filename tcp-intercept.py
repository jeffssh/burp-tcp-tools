# Decode the value of Authorization: Basic header
# Author: Jake Miller (@LaconicWolf)

from burp import IBurpExtender, ITab               # Required for all extensions
from burp import IMessageEditorTab           # Used to create custom tabs within the Burp HTTP message editors
from burp import IMessageEditorController
from burp import IExtensionStateListener
from javax import swing
from javax.swing import JTextField
from javax.swing import JLabel
from java.awt import BorderLayout
from java.awt import Color
import base64                                # Required to decode Base64 encoded header value
import sys                                   # Used to write exceptions for exceptions_fix.py debugging
import pprint
import socket
import threading
import Queue
import tcpmitm

try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass


class BurpExtender(IBurpExtender, ITab, IMessageEditorController, IExtensionStateListener):
    debug = False


    def registerExtenderCallbacks(self, callbacks):
        self.TcpMitm = None
        self.mainMessageQueue = Queue.Queue()
        self.currentMessage = None
        self.currentMessageLock = threading.Lock()
        
        # required for debugger: https://github.com/securityMB/burp-exceptions
        sys.stdout = callbacks.getStdout()

        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        # This method is used to obtain an IExtensionHelpers object, which can be used by the extension to perform numerous useful tasks
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("TCP Tools")

        callbacks.registerExtensionStateListener(self)
        # create a new tab and register it
        self.tab = swing.JPanel(BorderLayout())
        topTabPane = swing.JTabbedPane()
        interceptTab = swing.JTabbedPane()
        
        topTabPane.add("Proxy", interceptTab)
        self.tab.add("Center", topTabPane)
        
        interceptTab.addTab("Intercept", self.buildInterceptTab())
        #interceptTab.addTab("History", self.buildHistoryTab())
        interceptTab.addTab("Options", self.buildOptionsTab())

        callbacks.addSuiteTab(self)
        return
        

    def getTabCaption(self):
        return "TCP Tools"

    def getUiComponent(self):
        return self.tab

    def buildInterceptTab(self):
        tab = swing.JPanel(BorderLayout())
        
        panel = swing.JPanel(BorderLayout())
        northPanel = swing.JPanel(BorderLayout())
        northWestPanel = swing.JPanel()
        
        # build top left buttons Forward, Drop, and Intercept is off/on
        northWestPanel.add(swing.JButton('Forward', actionPerformed=self.forwardMessage))
        northWestPanel.add(swing.JButton('Drop', actionPerformed=self.dropMessage))
        self.interceptButton = swing.JButton('Intercept is off', actionPerformed=self.toggleIntercept)
        self.interceptButton.setOpaque(True)
        self.interceptButton.setBorderPainted(False)
        self.intercept = False
        self.interceptButtonColor = self.interceptButton.getBackground()
        northWestPanel.add(self.interceptButton)
        northPanel.add(northWestPanel, BorderLayout.WEST)
        panel.add(northPanel, BorderLayout.NORTH)

        # build message editor
        self.requestViewer = self._callbacks.createMessageEditor(self, True)
        #self.requestViewer.setMessage(b"howdy!", True)
        panel.add(self.requestViewer.getComponent())

        tab.add(panel)
        return tab

    def buildHistoryTab(self):
        tab = swing.JPanel(BorderLayout())
        return tab
    
    def buildOptionsTab(self):
        tab = swing.JPanel()
    
        lHostLabel = JLabel("lHost:")
        self.lHostTextField = JTextField()
        self.lHostTextField.setText("127.0.0.1")
        tab.add(lHostLabel)
        tab.add(self.lHostTextField)

        lPortLabel = JLabel("lPort:")
        self.lPortTextField = JTextField()
        self.lPortTextField.setText("1337")
        tab.add(lPortLabel)
        tab.add(self.lPortTextField)

        rHostLabel = JLabel("rHost:")
        self.rHostTextField = JTextField()
        self.rHostTextField.setText("127.0.0.1")
        tab.add(rHostLabel)
        tab.add(self.rHostTextField)

        rPortLabel = JLabel("rPort:")
        self.rPortTextField = JTextField()
        self.rPortTextField.setText("1338")
        tab.add(rPortLabel)
        tab.add(self.rPortTextField)
        
        bufSizeLabel = JLabel("bufSize:")
        self.bufSizeTextField = JTextField()
        self.bufSizeTextField.setText("4096")
        tab.add(bufSizeLabel)
        tab.add(self.bufSizeTextField)
        
        
        tab.add(swing.JButton('Update proxy settings', actionPerformed=self.updateProxySettings))
        tab.add(swing.JButton('Stop proxy', actionPerformed=self.stopProxy))
        return tab

    def setCurrentInterceptMessage(self):
        # requires you to hold lock before calling
        m = ""
        if self.currentMessage:
            m = self.currentMessage.message
        print("setCurrentInterceptMessage to:")
        print(m)
        self.requestViewer.setMessage(m, True)


    def toggleIntercept(self, event):
        if self.intercept:
            self.interceptButton.setText('Intercept is off')
            self.interceptButton.setBackground(self.interceptButtonColor)
            # dump intercept queue
            self.currentMessageLock.acquire()
            if self.currentMessage:
                self.currentMessage.message = self.requestViewer.getMessage().tostring()
                self.currentMessage.send()
            self.currentMessage = None
            try:
                while True:
                    ms = self.mainMessageQueue.get(False)
                    ms.send()
            except Queue.Empty:
                pass


            self.setCurrentInterceptMessage()
            self.currentMessageLock.release()
        else:
            self.interceptButton.setText('Intercept is on')
            self.interceptButton.setBackground(Color.RED)

        self.intercept = not self.intercept
        print("intercept:")
        print(self.intercept)

    def dropMessage(self, event):
        self.currentMessageLock.acquire()
        try:
            self.currentMessage = self.mainMessageQueue.get(False)
        except Queue.Empty:
            self.currentMessage = None

        self.setCurrentInterceptMessage()           
        self.currentMessageLock.release()

    def forwardMessage(self, event):
        self.currentMessageLock.acquire()
        if self.currentMessage:
            self.currentMessage.message = self.requestViewer.getMessage().tostring()
            print("updated currentMessage.message to:")
            print(self.currentMessage.message)
            self.currentMessage.send()

        try:
            self.currentMessage = self.mainMessageQueue.get(False)
        except Queue.Empty:
            self.currentMessage = None

        self.setCurrentInterceptMessage()   
        self.currentMessageLock.release()

    def getAndDisplayFromQueue(self):
        self.currentMessageLock.acquire()
        self.currentMessage = self.mainMessageQueue.get()
        self.setCurrentInterceptMessage()
        self.currentMessageLock.release()        

    def addToQueue(self, sm):
        print("in add to queue")
        self.mainMessageQueue.put(sm)
        self.currentMessageLock.acquire()
        print("in critical section of add to queue")
        if not self.currentMessage:
            self.currentMessage = self.mainMessageQueue.get()
            self.setCurrentInterceptMessage()          
        self.currentMessageLock.release()   

        print("in displayandmodify")
        if not self.intercept: return
        print("in display and modify, setting message")
        self.currentMessageLock.acquire()
        self.setCurrentInterceptMessage()
        self.currentMessageLock.release()

    def stopProxy(self, event):
        if self.TcpMitm: self.TcpMitm.stop()

    def updateProxySettings(self, event):
        lHost = self.lHostTextField.getText()
        lPort = self.lPortTextField.getText()
        rHost = self.rHostTextField.getText()
        rPort = self.rPortTextField.getText()
        bufSize = self.bufSizeTextField.getText()
        try:
		    lPort = int(lPort, 0)
		    rPort = int(rPort, 0)
		    bufSize = int(bufSize, 0)

    	except ValueError:
            return

        if self.TcpMitm: self.TcpMitm.stop()
        self.TcpMitm = tcpmitm.TcpMitm(self, lHost, lPort, rHost, rPort, bufSize)
        if self.TcpMitm: self.TcpMitm.start()

    def testButton(self, event):
        print("hi from testbutton")
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(event)
        print(event.keys)

    def extensionUnloaded(self):
        self.stopProxy(None)

    def getHttpService():
        return None

    def getRequest():
        return None

    def getResponse():
        return None



try:
    FixBurpExceptions()
except:
    pass

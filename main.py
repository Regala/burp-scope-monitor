# -*- coding: utf-8 -*- 
from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from burp import IContextMenuFactory
from burp import IExtensionStateListener
from burp import IScannerCheck
from java.net import URL
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import LinkedList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import JFrame;
from javax.swing import JFileChooser;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from javax.swing.table import DefaultTableCellRenderer;
from javax.swing.table import DefaultTableModel;
from javax.swing.table import TableColumn;
from javax.swing.table import TableColumnModel;
from threading import Lock

###
from java.awt import Color
from java.awt.event import MouseAdapter
from javax.swing import JMenuItem
from javax.swing import JPopupMenu
from javax.swing import ListSelectionModel
from java.awt.event import ActionListener
#from java.awt.event import ListSelectionListener
from java.awt import BorderLayout
from java.awt import GridLayout
from javax.swing import JTextArea
from javax.swing import ButtonGroup
from javax.swing import JRadioButton
from javax.swing import JLabel
from javax.swing import JButton
from javax.swing import JComboBox
from javax.swing import JCheckBox
from javax.swing import JPanel
from javax.swing import SortOrder
from java.lang import Runnable
from javax.swing import RowFilter
from java.awt.event import ItemListener
from javax.swing.table import TableRowSorter


from java.awt import EventQueue

from urlparse import *
import datetime 
import time
import sched

RED_COLOR = Color(255,135,135) 
GREEN_COLOR = Color(107,255,127)

SHOW_ALL_BUTTON_LABEL = "Show All"
SHOW_NEW_BUTTON_LABEL = "Show New Only"
SHOW_TEST_BUTTON_LABEL = "Show Tested Only"

MONITOR_ON_LABEL = "Monitor is ON"
MONITOR_OFF_LABEL = "Monitor is OFF"

SCOPE_MONITOR_COMMENT = "scope-monitor-placeholder"

class Run(Runnable):
    def __init__(self, runner):
        self.runner = runner

    def run(self):
        self.runner()

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel, IContextMenuFactory, IExtensionStateListener):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Burp Scope Monitor Experimental")

        self.GLOBAL_HANDLER_ANALYZED = False
        self.GLOBAL_HANDLER = False
        self.STATUS = False
        self.AUTOSAVE_REQUESTS = 10
        self.AUTOSAVE_TIMEOUT  = 600 # 10 minutes should be fine
        self.CONFIG_INSCOPE    = True

        self.BAD_EXTENSIONS_DEFAULT = ['.gif', '.png', '.js', '.woff', '.woff2', '.jpeg', '.jpg', '.css', '.ico', '.m3u8', '.ts', '.svg']
        self.BAD_MIMES_DEFAULT      = ['gif', 'script', 'jpeg', 'jpg', 'png', 'video', 'mp2t']
        
        self.BAD_EXTENSIONS = self.BAD_EXTENSIONS_DEFAULT
        self.BAD_MIMES      = self.BAD_MIMES_DEFAULT

        # create the log and a lock on which to synchronize when adding log entries

        self._currentlyDisplayedItem = None

        self.SELECTED_MODEL_ROW = 0
        self.SELECTED_VIEW_ROW = 0

        self._log = ArrayList()
        self._fullLog = ArrayList()
        self._lock = Lock()
        self._lockFile = Lock()
        
        # main split pane
        self._parentPane = JTabbedPane()

        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        ##### config pane
        self._config = JTabbedPane()

        config = JPanel()
        iexport = JPanel()

        #config.setLayout(BorderLayout())
        config.setLayout(None)
        iexport.setLayout(None)
        
        # config radio button
        X_BASE = 40
        Y_OFFSET = 5
        Y_OPTION = 200
        Y_OPTION_SPACING = 20
        Y_CHECKMARK_SPACING = 20


        self.showAllButton = JRadioButton(SHOW_ALL_BUTTON_LABEL, True)
        self.showNewButton = JRadioButton(SHOW_NEW_BUTTON_LABEL, False)
        self.showTestedButton = JRadioButton(SHOW_TEST_BUTTON_LABEL, False)

        self.showAllButton.setBounds(40, 60 + Y_OFFSET, 400, 30)
        self.showNewButton.setBounds(40, 80 + Y_OFFSET, 400, 30)
        self.showTestedButton.setBounds(40, 100 + Y_OFFSET, 400, 30)
        #self.showNewButton = JRadioButton(SHOW_NEW_BUTTON_LABEL, False)
        #self.showTestedButton = JRadioButton(SHOW_TEST_BUTTON_LABEL, False)

        self.showAllButton.addActionListener(self.handleRadioConfig)
        self.showNewButton.addActionListener(self.handleRadioConfig)
        self.showTestedButton.addActionListener(self.handleRadioConfig) 

        self.clearButton = JButton("Clear")
        self.clearButton.addActionListener(self.handleClearButton)
        self.clearButton.setBounds(40, 20, 100, 30)

        self.startButton = JButton(MONITOR_ON_LABEL)
        self.startButton.addActionListener(self.handleStartButton)
        self.startButton.setBounds(150, 20, 200, 30)

        self.badExtensionsLabel = JLabel("Ignore extensions:")
        self.badExtensionsLabel.setBounds(X_BASE, 150, 200, 30)

        self.badExtensionsText = JTextArea("")
        self.loadBadExtensions()        
        self.badExtensionsText.setBounds(X_BASE, 175, 310, 30)

        self.badExtensionsButton = JButton("Save")
        self.badExtensionsButton.addActionListener(self.handleBadExtensionsButton)
        self.badExtensionsButton.setBounds(355, 175, 70, 30)

        self.badExtensionsDefaultButton = JButton("Load Defaults")
        self.badExtensionsDefaultButton.addActionListener(self.handleBadExtensionsDefaultButton)
        self.badExtensionsDefaultButton.setBounds(430, 175, 120, 30)

        self.badMimesLabel = JLabel("Ignore mime types:")
        self.badMimesLabel.setBounds(X_BASE, 220, 200, 30)

        self.badMimesText = JTextArea("")
        self.loadBadMimes() 
        self.badMimesText.setBounds(X_BASE, 245, 310, 30)

        self.badMimesButton = JButton("Save")
        self.badMimesButton.addActionListener(self.handleBadMimesButton)
        self.badMimesButton.setBounds(355, 245, 70, 30)

        self.badMimesDefaultButton = JButton("Load Defaults")
        self.badMimesDefaultButton.addActionListener(self.handleBadMimesDefaultButton)
        self.badMimesDefaultButton.setBounds(430, 245, 120, 30)


        self.otherLabel = JLabel("Other:")
        self.otherLabel.setBounds(40, 300, 120, 30)

        self.otherLabel2 = JLabel("Other:")
        self.otherLabel2.setBounds(X_BASE, Y_OPTION, 120, 30)

        self.autoSaveOption = JCheckBox("Auto save periodically")
        self.autoSaveOption.setSelected(True)
        self.autoSaveOption.addActionListener(self.handleAutoSaveOption)
        self.autoSaveOption.setBounds(X_BASE, Y_OPTION + Y_CHECKMARK_SPACING, 420, 30)

        self.repeaterOptionButton = JCheckBox("Repeater request automatically marks as analyzed")
        self.repeaterOptionButton.setSelected(True)
        self.repeaterOptionButton.addActionListener(self.handleRepeaterOptionButton)
        self.repeaterOptionButton.setBounds(50, 330, 420, 30)

        self.scopeOptionButton = JCheckBox("Follow Burp Target In Scope rules")
        self.scopeOptionButton.setSelected(True)
        self.scopeOptionButton.addActionListener(self.handleScopeOptionButton)
        self.scopeOptionButton.setBounds(50, 350, 420, 30)

        self.startOptionButton = JCheckBox("Autostart Scope Monitor")
        self.startOptionButton.setSelected(True)
        self.startOptionButton.addActionListener(self.handleStartOption)
        self.startOptionButton.setBounds(50, 350 + Y_OPTION_SPACING, 420, 30)

        self.markTestedRequestsProxy = JCheckBox("Color request in Proxy tab if analyzed")
        self.markTestedRequestsProxy.setSelected(True)
        self.markTestedRequestsProxy.addActionListener(self.handleTestedRequestsProxy)
        self.markTestedRequestsProxy.setBounds(50, 350 + Y_OPTION_SPACING*2, 420, 30)

        self.markNotTestedRequestsProxy = JCheckBox("Color request in Proxy tab if NOT analyzed")
        self.markNotTestedRequestsProxy.setSelected(True)
        self.markNotTestedRequestsProxy.addActionListener(self.handleNotTestedRequestsProxy)
        self.markNotTestedRequestsProxy.setBounds(50, 350 + Y_OPTION_SPACING*3, 420, 30)


        self.saveButton = JButton("Save now")
        self.saveButton.addActionListener(self.handleSaveButton)
        self.saveButton.setBounds(X_BASE + 320, 95, 90, 30)

        self.loadButton = JButton("Load now")
        self.loadButton.addActionListener(self.handleLoadButton)
        self.loadButton.setBounds(X_BASE + 420, 95, 90, 30)

        self.selectPath = JButton("Select path")
        self.selectPath.addActionListener(self.selectExportFile)
        self.selectPath.setBounds(X_BASE + 530, 60, 120, 30)

        self.selectPathText = JTextArea("")
        self.selectPathText.setBounds(X_BASE, 60, 510, 30)

        self.selectPathLabel = JLabel("State file:")
        self.selectPathLabel.setBounds(X_BASE, 30, 200, 30)

        bGroup = ButtonGroup()

        bGroup.add(self.showAllButton)
        bGroup.add(self.showNewButton)
        bGroup.add(self.showTestedButton)

        config.add(self.clearButton)
        config.add(self.startButton)
        config.add(self.startOptionButton)
        config.add(self.showAllButton)
        config.add(self.showNewButton)
        config.add(self.showTestedButton)

        config.add(self.badExtensionsButton)
        config.add(self.badExtensionsText)
        config.add(self.badExtensionsLabel)

        config.add(self.badMimesButton)
        config.add(self.badMimesText)
        config.add(self.badMimesLabel)

        config.add(self.badExtensionsDefaultButton)
        config.add(self.badMimesDefaultButton)

        config.add(self.otherLabel)
        config.add(self.repeaterOptionButton)
        config.add(self.scopeOptionButton)
        config.add(self.markTestedRequestsProxy)
        config.add(self.markNotTestedRequestsProxy)

        iexport.add(self.saveButton)
        iexport.add(self.loadButton)
        iexport.add(self.selectPath)
        iexport.add(self.selectPathText)
        iexport.add(self.selectPathLabel)
        iexport.add(self.otherLabel2)
        iexport.add(self.autoSaveOption)


        self._config.addTab("General", config)
        self._config.addTab("Import/Export", iexport)

        ##### end config pane


        self._parentPane.addTab("Monitor", self._splitpane)
        self._parentPane.addTab("Config", self._config)
        
        # table of log entries
        self.logTable = Table(self)

        #self.logTable.setDefaultRenderer(self.logTable.getColumnClass(0), ColoredTableCellRenderer(self))

        self.logTable.setAutoCreateRowSorter(True)
        self.logTable.setRowSelectionAllowed(True)

        renderer = ColoredTableCellRenderer(self)
        #column = TableColumn(0, 190, renderer, None)

        print 'Initiating... '

        # this could be improved by fetching initial dimensions
        self.logTable.getColumn("URL").setPreferredWidth(720) # noscope
        self.logTable.getColumn("URL").setResizable(True)

        self.logTable.getColumn("Checked").setCellRenderer(renderer)
        self.logTable.getColumn("Checked").setPreferredWidth(80)
        self.logTable.getColumn("Checked").setMaxWidth(80)

        self.logTable.getColumn("Method").setPreferredWidth(120)
        #self.logTable.getColumn("Method").setMaxWidth(120)
        self.logTable.getColumn("Method").setResizable(True)

        self.logTable.getColumn("Time").setPreferredWidth(120) # noscope
        self.logTable.getColumn("Time").setResizable(True)


        scrollPane = JScrollPane(self.logTable)
        self._splitpane.setLeftComponent(scrollPane)

        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)

        ## Row sorter shit 

        #self._tableRowSorterAutoProxyAutoAction = CustomTableRowSorter(self.logTable.getModel())
        #self.logTable.setRowSorter(self._tableRowSorterAutoProxyAutoAction)
        

        markAnalyzedButton = JMenuItem("Mark Requests as Analyzed")
        markAnalyzedButton.addActionListener(markRequestsHandler(self, True))

        markNotAnalyzedButton = JMenuItem("Mark Requests as NOT Analyzed")
        markNotAnalyzedButton.addActionListener(markRequestsHandler(self, False))

        sendRequestMenu = JMenuItem("Send Request to Repeater")
        sendRequestMenu.addActionListener(sendRequestRepeater(self))

        deleteRequestMenu = JMenuItem("Delete request")
        deleteRequestMenu.addActionListener(deleteRequestHandler(self))

        self.menu = JPopupMenu("Popup")
        self.menu.add(markAnalyzedButton)
        self.menu.add(markNotAnalyzedButton)
        self.menu.add(sendRequestMenu)
        self.menu.add(deleteRequestMenu)

        # customize our UI components
        callbacks.customizeUiComponent(self._parentPane)
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(self._config)
        callbacks.customizeUiComponent(config)
        callbacks.customizeUiComponent(self.logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)

        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)
        # callbacks.registerScannerCheck(passiveScanner(self))
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)

        self.loadConfigs()

        print "Loaded!"

        print "Experimental import state.. "
        self.importState("")

        self.SC = sched.scheduler(time.time, time.sleep)
        self.SCC = self.SC.enter(10, 1, self.autoSave, (self.SC,))
        self.SC.run()

        return
        
    ##### CUSTOM CODE #####
    def loadConfigs(self):

        if self._callbacks.loadExtensionSetting("CONFIG_AUTOSTART") == "False":
            self.startOptionButton.setSelected(False)
            self.startOrStop(None, False)
        else:
            self.startOptionButton.setSelected(True)
            self.startOrStop(None, True)

        if self._callbacks.loadExtensionSetting("exportFile") != "":
            self.selectPathText.setText(self._callbacks.loadExtensionSetting("exportFile"))

        if self._callbacks.loadExtensionSetting("CONFIG_REPEATER") == "True":
            self.repeaterOptionButton.setSelected(True)
        else:
            self.repeaterOptionButton.setSelected(False)

        if self._callbacks.loadExtensionSetting("CONFIG_INSCOPE") == "True":
            self.scopeOptionButton.setSelected(True)
        else:
            self.scopeOptionButton.setSelected(False)

        if self._callbacks.loadExtensionSetting("CONFIG_AUTOSAVE") == "True":
            self.autoSaveOption.setSelected(True)
        else:
            self.autoSaveOption.setSelected(False)
        
        if self._callbacks.loadExtensionSetting("CONFIG_HIGHLIGHT_TESTED") == "True":
            self.markTestedRequestsProxy.setSelected(True)
        else:
            self.markTestedRequestsProxy.setSelected(False)

        if self._callbacks.loadExtensionSetting("CONFIG_HIGHLIGHT_NOT_TESTED") == "True":
            self.markNotTestedRequestsProxy.setSelected(True)
        else:
            self.markNotTestedRequestsProxy.setSelected(False)





        return

    def selectExportFile(self, event):
        parentFrame = JFrame()
        fileChooser = JFileChooser()
        fileChooser.setDialogTitle("Specify file to save state")
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY)

        userSelection = fileChooser.showOpenDialog(parentFrame)

        if (userSelection == JFileChooser.APPROVE_OPTION):
            fileLoad = fileChooser.getSelectedFile()
            filename = fileLoad.getAbsolutePath()

            self.selectPathText.setText(filename)
            print 'Filename selected:' + filename
            self._callbacks.saveExtensionSetting("exportFile", filename)

        return


    def extensionUnloaded(self):
        print 'extension unloading.. '

        print 'canceling scheduler.. '
        map(self.SC.cancel, self.SC.queue)
        return

    def loadBadExtensions(self):
        bad = self._callbacks.loadExtensionSetting("badExtensions")
        if bad:
            self.badExtensionsText.setText(bad)
            # transform text to array 
            bad = bad.replace(" ", "")
            self.BAD_EXTENSIONS = bad.split(",")
        else:
            print 'no bad extension saved, reverting'
            self.badExtensionsText.setText(", ".join(self.BAD_EXTENSIONS))

    def loadBadMimes(self):
        bad = self._callbacks.loadExtensionSetting("badMimes")
        if bad:
            self.badMimesText.setText(bad)

            bad = bad.replace(" ", "")
            self.BAD_MIMES = bad.split(",")
        else:
            print 'no bad mimes saved, reverting'
            self.badMimesText.setText(", ".join(self.BAD_MIMES))



        

    ## GLOBAL CONTEXT CODE ##

    def createMenuItems(self, invocation):
        responses = invocation.getSelectedMessages()
        if responses > 0:
            ret = LinkedList()
            analyzedMenuItem = JMenuItem("Mark as analyzed")
            notAnalyzedMenuItem = JMenuItem("Mark as NOT analyzed")

            for response in responses:
                analyzedMenuItem.addActionListener(handleMenuItems(self,response, "analyzed"))
                notAnalyzedMenuItem.addActionListener(handleMenuItems(self, response, "not"))   
            ret.add(analyzedMenuItem)
            ret.add(notAnalyzedMenuItem)
            return ret


    def getEndpoint(self, requestResponse):
        url_ = str(self._helpers.analyzeRequest(requestResponse).getUrl())
        o = urlparse(url_)

        url = o.scheme+"://"+o.netloc+o.path
        #print "Url3: " + url
        return url


    def getMethod(self, requestResponse):
        return self._helpers.analyzeRequest(requestResponse).getMethod()


    ##### CUSTOM CODE #####
    def handleTestedRequestsProxy(self, event):
        self._callbacks.saveExtensionSetting("CONFIG_HIGHLIGHT_TESTED", str(self.markTestedRequestsProxy.isSelected()))
        return

    def handleNotTestedRequestsProxy(self, event):
        self._callbacks.saveExtensionSetting("CONFIG_HIGHLIGHT_NOT_TESTED", str(self.markNotTestedRequestsProxy.isSelected()))
        return



    def handleStartOption(self, event):
        self._callbacks.saveExtensionSetting("CONFIG_AUTOSTART", str(self.startOptionButton.isSelected()))
        #print 'saving autostart: ' + str(self.startOptionButton.isSelected())
        return

    def startOrStop(self, event, autoStart):
        if (self.startButton.getText() == MONITOR_OFF_LABEL) or autoStart:
            self.startButton.setText(MONITOR_ON_LABEL)
            self.startButton.setBackground(GREEN_COLOR)
            self.STATUS = True
        else:
            self.startButton.setText(MONITOR_OFF_LABEL)
            self.startButton.setBackground(RED_COLOR)
            self.STATUS = False

    def handleStartButton(self, event):
        self.startOrStop(event, False)

    def handleAutoSaveOption(self, event):
        self._callbacks.saveExtensionSetting("CONFIG_AUTOSAVE", str(self.autoSaveOption.isSelected()))
        return

    def handleSaveButton(self, event):
        self.exportState("")

    def handleLoadButton(self, event):
        self.importState("")

    def handleRepeaterOptionButton(self, event):
        self._callbacks.saveExtensionSetting("CONFIG_REPEATER", str(self.repeaterOptionButton.isSelected()))
        return

    def handleScopeOptionButton(self, event):
        self.CONFIG_INSCOPE = self.scopeOptionButton.isSelected()
        self._callbacks.saveExtensionSetting("CONFIG_INSCOPE", str(self.CONFIG_INSCOPE))
        return 

    def handleBadExtensionsButton(self, event):
        #print "before BAD array: "
        print self.BAD_EXTENSIONS

        extensions = self.badExtensionsText.getText()
        self._callbacks.saveExtensionSetting("badExtensions", extensions)
        print 'New extensions blocked: ' + extensions 
        bad = extensions.replace(" ", "")
        self.BAD_EXTENSIONS = bad.split(",")
        #print "BAD array: "
        #print self.BAD_EXTENSIONS

    def handleBadExtensionsDefaultButton(self, event):
        self.BAD_EXTENSIONS = self.BAD_EXTENSIONS_DEFAULT
        self.badExtensionsText.setText(", ".join(self.BAD_EXTENSIONS))
        self._callbacks.saveExtensionSetting("badExtensions", ", ".join(self.BAD_EXTENSIONS))
        return

    def handleBadMimesDefaultButton(self, event):
        self.BAD_MIMES = self.BAD_MIMES_DEFAULT
        self.badMimesText.setText(", ".join(self.BAD_MIMES))
        self._callbacks.saveExtensionSetting("badExtensions", ", ".join(self.BAD_MIMES))
        return

    def handleBadMimesButton(self, event):
        mimes = self.badMimesText.getText()
        self._callbacks.saveExtensionSetting("badMimes", mimes)
        print 'New mimes blocked: ' + mimes 
        bad = mimes.replace(" ", "")
        self.BAD_MIMES = bad.split(",")

    def handleClearButton(self, event):
        print 'Clearing table'
        self._lock.acquire()
        self._log = ArrayList()
        self._fullLog = ArrayList()
        self._lock.release()
        return

    def handleRadioConfig(self, event):
        #print ' radio button clicked '
        #print event.getActionCommand()
        self._lock.acquire()

        if event.getActionCommand() == SHOW_ALL_BUTTON_LABEL:
            print "Showing all"
            self._log = self._fullLog
        elif event.getActionCommand() == SHOW_NEW_BUTTON_LABEL:
            print "Showing new scope only"
            tmpLog = ArrayList()
            for item in self._fullLog:
                if not(item._analyzed):
                    tmpLog.add(item)
            self._log = tmpLog
        elif event.getActionCommand() == SHOW_TEST_BUTTON_LABEL:
            print "Showing tested scope only"
            tmpLog = ArrayList()
            for item in self._fullLog:
                if item._analyzed:
                    tmpLog.add(item)
            self._log = tmpLog
        else:
            print "unrecognized radio label"

        
        self.fireTableDataChanged()
        #self._tableRowSorterAutoProxyAutoAction.toggleSortOrder(1)
        #self.toggleSortOrder(2)
        
        #self.logTable.toggleSortOrder(2)

        # refresh table?

        self._lock.release()


    #
    # implement ITab
    #
    
    def getTabCaption(self):
        return "Scope Monitor"
    
    def getUiComponent(self):
        return self._parentPane
        
    #
    # implement IHttpListener
    #
    
    def markAnalyzed(self, messageIsRequest, state):
        #print "markAnalyzed..."
        self._lock.acquire()

        method = self.getMethod(messageIsRequest)
        url = self.getEndpoint(messageIsRequest)
        #这里有bug,应该同时比较method
        for item in self._log:
            if url == item._url and method==self._helpers.analyzeRequest(item._requestResponse).getMethod():
                item._analyzed = state
                self._lock.release()
                return
        self._lock.release()
        return

    # 不能把右键和代理混在一起，不然来源于porxy的非右键流量会覆盖item，存在逻辑错误
    # 完美调试通过了
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only process requests

        #print "processing httpMessage.."
        #print messageIsRequest

        # print "processHttpMessage toolFlag: " + str(toolFlag)
        #print " -- " + str(self._callbacks.getToolName(toolFlag)) + " -- "

        if not(self.STATUS):
            return

        #print "global handler status: (true): " + str(self.GLOBAL_HANDLER)
        #print "(processHTTP) messageIsRequest"
        #print messageIsRequest 
        if messageIsRequest and not(self.GLOBAL_HANDLER):
            # print "1.5 processHttpMessage droping message"
            return

        if self.scopeOptionButton.isSelected():
            url = self._helpers.analyzeRequest(messageInfo).getUrl()
            if not self._callbacks.isInScope(url):
                #print 'Url not in scope, skipping.. '
                return

        url = self.getEndpoint(messageInfo)
        method = self.getMethod(messageInfo)

        #print "(processHTTP) before extensions check: " + url 

        for extension in self.BAD_EXTENSIONS:
            if url.endswith(extension):
                return

        if messageInfo.getResponse():
            mime = self._helpers.analyzeResponse(messageInfo.getResponse()).getStatedMimeType()
            #print 'Declared mime:' + mime
            mime = mime.lower()
            if mime in self.BAD_MIMES:
                #print 'Bad mime:' + mime
                return

        #print "[httpMessage] before lock"        
        # create a new log entry with the message details
        self._lock.acquire()

        row = self._log.size()

        analyzed=False
        ined=False
        

        self.GLOBAL_HANDLER=True
        self.GLOBAL_HANDLER_ANALYZED=False

        try:
            for item in self._log:
                # print "arrive 735"
                if url == item._url:
                    # print "arrive 737"
                    if method == self._helpers.analyzeRequest(item._requestResponse).getMethod():
                        #print 'duplicate URL+method, skipping.. '
                        # self._lock.release()
                        # has it been analyzed?
                        # 非右键的同路径新请求(也就是被动扫描)会覆盖掉所在的item，比如测过的会被刷新为非测过的，不合逻辑,因此这里是个bug
                        # 已经存在记录表里的话可以直接break
                        ined=True
                        analyzed=item._analyzed
                        self.GLOBAL_HANDLER_ANALYZED = True if analyzed else False
                        # print "arrive 745"
                        self.paintItems(messageInfo, item)
                        # print('paint item with:'+str(analyzed))
                        break


            # 如果在scope里但是没有在log里则创建新的item项
            if not ined:
                # print "arrive 755"
                # print "into not ined but in scope"
                messageInfo.setComment(SCOPE_MONITOR_COMMENT)
                date = datetime.datetime.fromtimestamp(time.time()).strftime('%H:%M:%S %d %b %Y')
                entry = LogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), url, analyzed, date, method)
                #print "toolFlag: " + str(toolFlag)
                #print "(processHTTP) Adding URL: " + url 
                # print("add item with:"+str(analyzed))
                self._log.add(entry)
                self._fullLog.add(entry)
                self.fireTableRowsInserted(row, row)
                # print "arrive 766"
                self.paintItems(messageInfo, entry)
            #注意还原全局标志变量
            self.GLOBAL_HANDLER_ANALYZED = False
            self.GLOBAL_HANDLER=False
        except Exception as e:
            # print "772"
            print e.message 
            #异常后也应该释放锁
            self._lock.release()

        self._lock.release()
            #print "columnCoun:" + str(self.logTable.getColumnCount())



    # 处理右键相关的message
    def processHttpMessageAdvanced(self, toolFlag, messageIsRequest, messageInfo):
        # only process requests

        #print "processing httpMessage.."
        #print messageIsRequest

        # print "processHttpMessageAdvanced toolFlag: " + str(toolFlag)
        #print " -- " + str(self._callbacks.getToolName(toolFlag)) + " -- "

        if not(self.STATUS):
            return

        #print "global handler status: (true): " + str(self.GLOBAL_HANDLER)
        #print "(processHTTP) messageIsRequest"
        #print messageIsRequest 

        if messageIsRequest and not(self.GLOBAL_HANDLER):
            # print "1.5 processHttpMessageAdvanced droping message"
            return

        if self.scopeOptionButton.isSelected():
            url = self._helpers.analyzeRequest(messageInfo).getUrl()
            if not self._callbacks.isInScope(url):
                #print 'Url not in scope, skipping.. '
                return

        #toolFlag = 4
        if ((self._callbacks.getToolName(toolFlag) != "Repeater") and (self._callbacks.getToolName(toolFlag) != "Proxy") and (self._callbacks.getToolName(toolFlag) != "Target")):
            #print 'Aborting processHTTP, request came from: ' + str(self._callbacks.getToolName(toolFlag))
            print "Droping request from " + str(self._callbacks.getToolName(toolFlag))
            return

        #print "---> still processing from tool: " + str(self._callbacks.getToolName(toolFlag))

        url = self.getEndpoint(messageInfo)
        method = self.getMethod(messageInfo)

        #print "(processHTTP) before extensions check: " + url 

        for extension in self.BAD_EXTENSIONS:
            if url.endswith(extension):
                return

        if messageInfo.getResponse():
            mime = self._helpers.analyzeResponse(messageInfo.getResponse()).getStatedMimeType()
            #print 'Declared mime:' + mime
            mime = mime.lower()
            if mime in self.BAD_MIMES:
                #print 'Bad mime:' + mime
                return

        #print "[httpMessage] before lock"        
        # create a new log entry with the message details
        self._lock.acquire()
        row = self._log.size()

        try:
            for item in self._log:
                if url == item._url:
                    if method == self._helpers.analyzeRequest(item._requestResponse).getMethod():
                        #print 'duplicate URL+method, skipping.. '
                        self._lock.release()

                        # has it been analyzed?
                        analyzed = False
                        if self._callbacks.getToolName(toolFlag) == "Repeater":
                            if self.repeaterOptionButton.isSelected():
                                analyzed = True
                                #print "[httpMessage] setting analyzed as true" 
                        if self.GLOBAL_HANDLER_ANALYZED:
                            analyzed = True

                        item._analyzed = analyzed
                        self.paintItems(messageInfo, item)
                        return

            #print "[httpMessage] before setComment" 
            messageInfo.setComment(SCOPE_MONITOR_COMMENT)
            # reached here, must be new entry
            analyzed = False
            if self._callbacks.getToolName(toolFlag) == "Repeater":
                if self.repeaterOptionButton.isSelected():
                    analyzed = True
                    #print "[httpMessage] setting analyzed as true" 
            if self.GLOBAL_HANDLER_ANALYZED:
                analyzed = True

            #print "[httpMessage] after comment" 
            #print 'in httpmessage, response:'
            #print self._helpers.analyzeResponse(messageInfo.getResponse())

            date = datetime.datetime.fromtimestamp(time.time()).strftime('%H:%M:%S %d %b %Y')
            entry = LogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), url, analyzed, date, method)
            #print "toolFlag: " + str(toolFlag)

            #print "(processHTTP) Adding URL: " + url 
            self._log.add(entry)
            self._fullLog.add(entry)
            self.fireTableRowsInserted(row, row)

            self.paintItems(messageInfo, entry)
        except Exception as e:
            print e.message
            self._lock.release()

        self._lock.release()

        #print "columnCoun:" + str(self.logTable.getColumnCount())

    #
    # extend AbstractTableModel
    #
    
    def paintItems(self, messageInfo, item):
        print "arrive 897: in paint Items"
        # print "mark color is: (true)" + str(self.markTestedRequestsProxy.isSelected())
        # print "global handler analyzed:           :" + str(self.GLOBAL_HANDLER_ANALYZED)
        # print "item analyzed should be the same ^^:" + str(item._analyzed)
        # print "--------893:"+str(self.GLOBAL_HANDLER_ANALYZED)+"---------------"
        if (self.markTestedRequestsProxy.isSelected()) and (item._analyzed and self.GLOBAL_HANDLER_ANALYZED):
            messageInfo.setHighlight("green")
            # print "---------897:into paint green--------------"
            return
        if self.markNotTestedRequestsProxy.isSelected() and not(item._analyzed):
            messageInfo.setHighlight("red")
            # print "---------897:into red green--------------"
            # return
        # print "--------------903:into exception---------"


    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 4

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Checked"
        if columnIndex == 1:
            return "URL"
        if columnIndex == 2:
            return "Method"
        if columnIndex == 3:
            return "Time"

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)

        #self.setBackground(Color.GREEN)
        return self.returnEntry(rowIndex, columnIndex, logEntry)

        if self.showNewButton.isSelected() and not(logEntry._analyzed):  
            return self.returnEntry(rowIndex, columnIndex, logEntry)
        elif self.showTestedButton.isSelected() and logEntry._analyzed:
            return self.returnEntry(rowIndex, columnIndex, logEntry)
        elif self.showAllButton.isSelected():
            return self.returnEntry(rowIndex, columnIndex, logEntry)


    def returnEntry(self, rowIndex, columnIndex, entry):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            if logEntry._analyzed:
                return "True"
            else:
                return "False"
        if columnIndex == 1:
            return self._helpers.urlDecode(logEntry._url) 
        if columnIndex == 2:
            return logEntry._method
        if columnIndex == 3:
            return logEntry._date
            # return date
        return ""


    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    
    
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        #print 'getRequest called'
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        #print 'getResponse called: '
        print self._currentlyDisplayedItem.getResponse()
        return self._currentlyDisplayedItem.getResponse()
    

    def exportRequest(self, entity, filename):

        line = str(entity._analyzed) + ","
        line = line + self._helpers.urlEncode(entity._url).replace(",", "%2c") + ","    # URL is encoded so we should be good
        line = line + entity._method  + ","
        line = line + entity._date 
        line = line + '\n'

        #print 'Exporting: "' + line + '"'
        return line

    def exportUrlEncode(self, url):
        return self._helpers.urlEncode(url).replace(",", "%2c")

    def exportState(self, filename):
        filename = self.selectPathText.getText()

        if filename == "":
            filename = self._callbacks.loadExtensionSetting("exportFile")
            print 'Empty filename, skipping export'
            return 
        else:
            self._callbacks.saveExtensionSetting("exportFile", filename)

        print 'saving state to: ' + filename

        savedUrls = []
        
        self._lockFile.acquire()
        try:
            with open(filename, 'r') as fr:
                savedEntries = fr.read().splitlines()
                savedUrls = []
                for savedEntry in savedEntries:
                    savedUrls.append(savedEntry.split(",")[1])
                #print "savedUrls len: " + str(len(savedUrls))
                #print "savedUrls:"
                #print savedUrls
                fr.close()
        except IOError:
            print "Autosaving skipped as file doesn't exist yet" 

        with open(filename, 'a+') as f:
            
            for item in self._log:
                if self.exportUrlEncode(item._url) not in savedUrls:
                    line = self.exportRequest(item, "xx")
                    f.write(line)
            f.close()
        self._lockFile.release()
        
        return

    def importState(self, filename):
        filename = self.selectPathText.getText()

        if filename == "":
            filename = self._callbacks.loadExtensionSetting("exportFile")
            print 'Empty filename, skipping import'
            return 
        else:
            self._callbacks.saveExtensionSetting("exportFile", filename)

        print 'loading state from: ' + filename

        self.STATUS = False

        self._lockFile.acquire()
        with open(filename, 'r') as f:

            proxy = self._callbacks.getProxyHistory()

            proxyItems = []
            for item in proxy:
                if item.getComment():
                    if SCOPE_MONITOR_COMMENT in item.getComment():
                        proxyItems.append(item)


            print 'proxyItems has: ' + str(len(proxyItems))
            # TODO - if no proxy items, sraight to import

            lines = f.read().splitlines()
            for line in lines:
                data = line.split(",")
                url = data[1]
                url = self._helpers.urlDecode(url) 

                #print 'Saving: ' + url
                if not self._callbacks.isInScope(URL(url)):
                    print '-- imported url not in scope, skipping.. '
                    continue


                analyzed = False
                if data[0] == "True":
                    analyzed = True


                #print '.. simulating url search.. '
                requestResponse = None
                for request in proxyItems:
                    if url == self.getEndpoint(request):
                        #print 'Match found when importing for url: ' + url
                        requestResponse = request
                        break

                self._log.add(LogEntry("", requestResponse, url, analyzed, data[3], data[2]) ) 


            self._lockFile.release()
        print 'finished loading.. '
        #print 'size: ' + str(self._log.size())
        self.fireTableDataChanged()

        if self.startButton.getText() == MONITOR_ON_LABEL:
            self.STATUS = True

        return

    def autoSave(self, sc):
        #print 'autosaving.. lol what'
        if self.autoSaveOption.isSelected():
            print "[" + self.getTime() + "] autosaving to " + self._callbacks.loadExtensionSetting("exportFile")
            self.exportState("")

        self.SC.enter(self.AUTOSAVE_TIMEOUT, 1, self.autoSave, (self.SC,))
        return

    def getTime(self):
        date = datetime.datetime.fromtimestamp(time.time()).strftime('%H:%M:%S')
        return date

#
# extend JTable to handle cell selection
#

    #def getRequest(self,):
    
class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        self.addMouseListener(mouseclick(self._extender))
        self.setRowSelectionAllowed(True)
        self.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
    
    def changeSelection(self, row, col, toggle, extend):
    
        # shows "entries" matching

        # show the log entry for the selected row
        #print 'Selecting entry ' + str(row) + ' in changeSelection: ' 

        JTable.changeSelection(self, row, col, toggle, extend)

        modelRow = self.convertRowIndexToModel(row)
        #print 'converted: ' + str()

        logEntry = self._extender._log.get(modelRow)

        #print str(self._extender._helpers.analyzeRequest(logEntry._requestResponse).getUrl())

        self._extender.SELECTED_MODEL_ROW = modelRow
        self._extender.SELECTED_VIEW_ROW = row

        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        
        
        #JTable.changeSelection(self, row, col, toggle, extend)
        return

    
class mouseclick(MouseAdapter):
    def __init__(self, extender):
        self._extender = extender

    def mouseReleased(self, evt):
        if evt.button == 3:
            self._extender.menu.show(evt.getComponent(), evt.getX(), evt.getY())


class ColoredTableCellRenderer(DefaultTableCellRenderer):
    def __init__(self, extender):
        self._extender = extender

    def setValue(self, value):
        if value == "False":
            self.setBackground(Color(255,135,135))
            #self.setForeground(Color.RED)
        elif value == "True":
            self.setBackground(Color(107,255,127))
            #self.setForeground(Color.GREEN)
        #return value
        self.super__setValue(value)


#
# class to hold details of each log entry
#

class LogEntry:
    def __init__(self, tool, requestResponse, url, analyzed, date, method):
        self._tool = tool
        self._requestResponse = requestResponse
        self._url = url
        self._displayed = False
        self._analyzed  = analyzed
        self._date = date 
        self._method = method

class CustomTableRowSorter(TableRowSorter):

    # override toggleSortOrder method
    def toggleSortOrder(self, column):

        # check if valid column 
        if column >= 0:

            # get the sort keys
            keys = self.getSortKeys()

            # check if the sort keys are not empty
            if keys.isEmpty() == False:

                # get the sort key
                sortKey = keys.get(0)

                # check if the column clicked is sorted in descending order
                if sortKey.getColumn() == column and sortKey.getSortOrder() == SortOrder.DESCENDING:

                    # clear sorting
                    self.setSortKeys(None)

                    # do not continue
                    return

        # try to toggle default toggleSortOrder
        try:
            # toggle default toggleSortOrder
            TableRowSorter.toggleSortOrder(self, column)

        # catch if table is being sorted by processProxyMessage and user
        except:
            pass

class deleteRequestHandler(ActionListener):
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, e):
        #print "COPY SELECTED URL HANDLER ******"

        rows = self._extender.logTable.getSelectedRows()
        to_delete = []

        for row in rows:

            model_row = self._extender.logTable.convertRowIndexToModel(row)

            self._extender._log.remove(self._extender._log.get(model_row))

        self._extender.fireTableDataChanged()
        #print 'refreshing view ..... *****'

        return 

class sendRequestRepeater(ActionListener):
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, e):
        #print "COPY SELECTED URL HANDLER ******"

        rows = self._extender.logTable.getSelectedRows()
        for row in rows:

            model_row = self._extender.logTable.convertRowIndexToModel(row)

            request = self._extender._log.get(model_row)._requestResponse
            url = self._extender._log.get(model_row)._url

            host = request.getHttpService().getHost()
            port = request.getHttpService().getPort()
            proto = request.getHttpService().getProtocol()

            secure = True if proto == 'https' else False
            
            self._extender._callbacks.sendToRepeater(host, port, secure, request.getRequest(), None);

        return 

### LOCAL CONTEXT
class markRequestsHandler(ActionListener):
    def __init__(self, extender, state):
        self._extender = extender
        self._state = state

    def actionPerformed(self, e):
        #print "COPY SELECTED URL HANDLER ******"
        #print "Status is: " + str(self._state)
        # print "into markrequestedshandler"

        rows = self._extender.logTable.getSelectedRows()
        try:
            for row in rows:
                # print "into for"

                model_row = self._extender.logTable.convertRowIndexToModel(row)
                url = self._extender._log.get(model_row)._url
                method =self._extender._log.get(model_row)._method

                #print "Changing url: " + url

                ### TODO REPLACE FOR MARK_AS_ANALYZED 
                self._extender._lock.acquire()

                # print "arrive 1302"
                for item in self._extender._log:
                    if url == item._url and method==item._method:
                        # print "arrive 1305"
                        item._analyzed = self._state
                        # print "arrive 1307: panintitems with",item._analyzed
                        # 修改即可无须重画会造成死锁,set value的时候会和ColoredTableCellRenderer的触发监听函数造成冲突
                        # self._extender.paintItems(item._requestResponse, item)
                        break
                # 同步修改对应的log 和 fulllog数据
                for item in self._extender._fullLog:
                    if url == item._url and method==item._method:
                        # print "arrive 1313"
                        item._analyzed = self._state
                # print "arrive 1315"
                self._extender._lock.release()
        except Exception as e:
            print e.message
            self._extender._lock.release()

        self._extender.fireTableDataChanged()
        #print 'refreshing view ..... *****'

        #self._extender.changeSelection(self._extender.SELECTED_VIEW_ROW, 1, True, True)
        #self._extender.changeSelection(self._extender.SELECTED_VIEW_ROW, 1, False, False)
        #self._extender.changeSelection(self._extender.SELECTED_VIEW_ROW, 1, True, True)

        return 


### GLOBAL CONTEXT #### 
class handleMenuItems(ActionListener):
    def __init__(self, extender, messageInfo, menuName):
        self._extender = extender
        self._menuName = menuName
        self._messageInfo = messageInfo

    def actionPerformed(self, e):
        self._extender.GLOBAL_HANDLER = True

        if self._menuName == "analyzed":
            self._extender.GLOBAL_HANDLER_ANALYZED = True
            self._extender.processHttpMessageAdvanced(4, self._messageInfo, self._messageInfo)
            self._extender.markAnalyzed(self._messageInfo, True)
            #start_new_thread(self._extender.sendRequestToAutorizeWork,(self._messageInfo,))

        if self._menuName == "not":
            self._extender.GLOBAL_HANDLER_ANALYZED = False
            self._extender.processHttpMessageAdvanced(4, self._messageInfo, self._messageInfo)
            self._extender.markAnalyzed(self._messageInfo, False)

        self._extender.GLOBAL_HANDLER_ANALYZED = False
        self._extender.GLOBAL_HANDLER = False
            #self._extender.replaceString.setText(self._extender.getCookieFromMessage(self._messageInfo))

class passiveScanner(IScannerCheck):
    def __init__(self, extender):
        self._extender = extender

    def doPassiveScan(self, messageInfo):
        pass
        # print "--> passiveScan:"
        #print messageInfo
        # 4 = "Proxy"
        # self._extender.processHttpMessageAdvanced(1234, messageInfo, messageInfo)

if __name__ in ('__main__', 'main'):
    EventQueue.invokeLater(Run(BurpExtender))

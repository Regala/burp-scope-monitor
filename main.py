# -*- coding: utf-8 -*- 
from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from burp import IContextMenuFactory
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import LinkedList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from threading import Lock

###
from java.awt.event import MouseAdapter
from javax.swing import JMenuItem
from javax.swing import JPopupMenu
from java.awt.event import ActionListener
from java.awt import BorderLayout
from java.awt import GridLayout
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
from urlparse import *

BAD_EXTENSIONS = ['.gif', '.png', '.js', '.woff', '.woff2', '.jpeg', '.jpg', '.css', '.ico']

SHOW_ALL_BUTTON_LABEL = "Show All"
SHOW_NEW_BUTTON_LABEL = "Show New Only"
SHOW_TEST_BUTTON_LABEL = "Show Tested Only"

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel, IContextMenuFactory):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Burp Scope Monitor")

        #self._showAllFlag = True
        #self._showNewOnly = False
        # - quero ver só os novos
        # - quero ver todos
        # 
        
        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._fullLog = ArrayList()
        self._lock = Lock()
        
        # main split pane
        self._parentPane = JTabbedPane()

        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        ##### config pane
        self._config = JTabbedPane()

        config = JPanel()
        config.setLayout(GridLayout(1,3))

        self.showAllButton = JRadioButton(SHOW_ALL_BUTTON_LABEL, True)
        self.showNewButton = JRadioButton(SHOW_NEW_BUTTON_LABEL, False)
        self.showTestedButton = JRadioButton(SHOW_TEST_BUTTON_LABEL, False)

        self.showAllButton.addActionListener(self.handleRadioConfig)
        self.showNewButton.addActionListener(self.handleRadioConfig)
        self.showTestedButton.addActionListener(self.handleRadioConfig) 


        bGroup = ButtonGroup()

        bGroup.add(self.showAllButton)
        bGroup.add(self.showNewButton)
        bGroup.add(self.showTestedButton)

        config.add(self.showAllButton)
        config.add(self.showNewButton)
        config.add(self.showTestedButton)

        self._config.addTab("Config", config)

        ##### end config pane


        self._parentPane.addTab("Monitor", self._splitpane)
        self._parentPane.addTab("Config", self._config)
        
        # table of log entries
        self.logTable = Table(self)
        self.logTable.setAutoCreateRowSorter(True)

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
        

        copyURLitem = JMenuItem("Copy URL")
        copyURLitem.addActionListener(copySelectedURL(self))

        #sendRequestMenu = JMenuItem("Send Original Request to Repeater")
        #sendRequestMenu.addActionListener(sendRequestRepeater(self, self._callbacks, True))
        self.menu = JPopupMenu("Popup")
        self.menu.add(copyURLitem)

        # customize our UI components
        callbacks.customizeUiComponent(self._parentPane)
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(self._config)
        callbacks.customizeUiComponent(config)
        callbacks.customizeUiComponent(self.logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)

        callbacks.registerContextMenuFactory(self)
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
        
        return
        
    ##### CUSTOM CODE #####

    ## GLOBAL CONTEXT CODE ##

    def createMenuItems(self, invocation):
        responses = invocation.getSelectedMessages()
        print 'trying to create menuItems.. (GLOBAL)'
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
        print "Url3: " + url
        return url


    def getMethod(self, requestResponse):
        return self._helpers.analyzeRequest(requestResponse).getMethod()


    ##### CUSTOM CODE #####

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
        self._tableRowSorterAutoProxyAutoAction.toggleSortOrder(1)
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
        print "markAnalyzed..."
        self._lock.acquire()

        url = self.getEndpoint(messageIsRequest)
        for item in self._log:
            if url == item._url:
                item._analyzed = state
                self._lock.release()
                return
        self._lock.release()
        return

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only process requests

        #print "processing httpMessage.."
        #print messageIsRequest
        #if messageIsRequest:
        #    return

        #print "still processing httpMessage.."

        #if (self._callbacks.getToolName(toolFlag) != "Proxy") or (self._callbacks.getToolName(toolFlag) != "Repeater"):
        #    return

        url = self.getEndpoint(messageInfo)

        for extension in BAD_EXTENSIONS:
            if url.endswith(extension):
                return
        
        # create a new log entry with the message details
        self._lock.acquire()
        row = self._log.size()


        for item in self._log:
            if url == item._url:
                print 'duplicate url, skipping.. '
                self._lock.release()
                return

        # reached here, must be new entry
        analyzed = False
        if self._callbacks.getToolName(toolFlag) == "Repeater":
            analyzed = True

        entry = LogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), url, analyzed)
        print "toolFlag: " + str(toolFlag)
        self._log.add(entry)
        self._fullLog.add(entry)
        self.fireTableRowsInserted(row, row)
        self._lock.release()

    #
    # extend AbstractTableModel
    #
    
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 2

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Checked"
        if columnIndex == 1:
            return "URL"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)

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
            return logEntry._url
        return ""


    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return 
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return 
        return self._currentlyDisplayedItem.getResponse()

#
# extend JTable to handle cell selection
#

    #def getRequest(self,):
    
class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        self.addMouseListener(mouseclick(self._extender))
    
    def changeSelection(self, row, col, toggle, extend):
    
        # shows "entries" matching

        # show the log entry for the selected row
        print 'Selecting entry ' + str(row) + ' in changeSelection: ' 

        modelRow = self.convertRowIndexToModel(row)
        #print 'converted: ' + str()

        logEntry = self._extender._log.get(modelRow)

        #print str(self._extender._helpers.analyzeRequest(logEntry._requestResponse).getUrl())

        JTable.changeSelection(self, row, 1, toggle, extend)

        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        
        #JTable.changeSelection(self, row, col, toggle, extend)
    
class mouseclick(MouseAdapter):

    def __init__(self, extender):
        self._extender = extender

    def mouseReleased(self, evt):
        if evt.button == 3:
            self._extender.menu.show(evt.getComponent(), evt.getX(), evt.getY())

#
# class to hold details of each log entry
#

class LogEntry:
    def __init__(self, tool, requestResponse, url, analyzed):
        self._tool = tool
        self._requestResponse = requestResponse
        self._url = url
        self._displayed = False
        self._analyzed  = analyzed

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



class copySelectedURL(ActionListener):
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, e):
        print "COPY SELECTED URL HANDLER ******"
        return 
        stringSelection = StringSelection(str(self._extender._helpers.analyzeRequest(self._extender._currentlyDisplayedItem._requestResponse).getUrl()))
        clpbrd = Toolkit.getDefaultToolkit().getSystemClipboard()
        clpbrd.setContents(stringSelection, None)

### GLOBAL CONTEXT #### 
class handleMenuItems(ActionListener):
    def __init__(self, extender, messageInfo, menuName):
        self._extender = extender
        self._menuName = menuName
        self._messageInfo = messageInfo

    def actionPerformed(self, e):
        if self._menuName == "analyzed":
            print "MARK AS ANALYZED"
            self._extender.processHttpMessage(4, self._messageInfo, self._messageInfo)
            self._extender.markAnalyzed(self._messageInfo, True)
            #start_new_thread(self._extender.sendRequestToAutorizeWork,(self._messageInfo,))

        if self._menuName == "not":
            print "MARK AS NOT ANALYZED"
            self._extender.processHttpMessage(4, self._messageInfo, self._messageInfo)
            self._extender.markAnalyzed(self._messageInfo, False)

            #self._extender.replaceString.setText(self._extender.getCookieFromMessage(self._messageInfo))

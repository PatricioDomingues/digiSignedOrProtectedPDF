# coding=utf-8
# @lastupdate: 2018-08-25 15h39:51
# Name: digiSignedOrProtectedPDFs
# Type: file ingest module
#
# TLDR; Summary
# ==============
# For each PDF file (detected through the .pdf extension of filename), the 
# module:
# - detects the signed PDF files, that is, the ones with a 
#   digital signature. It reports them as "interesting files"
# - detects the protected PDF files, that is, the ones that have some
#   kind of protection (e.g., no copy of its content is allowed due to the 
#   existence of user protection for the PDF file).
# 
# Dependencies
# =============
# The module depends on two external applications:
# - an external APP (JSignPDF[1]) is called that returns a numeric code
# pointing out whether the PDF file is digitally signed or not.
# For each signed PDF file, the module inserts it into 
# TSK_INTERESTING_FILE_HIT artifacts.
#
# - another external APP (exiftool[2]) is called to determine whether
#   the PDF file has some special user/owner restrictions/permissions.
#   Specifically, the module spots the PDF files 
# 
# Author: Patricio Domingues, 2017
#
# [1] JSignPdf by Josef Cacek (http://jsignpdf.sourceforge.net/)
# [2] ExifTool by Phil Harvey (https://www.sno.phy.queensu.ca/~phil/exiftool/)
#
#
# The code is based on:
# - sample "file ingest" module from Brian Carrier 
# - Gui_Test_With_Settings(https://github.com/markmckinnon/Autopsy-Plugins/tree/master/Gui_Test_With_Settings) 
#   from Mark McKinnon
#
# Thanks to all Of them.
#
# INFO #1
# =======
# This module depends on the very good "JSignPdf" software:
# - The software is available at http://jsignpdf.sourceforge.net
# - Specifically, this module requires the following files from JSignPdf:
# -- Verifier.exe
# -- Verifier.jar
# -- SignatureCounter.jar
# -- JSignPdf.jar
# -- jre DIR (from JSignPdf)
# -- lib DIR (from JSignPdf)
# The files of lib DIR are:
# -a----       2014/09/16     23:36         487135 bcmail-jdk15-146.jar
# -a----       2014/09/16     23:36        1815677 bcprov-jdk15-146.jar
# -a----       2014/09/16     23:36          39707 bctsp-jdk15-146.jar
# -a----       2014/09/16     23:36          41123 commons-cli-1.2.jar
# -a----       2014/09/16     23:36         163151 commons-io-2.1.jar
# -a----       2014/09/16     23:36         315805 commons-lang3-3.1.jar
# -a----       2014/09/16     23:36         205152 fontbox-1.8.2.jar
# -a----       2014/09/16     23:36        6340486 icu4j-4_2_1.jar
# -a----       2014/09/16     23:36        2508455 icu4j-charsets-4_2_1.jar
# -a----       2014/09/16     23:36          17308 jcl-over-slf4j-1.6.4.jar
# -a----       2014/09/16     23:36          50966 jempbox-1.8.2.jar
# -a----       2014/09/16     23:36        2929058 jpedal_lgpl.jar
# -a----       2014/09/16     23:37        1130571 jsignpdf-itxt-1.6.1.jar
# -a----       2014/09/16     23:36         481534 log4j-1.2.16.jar
# -a----       2014/09/16     23:36        3959589 pdfbox-1.8.2.jar
# -a----       2014/09/16     23:36        1620310 PDFRenderer.jar
# -a----       2014/09/16     23:36          25962 slf4j-api-1.6.4.jar
# -a----       2014/09/16     23:36           9748 slf4j-log4j12-1.6.4.jar
#
#
# The localization of the EXE verifier needs to be given as the "Verifier EXE"
# parameter available in the module panel configuration.
# The simplest way to configure JSignPDF for the module is simply to install 
# it and to have the "Verifier EXE" parameter to point (to have the full path) 
# to the "verifier.exe" file.
#
# INFO #2
# =======
# The PDF permission module depends on the excellent command line 
# tool "exiftool". Unser Windows, the simplest way to configure it, is 
# to unzip exiftool in a given directory, change its name to exiftool.exe 
# and then configure the module through its GUI config panel to point to the
# full path of the "exiftool.exe" file.
#
# INFO #3
# =======
# The module was only tested under Windows OS.
#
# License
#=========
# MIT License (MIT)
# 
# Copyright (c) 2017,2018 Patricio Domingues
#
# Permission is hereby granted, free of charge, to any person obtaining a 
# copy of this software and associated documentation files (the "Software"), 
# to deal in the Software without restriction, including without limitation 
# the rights to use, copy, modify, merge, publish, distribute, sublicense, 
# and/or sell copies of the Software, and to permit persons to whom the 
# Software is furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included 
# in all copies or substantial portions of the Software.
#
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR 
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE 
# USE OR OTHER DEALINGS IN THE SOFTWARE. 
#
#--------------------------------------------------------------------


import jarray
import inspect
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from org.sleuthkit.autopsy.datamodel import ContentUtils


from javax.swing import JCheckBox
from javax.swing import JList
from javax.swing import JTextArea
from javax.swing import BoxLayout
from java.awt import GridLayout
from java.awt import BorderLayout
from javax.swing import BorderFactory
from javax.swing import JToolBar
from javax.swing import JPanel
from javax.swing import JFrame
from javax.swing import JScrollPane
from javax.swing import JComponent
from java.awt.event import KeyListener
from javax.swing import JTextField
from javax.swing import JLabel
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from javax.swing import JFileChooser
from javax.swing.filechooser import FileNameExtensionFilter
from javax.swing import ButtonGroup
from javax.swing import JButton


import java.io.File
from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException


import codecs   # To produce CSV utf-8 files
import sys      # To process exception
import string
import os.path
import os
import subprocess
from datetime import datetime
import time
import random


from subprocess import PIPE, Popen
import json
import threading

##--------------------------------------------------------------------
## TODO:2018-05-19:g_lock to avoid repeated references to "threading.lock"? 
##--------------------------------------------------------------------

#--------------------------------------
# global variables
#--------------------------------------
Sep_S = "%s" % ('='*70)

# This is controlled by the setting section
# Default path for PDFsigner
C_PATH_VERIFIER="C:/Users/Public/tmp/_Autopsy.modules/verifier---2017.07.24a/verifier/verifier.exe"

# Default path for exiftool (used to extract userAccess info from PDF files)
# C_PATH_EXIFTOOL="C:/Users/Public/Portable/exifTool/exiftool.exe"
C_PATH_EXIFTOOL="NONE"


#--------------------------------------
# Constants for user_access_to_int
#--------------------------------------
C_ASSEMBLE  = 1L << 0
C_ANNOTATE  = 1L << 1
C_COPY      = 1L << 2
C_EXTRACT   = 1L << 3
C_FILLFORMS = 1L << 4
C_MODIFY    = 1L << 5
C_PRINT     = 1L << 6

C_ASSEMBLE_S  = "assemble"
C_ANNOTATE_S  = "annotate"
C_COPY_S      = "copy"
C_EXTRACT_S   = "extract"
C_FILLFORMS_S = "fill forms"
C_MODIFY_S    = "modify"
C_PRINT_S     = "print"


C_USER_ACCESS_D = {C_ASSEMBLE_S:C_ASSEMBLE, 
                   C_ANNOTATE_S:C_ANNOTATE,
                   C_COPY_S:C_COPY,
                   C_EXTRACT_S:C_EXTRACT,
                   C_FILLFORMS_S:C_FILLFORMS,
                   C_MODIFY_S:C_MODIFY,
                   C_PRINT_S:C_PRINT}

#====================================================================
# Configuration of DEBUG
#====================================================================
#--------------------------------------
# Levels of logging
#--------------------------------------
# controls the log level:only msg with log level <= C_Log_Level are logged
C_Log_Level = 3 

# Log level for message regarding analyzing files
C_LOG_ANALYZE = 3

# Log details of every processed file
C_LOG_FILE_DETAILS = 4

# Log details of every executed external command (log stdout and stderr)
C_LOG_EXEC_DETAILS = 5

# Name of file to receive PDF filenames
C_LOG_PDF_FNAMES     = "_log_name_PDF_files.log.txt"

# Name of file to receive NOT PDF files
C_LOG_NOT_PDF_FNAMES = "_log_name_NOT_PDF_files.log.txt"

# Name of file to receive EVERYTHING filenames
C_LOG_EVERY_FNAMES   = "_log_name_EVERY.log.txt"

# Name of file to receive ALL counted filenames
C_LOG_ALL_COUNTED_FNAMES = "_log_name_COUNTED.log.txt"



#------------------------------------------------
# Name of settings DB (SQLite to save settings)
#------------------------------------------------
C_DB_NAME = "SignedPDFs_Settings.db3"

#------------------------------------------------
# Fields to be saved/kept in the settings DB
#------------------------------------------------
C_SIGNER_EXEC_FIELD      = "signer_exec_name"
C_DONT_INSERT_DUPLICATES = "dont_insert_duplicates"
C_CREATE_CSV_FILE        = "create_CSV_file"
C_EXIFTOOL_EXEC_FIELD    = "exiftool_exec_name" 

#------------------------------------------------
# Strings to identify:
# i) permission states
# ii) used as keys for m_permission_Stats_D dict.
#------------------------------------------------
C_AssembleOFF_ModifyOFF = "AssembleOFF_ModifyOFF"
C_AssembleON_ModifyOFF  = "AssembleON_ModifyOFF"
C_AssembleON_ModifyON   = "AssembleON_ModifyON"
C_AssembleOFF_ModifyON  = "AssembleOFF_ModifyON"

# Possible keys for the m_permission_Stats_D dict.
C_FILES_WITH_PERMISSIONS_KEY="C_FILES_WITH_PERMISSIONS"
C_FILES_AssembleON_ModifyOFF_KEY="C_FILES_AssembleON_ModifyOFF"

#====================================================================
# code
#====================================================================
#--------------------------------------------------------------------
# Function to deal with special DEBUG log files
#--------------------------------------------------------------------
def open_log_file(fname):
    """Create and init file 'fname' returning the file handle"""

    temp_dirname = Case.getCurrentCase().getTempDirectory()
    full_log_fname = os.path.join(temp_dirname,fname)

    unbuffered = 0
    log_F = open(full_log_fname,"w",unbuffered)
    # Init the file
    Row_S = "%s\n" % (Sep_S)
    log_F.write(Row_S)
    log_F.write("# '%s'\n" % (fname))
    timestamp_S = datetime.now().strftime('# %Y-%m-%d_%Hh%Mm%Ss\n')
    log_F.write(timestamp_S)
    log_F.write(Row_S)

    # return the file handle
    return log_F

def write_log_file(log_handle_F,msg_S):
    timestamp_S = datetime.now().strftime('%Y-%m-%d_%Hh%Mm%Ss.%f')
    log_S = "%s:%s\n" % (timestamp_S,msg_S)
    log_handle_F.write(log_S.encode('utf-8'))


def close_log_file(log_F):
    """close log file"""
    if log_F is None:
        return None
    else:
        msg_S = "Closing log."
        write_log_file(log_F,msg_S)
        log_F.close()

#====================================================================
# classes
#====================================================================


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the anlaysis.
class FindSignedPDFsFilesIngestModuleFactory(IngestModuleFactoryAdapter):

    ## moduleName = "Signed PDFs (panel)"
    moduleName = "digiSignedOrProtectedPDF"

    #--------------------------------------------
    # Class variables
    # The variables are shared among the various
    # threads that might run the module.
    # (Autopsy creates several threads to process
    # data sources with a FileIngest module)
    #--------------------------------------------
    # Register start time
    g_start_time = time.time()

    # Count the number of processed PDF files
    g_PDFFiles_count = 0

    # Count the number of signed PDF files
    g_signedPDFFiles_count = 0

    # Count the number of inserted signed PDF files
    g_PDFFilesInserted_count = 0

    # Count the number of files
    g_files_count = 0

    # Count the number of files that are not PDF
    g_NotPDFFiles_count = 0 

    # Dictionary which keeps the full path of PDF files 
    # (and other parameters)
    g_fullPathPDFFiles_D = {}

    # Dicitionary to keep permissions of PDF files
    g_permission_PDFs_D = {}

    # Permissions stats
    g_permission_Stats_D = {}
    g_permission_Stats_D[C_AssembleOFF_ModifyOFF] = 0
    g_permission_Stats_D[C_AssembleON_ModifyOFF]  = 0
    g_permission_Stats_D[C_AssembleON_ModifyON]   = 0
    g_permission_Stats_D[C_AssembleOFF_ModifyON]  = 0

    # Log files for debugging
    if C_Log_Level >= C_LOG_FILE_DETAILS:
        g_log_pdf_names_F          = open_log_file(C_LOG_PDF_FNAMES)
        g_log_not_pdf_names_F      = open_log_file(C_LOG_NOT_PDF_FNAMES)
        g_log_every_fnames_F       = open_log_file(C_LOG_EVERY_FNAMES)
        g_log_all_counted_fnames_F = open_log_file(C_LOG_ALL_COUNTED_FNAMES)
    else:
        g_log_pdf_names_F          = None
        g_log_not_pdf_names_F      = None
        g_log_every_fnames_F       = None
        g_log_all_counted_fnames_F = None

    # Message to be shown to the user at the end. 
    # It only gets filled if a configuration error is detected
    # (e.g., wrong path for VERIFIER.EXE)
    g_final_msg = ""

    #--------------------------------------------
    def __init__(self):
        self.settings = None

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Detect i) digitally signed or "\
                "ii) protected PDF files"

    def getModuleVersionNumber(self):
        return "0.5"

    # Return true if module wants to get called for each file
    def isFileIngestModuleFactory(self):
        return True

#********************************************************************
# PANEL
#********************************************************************

    def getDefaultIngestJobSettings(self):
        ## return Process_AmcacheWithUISettings()
        return Process_FindSignedPDFFilesWithUISettings()

    def hasIngestJobSettingsPanel(self):
        return True

    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, Process_FindSignedPDFFilesWithUISettings):
            Err_S = "Expected 'settings' argument to be"\
                    "'Process_FindSignedPDFFilesWithUISettings'"
            raise IngestModuleException(Err_S)

        # Still here? Good
        self.settings = settings
        return Process_FindSignedPDFFilesWithUISettingsPanel(self.settings)    

    def isFileIngestModuleFactory(self):
        return True

    # can return null if isFileIngestModuleFactory returns False
    # Return True to have module called for each file
    def createFileIngestModule(self, ingestOptions):
        return FindSignedPDFFilesIngestModule(self.settings)

#--------------------------------------------------------------------
# File-level ingest module. One object gets created per thread.
#--------------------------------------------------------------------
class FindSignedPDFFilesIngestModule(FileIngestModule):

    _logger = \
         Logger.getLogger(FindSignedPDFsFilesIngestModuleFactory.moduleName)

    # Name to be used for creating directory under ModuleOutput
    _moduleDirname = "SignedPDFs"


    

    def log(self, level, msg):
        ## Troubles occurred with this code (it crashed...)
        self._logger.logp(level, self.__class__.__name__, 
                                        inspect.stack()[1][3], msg)

##        ## Safer approach (workaround in case above line of code fails)
##        ## Occasionally, it has failed...
##        self._logger.logp(level, self.__class__.__name__, 
##                                        "INFO", msg)

    #--------------------------------------------------------------------
    # Constructor with parameter
    # 2017-08-20
    #--------------------------------------------------------------------
    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self.log(Level.INFO, Sep_S)
        self.log(Level.INFO, "**INIT with parameters**")
        self.log(Level.INFO, Sep_S)




    # getter method for moduleDirname
    def getModuleDirname(self):
        return self._moduleDirname

    # getter for module name
    def getModuleName(self):
        return FindSignedPDFsFilesIngestModuleFactory.moduleName

    #--------------------------------------------------------------------
    # Getter for self.m_workDir
    # @return
    # 2017-08-02
    # NOTE: m_workdir is only set at self.startUp()
    #--------------------------------------------------------------------
    def getWorkDir(self):
        """getter for m_workDir"""
        return self.m_workDir

    #--------------------------------------------------------------------
    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext
    # See: http://sleuthkit.org/autopsy/docs/api-docs/4.4/...
    # ...classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    # Throw an IngestModule.IngestModuleException exception 
    #   if there is a problem setting up
    #--------------------------------------------------------------------
    def startUp(self, context):

        # start timer
        self.m_time_start = time.time()

        self.context = context        

        # TEMP directory
        self.m_tempDirectory = Case.getCurrentCase().getTempDirectory()

        self.m_baseDir = os.path.join(
                Case.getCurrentCase().getModuleDirectory(), 
                self.getModuleDirname())


        create_dir = self.create_dir_if_not_exist(self.m_baseDir)
        if create_dir == -1:
            # Could not create DIR 'self.m_baseDir'
            # Throw an IngestModule.IngestModuleException exception 
            Err_S = "Can't create DIR '%s'" % (self.m_baseDir)
            raise IngestModuleException(Err_S)

        raw_caseName = Case.getCurrentCase().getName()
        self.m_caseNameDir = string.replace(raw_caseName,' ','_')
        self.m_workDir = os.path.join(self.m_baseDir,self.m_caseNameDir)


        create_dir = self.create_dir_if_not_exist(self.m_workDir)
        if create_dir == -1:
            # Could not create DIR 'self.m_workDir'
            # Throw an IngestModule.IngestModuleException exception 
            Err_S = "Can't create DIR '%s'" % (self.m_workDir)
            self.log(Level.SEVERE, Err_S )

            lock = threading.Lock()
            lock.acquire()
            FindSignedPDFsFilesIngestModuleFactory.g_final_msg = Err_S
            lock.release()

            raise IngestModuleException(Err_S)

        # Check if signer EXE exists at the configured path
        # If not, we abort the execution
        EXE_signer_path = self.local_settings.get_EXE_signer_path()
        if not os.path.isfile(EXE_signer_path):
            Err1_S = "Cannot find PDF verifier EXE '%s'" % (EXE_signer_path)
            Err2_S = "\nPlease configure the correct path for 'verifier.exe'"
            Err_S = "%s\n%s" % (Err1_S,Err2_S)
            self.log(Level.SEVERE, Err_S )

            lock = threading.Lock()
            lock.acquire()
            FindSignedPDFsFilesIngestModuleFactory.g_final_msg = Err1_S
            lock.release()

            raise IngestModuleException(Err_S)

        # Check if ExifTool EXE exists at the configured path
        # If not we abort the execution
        EXE_exiftool_path = self.local_settings.get_EXE_exiftool_path()
        if not os.path.isfile(EXE_exiftool_path):
            Err1_S = "Cannot find ExifTool '%s'" % (EXE_exiftool_path)
            Err2_S = "Please configure the correct path for ExifTool"
            Err_S = "%s\n%s" % (Err1_S,Err2_S)
            self.log(Level.SEVERE, Err_S )

            lock = threading.Lock()
            lock.acquire()
            FindSignedPDFsFilesIngestModuleFactory.g_final_msg = Err1_S
            lock.release()

            raise IngestModuleException(Err_S)



    #---------------------------------------------------------------
    # create DIR if it does not exist yet
    # @param dirToCreate [IN] dir to create if it doesn't exist
    # @return 0 if the DIR already existed
    #         1 if it was created
    #        -1 if creation failed
    # 2017-08-04
    #---------------------------------------------------------------
    def create_dir_if_not_exist(self,dirToCreate):
        """create dirToCreate if it doesn't exist"""

        if os.path.isdir(dirToCreate):
            return 0

        # LOG
        Log_S = "trying to create directory '%s'" % (dirToCreate)
        self.log(Level.INFO, Log_S )

        try:
	    os.mkdir(dirToCreate)
            return 1
        except:
            msg_S = "Can't create DIR '%s'" % (dirToCreate)
	    self.log(Level.INFO, msg_S)
            return -1


    #--------------------------------------------------------------------
    # Where any shutdown code is run and resources are freed.
    #--------------------------------------------------------------------
    def shutDown(self):
        """shutdown code"""
        # Msg_S = "finished: %d PDF files" % (self.m_PDFFiles_count)
        # self.log(Level.INFO, Msg_S)

        #--------------------------------------------------
        # DEBUG -- it always returns 1...
        #--------------------------------------------------
        num_threads = threading.active_count()
        Log_S = "Number of threads=%d" % (num_threads)
        self.log(Level.INFO, Log_S)
        #--------------------------------------------------

        # Elaspsed time
        g_elapsed_time_secs = time.time() -\
                FindSignedPDFsFilesIngestModuleFactory.g_start_time

        lock = threading.Lock()
        lock.acquire()
        final_msg = FindSignedPDFsFilesIngestModuleFactory.g_final_msg
        lock.release()
        self.log(Level.INFO, "FINAL: '%s'" % (final_msg))

        if len(final_msg) > 0:
            # A final message exists (so, something wrong was detected)
            # Show the final message
            msg_to_show = "Got no results (%s)" % (final_msg)
        else:
            # LOG
            msg_to_show = "number of analyzed files %d "\
                "(%d PDF [%d signed PDF]) -- %d inserted (%f secs)" %\
                (FindSignedPDFsFilesIngestModuleFactory.g_files_count,
    ##             FindSignedPDFsFilesIngestModuleFactory.g_NotPDFFiles_count,
                 FindSignedPDFsFilesIngestModuleFactory.g_PDFFiles_count,
                 FindSignedPDFsFilesIngestModuleFactory.g_signedPDFFiles_count,
                 FindSignedPDFsFilesIngestModuleFactory.g_PDFFilesInserted_count, 
                 g_elapsed_time_secs)

        self.log(Level.INFO, msg_to_show)
        # Post message on central logger
        self.postIngestMessage(self.getModuleName(), msg_to_show)

        if len(final_msg) == 0:
            # Alias for self.m_permission_Stats_D dictionary 
            # (to have shorter lines of source code)
            #-- start of exclusive zone --
            lock = threading.Lock()
            lock.acquire()
            stats_D = FindSignedPDFsFilesIngestModuleFactory.g_permission_Stats_D
            num_permissions_PDFs = stats_D[C_AssembleOFF_ModifyOFF] +\
                                   stats_D[C_AssembleON_ModifyOFF]  +\
                                   stats_D[C_AssembleON_ModifyON]   +\
                                   stats_D[C_AssembleOFF_ModifyON]
                    
            Log_S = "number of permissions-based PDF files %d "\
                    "(AssembleOFF_ModifyOFF=%d,"\
                    "AssembleON_ModifyOFF=%d,"\
                    "AssembleON_ModifyON=%d,"\
                    "AssembleOFF_ModifyON=%d)" %\
                    (num_permissions_PDFs,
                    stats_D[C_AssembleOFF_ModifyOFF],
                    stats_D[C_AssembleON_ModifyOFF],
                    stats_D[C_AssembleON_ModifyON],
                    stats_D[C_AssembleOFF_ModifyON])

            lock.release()
            #-- end of exclusive zone --

            self.log(Level.INFO, Log_S)
            self.postIngestMessage(self.getModuleName(), Log_S)

            # write the dict with results to a CSV file 
            # (if the option to do so is set)
            if self.local_settings.get_create_csv_file_flag():
                # CSV holding the list of SIGNED pdf files
                self.write_signed_dict2CSVfile()

                # CSV file holding the list of PDF file with special 
                # User Access permissions
                self.write_permissions_dict2CSVfile()

        #--------------------------------------------------
        # DEBUG - close special log files
        #--------------------------------------------------
        if C_Log_Level >= C_LOG_FILE_DETAILS:
            lock = threading.Lock()
            lock.acquire()
            #---
            # Close special logfiles
            close_log_file(
                    FindSignedPDFsFilesIngestModuleFactory.g_log_pdf_names_F)
            FindSignedPDFsFilesIngestModuleFactory.g_log_pdf_names_F = None

            close_log_file(
                FindSignedPDFsFilesIngestModuleFactory.g_log_not_pdf_names_F)
            FindSignedPDFsFilesIngestModuleFactory.g_log_not_pdf_names_F = None

            close_log_file(
                FindSignedPDFsFilesIngestModuleFactory.g_log_every_fnames_F)
            FindSignedPDFsFilesIngestModuleFactory.g_log_every_fnames_F = None

            close_log_file(
             FindSignedPDFsFilesIngestModuleFactory.g_log_all_counted_fnames_F)
            FindSignedPDFsFilesIngestModuleFactory.g_log_all_counted_fnames_F=None
            #---
            lock.release()


    #--------------------------------------------------------------------
    # Write the result of signed DICT to CSV file
    # @return 
    # 2017-08-07
    #--------------------------------------------------------------------
    def write_signed_dict2CSVfile(self):
        """Dump the dictionary holding results to CSV file"""

        case_name_S = Case.getCurrentCase().getName()
        
        # build the CSV filename 
        ISO_datetime_S = get_now_timestamp_S()

        # Create name for CSV file
        filename = "%s_SIGN_%s.csv" % (case_name_S,ISO_datetime_S)

        # make it a global path
        full_path_filename = os.path.join(self.getWorkDir(),filename)

        # CSV separator
        col_sep_S = ";"

        # DEBUG
        Debug_S = "full_path_filename='%s'" % (full_path_filename)
        self.log(Level.INFO, Debug_S)
        Debug_S = "filenamelen='%d'" % (len(full_path_filename))
        self.log(Level.INFO, Debug_S)

        #----------------------------------------
        # Dump the dictionary to CSV file
        # This is done with a lock
        #----------------------------------------
        lock = threading.Lock()
        lock.acquire()
        ret = pdf_signed_dict2CSVfile(
            FindSignedPDFsFilesIngestModuleFactory.g_fullPathPDFFiles_D,
            col_sep_S, full_path_filename)
        lock.release()

        # DEBUG
        Log_S = "CSV file created '%s'" % (filename)
        self.log(Level.INFO, Log_S)
        
        # Post to central module
        self.postIngestMessage(self.getModuleName(),Log_S)

        return ret

    #--------------------------------------------------------------------
    # Write the result of signed DICT to CSV file
    # @return 
    # 2017-08-07
    #--------------------------------------------------------------------
    def write_permissions_dict2CSVfile(self):
        """Dump the dictionary holding results to CSV file"""

        case_name_S = Case.getCurrentCase().getName()
        
        # build the CSV filename 
        ISO_datetime_S = get_now_timestamp_S()

        # Create name for CSV file to hold list of 
        # PDF file with interesting owner PERMISSIONS
        filename = "%s_PERMS_%s.csv" %\
                (case_name_S,ISO_datetime_S)

        # make it a global path
        full_path_filename = os.path.join(self.getWorkDir(),filename)

        # CSV separator
        col_sep_S = ";"

        # DEBUG
        Debug_S = "[Permissions] full_path_filename='%s'" % (full_path_filename)
        self.log(Level.INFO, Debug_S)
        Debug_S = "[Permissions] filenamelen='%d'" % (len(full_path_filename))
        self.log(Level.INFO, Debug_S)

        #----------------------------------------
        # Dump dict with results in CSV 
        # format to full_path_filename
        #----------------------------------------
        lock = threading.Lock()
        lock.acquire()
        ret = pdf_permissions_dict2CSVfile(
                FindSignedPDFsFilesIngestModuleFactory.g_permission_PDFs_D,
                                        col_sep_S, full_path_filename)
        lock.release()

        # DEBUG
        Log_S = "Permissions CSV file created '%s'" % (filename)
        self.log(Level.INFO, Log_S)
        
        # Post to central module
        self.postIngestMessage(self.getModuleName(),Log_S)

        return ret


    #--------------------------------------------------------------------
    # Increment the shared variable g_signedPDFFiles_count
    # @param 
    # @return
    # 2018-05-15
    #--------------------------------------------------------------------
    def safe_inc_signedPDFFiles_count(self):
        """Increment, with a lock, the shared class 
           variable g_signedPDFFiles_count"""
        # Acquire lock
        lock = threading.Lock()
        lock.acquire()
        FindSignedPDFsFilesIngestModuleFactory.g_signedPDFFiles_count =\
                FindSignedPDFsFilesIngestModuleFactory.g_signedPDFFiles_count+1
        lock.release()

    #--------------------------------------------------------------------
    # Increment the shared variable g_PDFFilesInserted_count
    # @param 
    # @return
    # 2018-05-15
    #--------------------------------------------------------------------
    def safe_inc_PDFFilesInserted_count(self):
        """Increment, with a lock, the shared class 
           variable g_PDFFilesInserted_count"""
        # Acquire lock
        lock = threading.Lock()
        lock.acquire()
        FindSignedPDFsFilesIngestModuleFactory.g_PDFFilesInserted_count =\
             FindSignedPDFsFilesIngestModuleFactory.g_PDFFilesInserted_count+1
        lock.release()

    #--------------------------------------------------------------------
    # Where the analysis is done.  
    # Each file will be passed into here.
    # The 'file' object being passed in is of type:
    # org.sleuthkit.datamodel.AbstractFile.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/4.3/
    #            classorg_1_1sleuthkit_1_1datamodel_1_1_abstract_file.html
    #
    # NOTE: autopsy engines creates a pool of threads to process the files
    # SEE:
    # - self.context.ingest.getNumberOfFileIngestThreads()
    # - numberOfFileIngestThreads;
    #  final int org.sleuthkit.autopsy.ingest.IngestManager.
    #                               MAX_NUMBER_OF_FILE_INGEST_THREADS = 16
    # public int getNumberOfFileIngestThreads() {
    #   return numberOfFileIngestThreads;
    # }
    #--------------------------------------------------------------------
    def process(self, file):

        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        if self.context.fileIngestIsCancelled():
            return IngestModule.ProcessResult.OK

        # Acquire lock
        #---
        lock = threading.Lock()
        lock.acquire()

        # Write to DEBUG log file
        if C_Log_Level >= C_LOG_FILE_DETAILS:
            Msg_S = "%d:'%s'" %\
                (FindSignedPDFsFilesIngestModuleFactory.g_files_count,
                        file.getName())
            file_F = \
               FindSignedPDFsFilesIngestModuleFactory.g_log_every_fnames_F
            write_log_file(file_F, Msg_S)
        #---
        lock.release()

        #------------------------------------------------------------
        # Skip non-files
        #------------------------------------------------------------
        if (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS):
            # Debug 
            Log_S = "file '%s' is UNALLOC_BLOCKS" % (file.getName())
            self.log(Level.INFO, Log_S)

            return IngestModule.ProcessResult.OK

        if (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS):
            # Debug 
            Log_S = "file '%s' is UNUSED_BLOCKS" % (file.getName())
            self.log(Level.INFO, Log_S)

            return IngestModule.ProcessResult.OK

        if( file.isFile() == False ):
            # Debug 
            Log_S = "file '%s' is flagged as NOT file" % (file.getName())
            self.log(Level.INFO, Log_S)

            return IngestModule.ProcessResult.OK

        # alias for Module name
        ModuleName = FindSignedPDFsFilesIngestModuleFactory.moduleName

        #--------------------------------------------------------------------
        # https://docs.python.org/2/library/threading.html
        # http://www.jython.org/jythonbook/en/1.0/Concurrency.html
        # https://stackoverflow.com/questions/68645/...
        #                            are-static-class-variables-possible
        #====================================================================
        # Acquire lock
        lock = threading.Lock()
        #---
        lock.acquire()
        FindSignedPDFsFilesIngestModuleFactory.g_files_count += 1

        # Write to DEBUG log file
        if C_Log_Level >= C_LOG_FILE_DETAILS:
            Msg_S = "%d:'%s'" %\
                (FindSignedPDFsFilesIngestModuleFactory.g_files_count,
                        file.getName())
            file_F = \
               FindSignedPDFsFilesIngestModuleFactory.g_log_all_counted_fnames_F
            write_log_file(file_F, Msg_S)
        #---
        lock.release()

        # Log
        if C_Log_Level >= C_LOG_ANALYZE:
            JobID_S = "%s" % (self.context.getJobId())
            Log_S = "JobID:%s --- analyzing file '%s' (file #%d)" %\
                (JobID_S, file.getName(), 
                        FindSignedPDFsFilesIngestModuleFactory.g_files_count)
            self.log(Level.INFO, Log_S)


        if not self.is_pdf_file(file):
            # A file, but not a PDF file...
            lock = threading.Lock()
            lock.acquire()
            #---
            FindSignedPDFsFilesIngestModuleFactory.g_NotPDFFiles_count += 1

            # Special log files ON?
            if C_Log_Level >= C_LOG_FILE_DETAILS:
                Msg_S = "%d:'%s'" %\
                (FindSignedPDFsFilesIngestModuleFactory.g_NotPDFFiles_count,
                        file.getName())
                file_F = \
                  FindSignedPDFsFilesIngestModuleFactory.g_log_not_pdf_names_F
                write_log_file(file_F, Msg_S)
            #---
            lock.release()

            if C_Log_Level >= C_LOG_FILE_DETAILS:
                Log_S = "not a PDF file '%s'" % (file.getName())
                self.log(Level.INFO, Log_S)

            # not (considered as) a PDF file
            return IngestModule.ProcessResult.OK

        # another PDF file: update the counter
        lock = threading.Lock()
        lock.acquire()
        #---
        FindSignedPDFsFilesIngestModuleFactory.g_PDFFiles_count += 1

        if C_Log_Level >= C_LOG_FILE_DETAILS:
            # Special DEBUG log file
            Msg_S = "%d:'%s'" %\
                (FindSignedPDFsFilesIngestModuleFactory.g_PDFFiles_count,
                        file.getName())
            file_F = \
               FindSignedPDFsFilesIngestModuleFactory.g_log_pdf_names_F
            write_log_file(file_F, Msg_S)

        #---
        lock.release()
        
        filename = file.getName()

        if C_Log_Level >= C_LOG_FILE_DETAILS:
            # LOG
            msg_S = "Processing PDF file: '" + filename +\
                "' (#%d)" %\
                (FindSignedPDFsFilesIngestModuleFactory.g_PDFFiles_count)
            self.log(Level.INFO, msg_S)

        # Still here? PDF file
        filePath_S = file.getParentPath()
        fullFilePath_S = os.path.join(filePath_S, filename)

        # Prepare the paths for copying the file
        temp_dir_filepath = string.replace(filePath_S,'/','_')
        temp_filepath = temp_dir_filepath + filename
        temp_fullFilepath = os.path.join(self.getWorkDir(), temp_filepath)

        # save the full file name in the dictionary 
        # Acquire lock
        lock = threading.Lock()
        lock.acquire()
        FindSignedPDFsFilesIngestModuleFactory.g_fullPathPDFFiles_D[fullFilePath_S] = [temp_fullFilepath]
        lock.release()

        # Does the file already exist? (i.e, was it copied previously)
        if not os.path.isfile(temp_fullFilepath):
            # File does not exist: Copy the file
            ## ContentUtils.writeToFile(file, java.io.File(temp_fullFilepath))

            try:
                ContentUtils.writeToFile(file, java.io.File(temp_fullFilepath))
                msg_S = "file '%s' copied" % (filename)
                self.log(Level.INFO, msg_S)
            except:

                err_S = "Error in copying file '%s': %s (%s)" %\
                        (filename, sys.exc_info()[0], sys.exc_info()[1])
                # err_S = "problems in copying file '%s'" % (filename)
                self.log(Level.SEVERE, err_S)

                # We're leaving - file could not be copied
                return IngestModule.ProcessResult.ERROR

        else:
            # DEBUG
            Log_S = "file '%s' already exists" % (temp_fullFilepath)
            self.log(Level.INFO, Log_S)

        #----------------------------------------
        # Is the PDF file digitally signed? 
        #----------------------------------------
        # Launch EXE to determine if the PDF file is signed or not
        EXE_signer_path = self.local_settings.get_EXE_signer_path()
        ret_signed_code = is_pdf_signed(EXE_signer_path, temp_fullFilepath)

        #------------------------------
        # Append result to dictionary
        # (under lock)
        #------------------------------
        lock = threading.Lock()
        lock.acquire()
        FindSignedPDFsFilesIngestModuleFactory.g_fullPathPDFFiles_D[fullFilePath_S].append(ret_signed_code)

        ret_code_S = pdf_code_2_str(ret_signed_code)

        FindSignedPDFsFilesIngestModuleFactory.g_fullPathPDFFiles_D[fullFilePath_S].append(ret_code_S)
        lock.release()

        # DEBUG
        if C_Log_Level >= C_LOG_FILE_DETAILS:
            Log_S = "'%s': %d (ret_signed) (%s)" %\
                (filename,ret_signed_code,ret_code_S)
            self.log(Level.INFO, Log_S)

        add_as_artifact = False

        if ret_signed_code == 0:
            Info_S = "properly signed"
            # Safe increment of shared variable g_signedPDFFiles_count
            self.safe_inc_signedPDFFiles_count()
            add_as_artifact = True
        elif ret_signed_code >= 20 and\
                ret_signed_code <= 66:
            Info_S = "signed but with problems"

            # Safe increment of shared variable g_signedPDFFiles_count
            self.safe_inc_signedPDFFiles_count()
            add_as_artifact = True

        elif ret_signed_code == 10:
            Info_S = "NOT signed"

        else:
            Info_S = "problems"

        # DEBUG
        Log_S = "\n>>>SIGNED? %d  %s ('%s'):'%s'"%\
            (ret_signed_code,Info_S,ret_code_S,filename)
        self.log(Level.INFO, Log_S)

        #----------------------------------------
        # Check for duplicates
        #----------------------------------------
        C_NO_DUPLICATE = self.local_settings.get_insert_duplicate_flag()

        artifactType = \
                BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT

        existingArtifacts_L = file.getArtifacts(artifactType)
        num_artifacts = len(existingArtifacts_L)
        if add_as_artifact:
            # Check whether the file is already in the ArrayList
            if existingArtifacts_L:
                # LOG
                Msg_S = "file '%s' already exists as artifact" % (filename)
                for artifact in existingArtifacts_L:
                    S = "'%s'" % (artifact)
                    Msg_S = Msg_S + "\n" + S
                self.log(Level.INFO, Msg_S)

                if C_NO_DUPLICATE == True:
                    # the file already exists and we don't want duplicates
                    add_as_artifact = False

                    Msg_S = "skipping file '%s': already exists" % (filename)
                    self.log(Level.INFO, Msg_S)
                else:
                    Msg_S = "adding file '%s' that already exists" % (filename)
                    self.log(Level.WARNING, Msg_S)

        file_was_added = False
        if add_as_artifact:
            # File is gonna be inserted
            # DEBUG
            Msg_S = "***ADDING*** file '%s'" % (filename)
            self.log(Level.INFO, Msg_S)

            # Concurrently update the shared variable g_PDFFilesInserted_count 
            self.safe_inc_PDFFilesInserted_count()

            # yes, add as attribute
            art = file.newArtifact(
                    BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)

            att = BlackboardAttribute(
                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), 
                ModuleName, ret_code_S)
            art.addAttribute(att)

            file_was_added = True

        #----------------------------------------
        # PDF permissions module
        # Analysis done through exiftool
        #----------------------------------------
        if not file_was_added:
            # Check whether the file is already in the ArrayList
            if existingArtifacts_L and (C_NO_DUPLICATE==True):
                # file already exists and we don't want duplicates
                add_as_artifact = False
                # LOG
                Msg_S ="[PDF ACCESS] skipping file '%s': already exists" %\
                (filename)
                self.log(Level.INFO, Msg_S)
            else:
                path_tmp_dir = ""
                EXE_exiftool_path = self.local_settings.get_EXE_exiftool_path()
                ret_L = self.get_pdf_permissions(EXE_exiftool_path,
                                                            temp_fullFilepath)
                if len(ret_L) == 3:
                    User_Access_flag = ret_L[0]
                    User_Access_code = ret_L[1]
                    Encryption_flag  = ret_L[2]


                    # DEBUG ---------------------------------------------------
                    Msg_S = "[file '%s'] User_Access_flag=%s,"\
                         "User_Access_code=%s,"\
                         "Encryption_flag='%s'"%\
                        (filename, User_Access_flag, 
                                User_Access_code, Encryption_flag)
                    self.log(Level.INFO, Msg_S)
                    # DEBUG ---------------------------------------------------

                    # DEBUG ---------------------------------------------------
                    Msg_S = "AQUI:[file '%s'] User_Access_code & C_ASSEMBLE: %s,"\
                            "User_Access_code & C_MODIFY: %s"%\
                        (filename, User_Access_code & C_ASSEMBLE, 
                         User_Access_code & C_MODIFY)
                    self.log(Level.INFO, Msg_S)


                    # DEBUG ---------------------------------------------------
                    Msg_S = "AQUI2:[file '%s'] Encryption_flag=%s,"\
                            "User_Access_flag=%s,"\
                       "is_interesting_user_access(User_Access_code=%s)=%s"%\
                        (filename, Encryption_flag, User_Access_flag, 
                                User_Access_code,
                                is_interesting_user_access(User_Access_code))
                    self.log(Level.INFO, Msg_S)
                    #----------------------------------------------------------


                    # DEBUG ---------------------------------------------------
                    if (Encryption_flag or User_Access_flag) and\
                        (is_interesting_user_access(User_Access_code)):
                        # we have something interesting
                        user_access_S =\
                                user_access_numeric_to_str(User_Access_code)

                        # Concurrently update the shared 
                        # variable g_PDFFilesInserted_count 
                        self.safe_inc_PDFFilesInserted_count()
                        
                        Encryption_S = boolean2str(Encryption_flag)
                        User_S = boolean2str(User_Access_flag)

                        # Add to m_permission_PDFs_D dictionary
                        self.add_to_permissions_PDFs_D(fullFilePath_S, 
                                Encryption_S, User_S, user_access_S)

                        # DEBUG
                        Msg_S = "[file '%s'] Encryption_flag=%s,"\
                             "User_Access_flag=%s,"\
                             "user_Access_S='%s'"%\
                            (filename,Encryption_S,User_S,user_access_S)
                        self.log(Level.INFO, Msg_S)

                        # Update stat dictionary
                        ## --start of exclusive zone--
                        lock = threading.Lock()
                        lock.acquire()
                        # Alias since the "Find....g_permission_Stats_D" 
                        # identifier is (awfully) long
                        alias_g_permission_Stats_D =\
                          FindSignedPDFsFilesIngestModuleFactory.g_permission_Stats_D
                        alias_g_permission_Stats_D[user_access_S]=\
                                alias_g_permission_Stats_D[user_access_S] + 1
                        lock.release()
                        ## --end of exclusive zone--


                        # yes, add as attribute
                        art = file.newArtifact(
                  BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)

                        att = BlackboardAttribute(
                  BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), 
                            ModuleName, user_access_S)
                        art.addAttribute(att)

                        file_was_added = True

        if file_was_added:
            try:
                # index the artifact for keyword search
                blackboard.indexArtifact(art)
            except Blackboard.BlackboardException as e:
                Except_S = "Error indexing artifact '%s'" %\
                        (art.getDisplayName())
                self.log(Level.SEVERE, Except_S)

            # Fire an event to notify the UI and others 
            # that there is a new artifact  
            IngestServices.getInstance().fireModuleDataEvent(
             ModuleDataEvent(ModuleName, 
               BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT,None))

        return IngestModule.ProcessResult.OK


    #--------------------------------------------------------------------
    # Add permissions data of fullFilename to m_permission_PDFs_D dict.
    # @param fullFilename       [IN] full path name of file. Used as key of dict
    # @param encrypt_flag_S     [IN] boolean status of encrypt flag
    # @param user_access_flag_S [IN] boolean status of encrypt flag
    # @return
    # 2017-09-27
    #--------------------------------------------------------------------
    def add_to_permissions_PDFs_D(self, fullFilename, encrypt_flag_S,
                                            user_access_flag_S, user_access_S):
        """Add fullFilename to 
           FindSignedPDFFilesIngestModule.g_permission_PDFs_D dict"""

        lock = threading.Lock()
        lock.acquire()

        FindSignedPDFsFilesIngestModuleFactory.g_permission_PDFs_D[fullFilename] = [encrypt_flag_S]
        FindSignedPDFsFilesIngestModuleFactory.g_permission_PDFs_D[fullFilename].append(user_access_flag_S)
        FindSignedPDFsFilesIngestModuleFactory.g_permission_PDFs_D[fullFilename].append(user_access_S)

        lock.release()

    #--------------------------------------------------------------------
    # Post a message to the ingest messages in box.
    # @param module_S [IN] name of module
    # @param msg_S [IN] message to post
    # @return None
    # 2017-08-04
    #--------------------------------------------------------------------
    def postIngestMessage(self,module_S,msg_S):
        """post a message into AUTOPSY message GUI logger"""
        # Create the message
        message = IngestMessage.createMessage( 
        IngestMessage.MessageType.DATA,module_S, msg_S)
        # Post the message
        IngestServices.getInstance().postMessage(message)

    #--------------------------------------------------------------------
    # Method that returns True if file is considered to be a PDF file, 
    # false otherwise.
    # TODO: right now, we are only checking the extension, which can be
    # misleading (false positive and false negative extension). 
    # We should inspect the first byte of the file, looking for %PDF...
    # @param file [IN] file to be checked
    # @return True if the file is considered a PDF file, False otherwise
    # Patricio R. Domingues
    # 2017-08-02
    #--------------------------------------------------------------------
    def is_pdf_file(self,file):
        """check whether file is a PDF file"""
        filename, file_extension = os.path.splitext(file.getName())

        # DEBUG
        if C_Log_Level >= C_LOG_FILE_DETAILS:
            Log_S = "[%s] basename = '%s'" % (file.getName(), filename)
            self.log(Level.INFO, Log_S)

            Log_S = "[%s] extension = '%s'" % (file.getName(), file_extension)
            self.log(Level.INFO, Log_S)

        if file.getSize() == 0:
            # empty file?
            return False

        if len(file_extension) == 0:
            # no extension 
            return False

        if file_extension.lower() == ".pdf":
            # extension is pdf: bingo!
            ## FIXME: we should check the first 5 bytes, looking for "%PDF-"
            return True

        # still here? 
        return False

    #----------------------------------------------------------------
    # @param 
    # @return
    # 2017-09-03
    #----------------------------------------------------------------
    def get_pdf_permissions(self,path_exiftool, path_pdf_file):
        """return the permissions for the PDF file 'path_pdf_file'"""

        # Needed string
        # '-a  -UserAccess -Encryption -s %s -j' % (path_pdf_file)
        exif_process = Popen([path_exiftool, 
            "-a", "-UserAccess", "-Encryption", "-s", path_pdf_file, "-j"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        exif_outcode = exif_process.returncode

        Encryption_flag = False
        User_Access_flag = False
        User_Access_code_binary = 0

        stdout_json_S = exif_process.stdout.read()

        try:
            data_L = json.loads(stdout_json_S)
        except Exception, e:
            # Something went wrong. Bail out.
            Except_S = "Exception: can't json loads '%s'" % (e)
            self.log(Level.WARNING, Except_S)

            return [User_Access_flag,User_Access_code_binary,Encryption_flag]

        data_len = len(data_L)
        if data_len == 0:
            # DEBUG
            Warning_S = "no data returned by exiftool for file '%s'" %\
                (path_pdf_file)
            self.log(Level.INFO, Warning_S)
            return [User_Access_flag,User_Access_code_binary,Encryption_flag]

        data_D = data_L[0]

        C_ENCRYPTION_key="Encryption"
        if C_ENCRYPTION_key in data_D:
            Encryption_value = data_D[C_ENCRYPTION_key]
            Encryption_flag = True
    
        C_USER_ACCESS_key="UserAccess"
        if C_USER_ACCESS_key in data_D:
            User_Access_value_S = data_D[C_USER_ACCESS_key]
            User_Access_flag = True

            User_Access_code_binary = user_access_to_int( User_Access_value_S )

        return [User_Access_flag,User_Access_code_binary,Encryption_flag]

#====================================================================
# PANEL-related classes
#====================================================================
#--------------------------------------------------------------------
# Class
# 2017-08-20
#--------------------------------------------------------------------
class Process_FindSignedPDFFilesWithUISettings(IngestModuleIngestJobSettings):
    """Class that deals with PANEL settings and alike"""

    serialVersionUID = 1L

    #--------------------------------------------------------------------
    # constructor. Sets the default value.
    # 2017-08-21
    #--------------------------------------------------------------------
    def __init__(self):
        # Note: on Autopsy 4.4.1, the jython interpreter complains
        # about the non existence of the self.m_insert_duplicate flag.
        self.m_insert_duplicate = None
        pass
        # No init is done here. Init is done through the DB3 database.

    # getter for serialVersionUID
    def getVersionNumber(self):
        return serialVersionUID

    def get_insert_duplicate_flag(self):
        return self.m_insert_duplicate

    def set_insert_duplicate_flag(self,flag):
        self.m_insert_duplicate = flag

    def get_create_csv_file_flag(self):
        return self.m_create_csv_file

    def set_create_csv_file_flag(self,flag):
        self.m_create_csv_file = flag

    def get_EXE_signer_path(self):
        return self.m_EXE_signer_path

    def set_EXE_signer_path(self,pathExe):
        self.m_EXE_signer_path = pathExe

    def get_EXE_exiftool_path(self):
        return self.m_EXE_exiftool_path

    def set_EXE_exiftool_path(self,exiftoolExe):
        self.m_EXE_exiftool_path = exiftoolExe

#--------------------------------------------------------------------
# Class that controls the configuration panels
# 2017-08-20
#--------------------------------------------------------------------
class Process_FindSignedPDFFilesWithUISettingsPanel(
                        IngestModuleIngestJobSettingsPanel):
    """Class to create the user interface shown to the user"""
    def __init__(self,settings):
        self.local_settings = settings
        self.initComponents()
        self.customizeComponents()

    def checkBoxEvent(self, event):
        # duplicate insert
        if self.checkbox.isSelected():
            self.local_settings.set_insert_duplicate_flag(True)
        else:
            self.local_settings.set_insert_duplicate_flag(False)

        # Create CSV file
        if self.checkbox_create_file.isSelected():
            self.local_settings.set_create_csv_file_flag(True)
        else:
            self.local_settings.set_create_csv_file_flag(False)

    #--------------------------------------------------------------------
    # onClick even handler for Find_Program_Exec_BTN
    # @param e [IN] event
    # @return This is an event handler. It doesn't return explicitly.
    # 2017-08-22
    #--------------------------------------------------------------------
    def onClickVerifier(self,e):
        """onClick event handler for Find_Program_Exec_BTN button"""
        chooseFile = JFileChooser()
        filter_obj = FileNameExtensionFilter("EXE",["exe"])
        chooseFile.addChoosableFileFilter(filter_obj)

        ret = chooseFile.showDialog(self.panel0, "Select JSIGN EXE")
        if ret == JFileChooser.APPROVE_OPTION:
            file = chooseFile.getSelectedFile()
            Canonical_file = file.getCanonicalPath()
            self.Program_Executable_TF.setText(Canonical_file)

    #--------------------------------------------------------------------
    # onClick even handler for Find_Exiftool_BTN
    # @param e [IN] event
    # @return This is an event handler. It doesn't return explicitly.
    # 2017-09-24
    #--------------------------------------------------------------------
    def onClickExiftool(self,e):
        """onClick event handler for Find_Exiftool_BTN"""
        # NOTE: calling JFileChooser() crashes autopsy...
        # 2017-09-24
        try:
            chooseFile = JFileChooser()
            filter_obj = FileNameExtensionFilter("EXE",["exe"])
            chooseFile.addChoosableFileFilter(filter_obj)

            ret = chooseFile.showDialog(self.panel0, "Select exiftool EXE")
            if ret == JFileChooser.APPROVE_OPTION:
                file = chooseFile.getSelectedFile()
                Canonical_file = file.getCanonicalPath()
                self.Program_Exiftool_TF.setText(Canonical_file)
        except e:
            Err_S = "Error within onClickExiftool"
            self.Error_Message.setText(Err_S)


    #--------------------------------------------------------------------
    # Reads setting from the setting database
    # 2017-08-23
    #--------------------------------------------------------------------
    def check_Database_entries(self):
        head, tail = os.path.split(os.path.abspath(__file__)) 
        settings_db = os.path.join(head, C_DB_NAME)
        try: 
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection("jdbc:sqlite:%s" % settings_db)
        except SQLException as e:
            Err_S = "Error opening setting DB '%s'" % (C_DB_NAME)
            self.Error_Message.setText(Err_S)

        C_SET_VALUE="Setting_Value"
        try:
            stmt = dbConn.createStatement()
            SQL_Statement = 'Select Setting_Name, Setting_Value from settings;' 
            resultSet = stmt.executeQuery(SQL_Statement)

            while resultSet.next():

                setting_name_S = resultSet.getString("Setting_Name")

                # Signer EXE name
                if setting_name_S == C_SIGNER_EXEC_FIELD:
                    signer_exec_path = resultSet.getString(C_SET_VALUE)
                    self.Program_Executable_TF.setText(signer_exec_path)
                    # Set the appropriate field
                    self.local_settings.set_EXE_signer_path(signer_exec_path)

                # Don't insert duplicates
                if setting_name_S == C_DONT_INSERT_DUPLICATES:
                    dont_insert_duplicates = resultSet.getString(C_SET_VALUE)
                    flag = str2boolean(dont_insert_duplicates)
                    self.local_settings.set_insert_duplicate_flag(flag)

                # Create CSV file
                if setting_name_S == C_CREATE_CSV_FILE:
                    create_CSV_file = resultSet.getString(C_SET_VALUE)
                    flag = str2boolean(create_CSV_file)
                    self.local_settings.set_create_csv_file_flag(flag)

                # exiftool EXE name
                if setting_name_S == C_EXIFTOOL_EXEC_FIELD:
                    exiftool_path = resultSet.getString(C_SET_VALUE)
                    self.Program_Exiftool_TF.setText(exiftool_path)
                    self.local_settings.set_EXE_exiftool_path(exiftool_path)
            
            # only set a "read successfully" if message site is empty
            current_err_msg_S = self.Error_Message.getText()
            if len(current_err_msg_S) == 0:
                self.Error_Message.setText("Settings read successfully")

        except SQLException as e:
            self.Error_Message.setText("Error reading settings database")

        stmt.close()
        dbConn.close()

    #--------------------------------------------------------------------
    # Save entries from the GUI to the database.
    # 2017-08-23
    #--------------------------------------------------------------------
    def SaveSettings(self, e):
        """Save entries from GUI to the database"""
        head, tail = os.path.split(os.path.abspath(__file__)) 
        settings_db = os.path.join(head,C_DB_NAME)

        # Check whether the given path for the files are correct
        Signer_Exec_Path = self.Program_Executable_TF.getText()
        Exiftool_Exec_Path = self.Program_Exiftool_TF.getText()

        if not os.path.exists(Signer_Exec_Path):
            Err_S = "ERROR: Cannot find SIGNER executable" 
        elif not os.path.exists(Exiftool_Exec_Path):
            Err_S = "ERROR: Cannot find ExifTool executable'" 
        else:
            Err_S = ""

        try: 
            Class.forName("org.sqlite.JDBC").newInstance()
            Jdbc_S = "jdbc:sqlite:%s"  % settings_db
            dbConn = DriverManager.getConnection(Jdbc_S)
        except SQLException as e:
            Err_S = "Error opening setting DB '%s'" % (C_DB_NAME)
            self.Error_Message.setText(Err_S)


        try:
            stmt = dbConn.createStatement()

            # C_SIGNER_EXEC_FIELD
            SQL_Statement = 'UPDATE settings SET Setting_Value="%s" '\
                    'WHERE Setting_Name="%s";' %\
            (self.Program_Executable_TF.getText(),C_SIGNER_EXEC_FIELD) 
            stmt.execute(SQL_Statement)
            # DEBUG
            # Msg_S = "Settings Saved:'%s'" % (SQL_Statement)
        except SQLException as e:
            err_S = "Error inserting settings ('%s'): %s (%s)" %\
                      (SQL_Statement, sys.exc_info()[0], sys.exc_info()[1])
            self.Error_Message.setText(err_S)


        try:
            # C_EXIFTOOL_EXEC_FIELD
            SQL_Statement = 'UPDATE settings SET Setting_Value="%s" '\
                    'WHERE Setting_Name="%s";' %\
            (self.Program_Exiftool_TF.getText(),C_EXIFTOOL_EXEC_FIELD) 
            stmt.execute(SQL_Statement)

        except SQLException as e:
            err_S = "Error inserting settings ('%s'): %s (%s)" %\
                      (SQL_Statement, sys.exc_info()[0], sys.exc_info()[1])
            self.Error_Message.setText(err_S)

        try:
            # C_DONT_INSERT_DUPLICATES
            insert_duplicate_flag =\
                    self.local_settings.get_insert_duplicate_flag()
            insert_duplicate_flag_S = boolean2str(insert_duplicate_flag)

            SQL_Statement = 'UPDATE settings SET Setting_Value="%s" '\
                    'WHERE Setting_Name="%s";' %\
            (insert_duplicate_flag_S,C_DONT_INSERT_DUPLICATES) 
            stmt.execute(SQL_Statement)
        except SQLException as e:
            err_S = "Error inserting settings ('%s'): %s (%s)" %\
                      (SQL_Statement, sys.exc_info()[0], sys.exc_info()[1])
            self.Error_Message.setText(err_S)

        try:
            # C_CREATE_CSV_FILE
            create_CSV_file_flag =\
                    self.local_settings.get_create_csv_file_flag()
            create_CSV_file_flag_S = boolean2str(create_CSV_file_flag)

            SQL_Statement = 'UPDATE settings SET Setting_Value="%s" '\
                    'WHERE Setting_Name="%s";' %\
            (create_CSV_file_flag_S,C_CREATE_CSV_FILE)
            stmt.execute(SQL_Statement)
        except SQLException as e:
            err_S = "Error inserting settings ('%s'): %s (%s)" %\
                      (SQL_Statement, sys.exc_info()[0], sys.exc_info()[1])
            self.Error_Message.setText(err_S)

        if len(Err_S) == 0:
            Msg_S = "OK - settings saved"
        else:
            Msg_S = Err_S
        self.Error_Message.setText(Msg_S)


        stmt.close()
        dbConn.close()

        # Reread the current elements from the DB
        self.customizeComponents()

    #--------------------------------------------------------------------
    # Init the GUI components
    # 2017-08-22
    #--------------------------------------------------------------------
    def initComponents(self):

        self.panel0 = JPanel()

        self.rbgPanel0 = ButtonGroup()
        self.gbPanel0 = GridBagLayout()
        self.gbcPanel0 = GridBagConstraints()
        self.panel0.setLayout( self.gbPanel0 ) 

        # checkbox: do no insert duplicates
        self.checkbox = JCheckBox("Do not insert duplicate files",
                actionPerformed=self.checkBoxEvent)
        self.gbcPanel0.gridx = 0 
        self.gbcPanel0.gridy = 1 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.checkbox, self.gbcPanel0 ) 
        self.panel0.add( self.checkbox ) 

        # checkbox: create CSV file with list of 
        # all PDFs and respective status
        self.checkbox_create_file =\
                JCheckBox("Create CSV file with PDF status",
                                actionPerformed=self.checkBoxEvent)

        self.gbcPanel0.gridx = 0 
        self.gbcPanel0.gridy = 2 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints(self.checkbox_create_file,self.gbcPanel0)

        self.panel0.add(self.checkbox_create_file)

        #-------------------------------
        # EXE path of signer/verfier.exe
        #-------------------------------
        # text field
        self.Program_Executable_TF = JTextField(25) 
        self.Program_Executable_TF.setEnabled(True)

        # Set the text field with the path of JVERIFIER
        self.Program_Executable_TF.setText(C_PATH_VERIFIER)
       
        self.gbcPanel0.gridx = 0 
        self.gbcPanel0.gridy = 3 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints(self.Program_Executable_TF,self.gbcPanel0)

        self.panel0.add(self.Program_Executable_TF)

        #-------------------------------
        # File changer (verifier.exe)
        #-------------------------------
        self.Find_Program_Exec_BTN =\
                JButton( "Verifier EXE", actionPerformed=self.onClickVerifier)
        self.Find_Program_Exec_BTN.setEnabled(True)
        self.rbgPanel0.add( self.Find_Program_Exec_BTN )
        self.gbcPanel0.gridx = 6
        self.gbcPanel0.gridy = 3
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints(self.Find_Program_Exec_BTN,self.gbcPanel0)
        self.panel0.add( self.Find_Program_Exec_BTN )

        #-------------------------------
        # EXE path of exiftool
        #-------------------------------
        # text field
        self.Program_Exiftool_TF = JTextField(25) 
        self.Program_Exiftool_TF.setEnabled(True)

        # Set the text field with the path of EXIFTOOL
        self.Program_Exiftool_TF.setText(C_PATH_EXIFTOOL)

        self.gbcPanel0.gridx = 0 
        self.gbcPanel0.gridy = 4 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints(self.Program_Exiftool_TF,self.gbcPanel0)

        self.panel0.add(self.Program_Exiftool_TF)

        #-------------------------------
        # File changer (exiftool)
        #-------------------------------
        self.Find_Exiftool_BTN =\
                JButton( "exiftool EXE", actionPerformed=self.onClickExiftool)
        self.Find_Exiftool_BTN.setEnabled(True)
        self.rbgPanel0.add( self.Find_Exiftool_BTN )
        self.gbcPanel0.gridx = 6
        self.gbcPanel0.gridy = 4
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints(self.Find_Exiftool_BTN,self.gbcPanel0)
        self.panel0.add( self.Find_Exiftool_BTN )


        #------------------------------
        # Save settings button
        #------------------------------
        self.Save_Settings_BTN =\
                JButton("Save Settings", actionPerformed=self.SaveSettings)
        self.Save_Settings_BTN.setEnabled(True)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 5
        self.gbcPanel0.gridwidth = 1
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH
        self.gbcPanel0.weightx = 1
        self.gbcPanel0.weighty = 0
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Save_Settings_BTN, self.gbcPanel0 ) 
        self.panel0.add( self.Save_Settings_BTN ) 

        self.Error_Message = JLabel( "") 
        self.Error_Message.setEnabled(True)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 6
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints( self.Error_Message, self.gbcPanel0 ) 
        self.panel0.add( self.Error_Message ) 

        self.add(self.panel0)


    #--------------------------------------------------------------------
    # 2017-08-25
    #--------------------------------------------------------------------
    def customizeComponents(self):
        """customize components"""

        # Read values from DB
        self.check_Database_entries()

        insert_duplicate_flag = self.local_settings.get_insert_duplicate_flag()
        self.checkbox.setSelected(insert_duplicate_flag)

        create_csv_file_flag = self.local_settings.get_create_csv_file_flag()
        self.checkbox_create_file.setSelected(create_csv_file_flag)

    def getSettings(self):
        return self.local_settings

#====================================================================
# Functions
#====================================================================

#--------------------------------------------------------------------
# Checks whether fpath corresponds to an EXE file.
# NOTE: right now, it just checks whether fpath is a file or not.
# @param fpath [IN] full path of EXE to check
# @return True if considered as EXE, False otherwise.
# 2017-08-04
#--------------------------------------------------------------------
def is_exe(fpath):
    """https://stackoverflow.com/questions/377017/
                ...test-if-executable-exists-in-python\#377028"""
##    return os.path.isfile(fpath) and os.access(fpath, os.X_OK)
    return os.path.isfile(fpath)

#--------------------------------------------------------------------
# @param path_verifier [IN] path of EXE used to verify whether PDF is
#                           signed
# @param path_pdf_file [IN] PDF file to check
# @return returns the code that assesses the PDF file 'path_pdf_file'
# 2017-08-04
#--------------------------------------------------------------------
def is_pdf_signed(path_verifier,path_pdf_file):
    """check whether path_pdf_file is a signed PDF"""

    #------------------------------------------------------
    # C_Log_Level controls whether we capture or not 
    # STDOUT and STDERR from the "is digitally signed" test
    # If captured, STDOUT and STDERR is written in individual 
    # text files (two text files per EXEC: one for STDOUT and 
    # another one for STDERR).The text files are written in 
    # the case's TEMP directory
    #------------------------------------------------------
    if C_Log_Level >= C_LOG_EXEC_DETAILS:
        capture_stdout_stderr = True
    else:
        capture_stdout_stderr = False

    if not capture_stdout_stderr:
        # device null
        devnull = open(os.devnull, 'w')
        Out_fileno = devnull
        Err_fileno = devnull
    else:
        # We're going to capture STDOUT and STDERR to a file (FULL DEBUG)
        #-- start of exclusive zone --
        lock = threading.Lock()
        lock.acquire()
        Sequence_S = ("%05d") %\
                (FindSignedPDFsFilesIngestModuleFactory.g_PDFFiles_count)
        lock.release()
         #-- end of exclusive zone --


        # STDOUT and STDERR are going to be save in the case's TEMP directory
        temp_directory_S = Case.getCurrentCase().getTempDirectory()
        Out_filename = ("%s\out_is_signed_%s.txt") %\
                                    (temp_directory_S,Sequence_S)
        Err_filename = ("%s\err_is_signed_%s.txt") %\
                    (temp_directory_S,Sequence_S)

        Out_fileno = open(Out_filename,"w")
        Err_fileno = open(Err_filename,"w")

    ret_verifier = None

    if capture_stdout_stderr:
        ret_verifier = subprocess.call(
             [path_verifier,path_pdf_file],stdout=Out_fileno,stderr=Err_fileno)
        Out_fileno.write(("ret_verifier=%s") % (ret_verifier))
        Out_fileno.close()
        Err_fileno.close()
    else:
        ret_verifier = subprocess.call(
                  [path_verifier,path_pdf_file],stdout=devnull,stderr=devnull)
        devnull.close()

    return ret_verifier

#---------------------------------------
# Return codes for verifier.exe (JSign)
#---------------------------------------
C_PDF_code_D = { 
        0: 'SIG_STAT_CODE_INFO_SIGNATURE_VALID', 
        10: 'SIG_STAT_CODE_WARNING_NO_SIGNATURE',
        15: 'SIG_STAT_CODE_WARNING_ANY_WARNING',
        20: 'SIG_STAT_CODE_WARNING_NO_REVOCATION_INFO',
        30: 'SIG_STAT_CODE_WARNING_TIMESTAMP_INVALID',
        40: 'SIG_STAT_CODE_WARNING_NO_TIMESTAMP_TOKEN',
        50: 'SIG_STAT_CODE_WARNING_SIGNATURE_OCSP_INVALID',
        60: 'SIG_STAT_CODE_WARNING_CERTIFICATE_CANT_BE_VERIFIED',
        61: 'SIG_STAT_CODE_WARNING_CERTIFICATE_EXPIRED',
        62: 'SIG_STAT_CODE_WARNING_CERTIFICATE_NOT_YET_VALID',
        63: 'SIG_STAT_CODE_WARNING_CERTIFICATE_REVOKED',
        64: 'SIG_STAT_CODE_WARNING_CERTIFICATE_UNSUPPORTED_CRITICAL_EXTENSION',
        65: 'SIG_STAT_CODE_WARNING_CERTIFICATE_INVALID_STATE',
        66: 'SIG_STAT_CODE_WARNING_CERTIFICATE_PROBLEM',
        70: 'SIG_STAT_CODE_WARNING_UNSIGNED_CONTENT',
        101:'SIG_STAT_CODE_ERROR_FILE_NOT_READABLE',
        102: 'SIG_STAT_CODE_ERROR_UNEXPECTED_PROBLEM',
        105: 'SIG_STAT_CODE_ERROR_ANY_ERROR',
        110: 'SIG_STAT_CODE_ERROR_CERTIFICATION_BROKEN',
        120: 'SIG_STAT_CODE_ERROR_REVISION_MODIFIED' }

#--------------------------------------------------------------------
# Returns a string representation of a JSigner PDF's code
# @param pdf_code [IN] numerical PDF code
# @return String representation as shown on C_PDF_code_D dictionary
# 2017-08-07
#--------------------------------------------------------------------
def pdf_code_2_str(pdf_code):
    """returns a string representation of a PDF code"""
    if pdf_code in C_PDF_code_D:
        return C_PDF_code_D[pdf_code]
    else:
        return "ERROR: unkwown code"

#--------------------------------------------------------------------
# Write the content of dict_D as CSV content to the file 'filename'
# @param dict_D [IN] dictionary to write as CSV
# @param col_sep_S [IN] separator for CSV
# @param filename [IN] name of file to dump CSV
# @return 0 if filename exists, 1 otherwise
# 2017-08-07
#--------------------------------------------------------------------
def pdf_permissions_dict2CSVfile(dict_D, col_sep_S, filename):
    """write content of dict_D in CSV format to file 'filename'"""
    assert dict_D != None, "dict_D is None"
    assert filename is not None , "filename is empty string"
    assert len(filename)!=0 , "filename is empty string"

    if os.path.exists(filename):
        return 0

    # We use encoding compatible with Windows, others filenames 
    # with special characters are mangled, etc.
    # encoding_S = 'utf-16-le'
    # It works with utf-8 encoding.
    encoding_S = 'utf-8'
    S = "#FullPath%sEncryptFlag%sUserAccessFlag%sUserAccess_S%s" %\
            (col_sep_S,col_sep_S,col_sep_S,"\n")
    Header_S = S.encode(encoding_S)                         

    with open(filename,'w') as f:
        # NOTE: if the BOM_UTF16_LE is added to the file, the CSV file
        # becomes mangled when read by EXCEL (I didn't try with libreoffice
        # or other programs). So, for now, the BOM below is commented out.
        # 
        # f.write(codecs.BOM_UTF16_LE)


        # Write header
        f.write(Header_S)
        f.write("\n")

        for key,value in sorted(dict_D.iteritems()):

            value_0 = "(empty)"
            value_1 = "(empty)"
            value_2 = "(empty)"
            value_len = len(value)
            if value_len >= 1:
                value_0 = value[0]
            if value_len >= 2:
                value_1 = value[1]
            if value_len >= 3:
                value_2 = value[2]

            S = "%s%s%s%s%s%s%s%s" %\
                (key,col_sep_S,value_0,col_sep_S,
                               value_1,col_sep_S,
                               value_2,"\n")
            Row_S = S.encode(encoding_S)

            f.write(Row_S)

    # Done with the file
    f.close()

    return 1

#--------------------------------------------------------------------
# Write the content of dict_D as CSV content to the file 'filename'
# @param dict_D [IN] dictionary to write as CSV
# @param col_sep_S [IN] separator for CSV
# @param filename [IN] name of file to dump CSV
# @return 0 if filename exists, 1 otherwise
# 2017-08-07
#--------------------------------------------------------------------
def pdf_signed_dict2CSVfile(dict_D, col_sep_S, filename):
    """write content of dict_D in CSV format to file 'filename'"""
    assert dict_D != None, "dict_D is None"
    assert filename is not None , "filename is empty string"
    assert len(filename)!=0 , "filename is empty string"

    # Bails out if the CSV file already exists
    if os.path.exists(filename):
        return 0

    #Debug_S = "dict_D = '%s' (%d elements)" % (dict_D,len(dict_D))
    #assert 0, Debug_S

    # We use encoding compatible with Windows, others filenames 
    # with special characters are mangled, etc.
    # encoding_S = 'utf-16-le'
    # It works with utf-8 encoding.
    encoding_S = 'utf-8'
    S = "#FullPath%sTmpPath%sSignedCode%sSignedCodeString%s" %\
                        (col_sep_S,col_sep_S,col_sep_S,"\n")
    Header_S = S.encode(encoding_S)                         

    with open(filename,'w') as f:
        # NOTE: if the BOM_UTF16_LE is added to the file, the CSV file
        # becomes mangled when read by EXCEL (I didn't try with libreoffice
        # or other programs). So, the BOM below is commented out.
        # 
        # f.write(codecs.BOM_UTF16_LE)

        # Write header
        f.write(Header_S)
        f.write("\n")


        for key,value in sorted(dict_D.iteritems()):

            value_0 = "(empty)"
            value_1 = "(empty)"
            value_2 = "(empty)"
            value_len = len(value)
            if value_len >= 1:
                value_0 = value[0]
            if value_len >= 2:
                value_1 = value[1]
            if value_len >= 3:
                value_2 = value[2]


            S = "%s%s%s%s%s%s%s%s" %\
                (key,col_sep_S,value_0,col_sep_S,
                               value_1,col_sep_S,
                               value_2,"\n")
            Row_S = S.encode(encoding_S)

            f.write(Row_S)

    # Done with the file
    f.close()

    return 1



#--------------------------------------------------------------------
# Return the current (local) timestamp in ISO 
# format (YYYY-MM-DD_HHMinSec)
# @param None
# @return string with localtime in ISO format
# 2017-08-07
#--------------------------------------------------------------------
def get_now_timestamp_S():
    """return a timestamp string"""
##    now = time.localtime()
##    now_S = datetime.datetime.fromtimestamp(now).strftime('%Y%m%d_%H%M%S')

    now_S = time.strftime('%Y%m%d_%H%M%S')

    return now_S

#--------------------------------------------------------------------
# Function that receives a dictionary ('dict_D') and returns
# a string representing the dictionary.
# Example of calling the function:
#   dict2txt_S( dictionary )
# @param dict_D [IN] source dictionary for CSV
# @param add_num_elems [IN] if True, the string representing 
# "dict_D" starts with the number of elements existing on the dict.
# @return string representing dict_D
# 2017-08-19
#--------------------------------------------------------------------
def dict2txt_S(dict_D,add_num_elems=False):
    """returns a string representation of dict_D"""

    if add_num_elems:
        dict_S = "len=%s\n" % (len(dict_D))
    else:
        dict_S = ""
    for key,val in dict_D.iteritems():
        dict_S = dict_S + "\n'%s'='%s'" % (key,val)

    return dict_S

#--------------------------------------------------------------------
# @param flag_str [IN] string of which a boolean representation 
#                      is sought
# @return True or False (boolean)
# 2017-08-25
#--------------------------------------------------------------------
def str2boolean(flag_str):
    """returns boolean representation of flag_str"""
    flag_S = flag_str.lower()
    if flag_S == "true":
        return True
    elif flag_S == "false":
        return False

#--------------------------------------------------------------------
# @param flag [IN] flag of which a string return is wanted
# @return True of False accordingly to the 'flag' parameter
# 2017-08-25
#--------------------------------------------------------------------
def boolean2str(flag):
    """Returns string representation of boolean flag"""
    if flag:
        return "True"
    else:
        return "False"

#--------------------------------------------------------------------
# Receives user_access_S string with JSON content regarding the
# user access permission of the PDF file being analyzed.
# It returns a bit-wise integer code pointing out which permissions are
# ON (associated bit is 1) and which are not (associated bit is 0).
# @param user_access_to_S [IN] JSON string with user permissions
# @return
# 2017-09-03
#--------------------------------------------------------------------
def user_access_to_int(user_access_S):
    if len(user_access_S) == 0:
        return 0

    user_access_L = user_access_S.split(",")
    if len(user_access_L) == 0:
        # No content -- empty list
        return 0

    # Still here? Good
    ret_value = 0
    num_flags_on = 0
    for elem in user_access_L:
        # lower-case + remove any space from the string
        elem_lower = elem.lower().strip()
        if elem_lower in C_USER_ACCESS_D:
            ret_value = ret_value + C_USER_ACCESS_D[elem_lower]
            num_flags_on = num_flags_on + 1

            # DEBUG
            Msg_S = "[DEBUG] access '%s' ON (%d added to ret_value)" %\
                    (elem_lower,C_USER_ACCESS_D[elem_lower])
            print Msg_S

    # DEBUG
    Msg_S = "[DEBUG] %d flags ON (ret_value=%d)" % (num_flags_on, ret_value)
    print Msg_S

    return ret_value

# --------------------------------------------------------------------
# Convert numeric representation of user access to a 
# string representation.
# @param user_access_int [IN] 
# @return string with the representation of the giver user access 
# NOTE:
# Only assemble and modify permissions are considered
#
# AssembleON_ModifyON
# AssembleOFF_ModifyON
# AssembleON_ModifyON
# AssembleOFF_ModifyOFF
# 
# 2017-09-09
#--------------------------------------------------------------------

def user_access_numeric_to_str(user_access_int):
    """convert numeric user access to str for autopsy usage"""

    if ((user_access_int & C_ASSEMBLE)==0)and((user_access_int & C_MODIFY==0)):
        return C_AssembleOFF_ModifyOFF
    elif (user_access_int & C_ASSEMBLE) and (user_access_int & C_MODIFY):
        return C_AssembleON_ModifyON
    elif (user_access_int & C_ASSEMBLE) and ((user_access_int & C_MODIFY)==0):
        return C_AssembleON_ModifyOFF
    elif ((user_access_int & C_ASSEMBLE)==0) and (user_access_int & C_MODIFY):
        return C_AssembleOFF_ModifyON
    else:
        Msg_S = "Unexpected value for user_access_int: 0x%x" % (user_access_int)
        return Msg_S

#--------------------------------------------------------------------
# Returns True if user_access_code has one or none of 
# C_ASSEMBLE / C_MODIFY properties activated.
# @param user_access_code [IN] binary encoded user access code
# @return True / False
# 2017-09-22
#--------------------------------------------------------------------
def OLD_is_interesting_user_access(user_access_int):
    "return True if user_access_code interests us"""
    if user_access_int == 0:
        return False
    elif (user_access_int & C_ASSEMBLE) and (user_access_int & C_MODIFY):
        return True
    elif (user_access_int & C_ASSEMBLE) and ((user_access_int & C_MODIFY)==0):
        return True
    elif ((user_access_int & C_ASSEMBLE)==0) and (user_access_int & C_MODIFY):
        return True


#--------------------------------------------------------------------
# Returns True if user_access_code has one or none of 
# C_ASSEMBLE / C_MODIFY properties activated.
# @param user_access_code [IN] binary encoded user access code
# @return True / False
# 2017-09-22
#--------------------------------------------------------------------
def is_interesting_user_access(user_access_int):
    "return True if user_access_code interests us"""
    if (user_access_int & C_ASSEMBLE) == 0:
        return True
    if (user_access_int & C_MODIFY) == 0:
        return True

    # Still here?
    return False


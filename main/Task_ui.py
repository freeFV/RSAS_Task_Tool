# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'Task_ui.ui'
#
# Created by: PyQt5 UI code generator 5.15.2
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Task(object):
    def setupUi(self, Task):
        Task.setObjectName("Task")
        Task.resize(997, 826)
        Task.setMinimumSize(QtCore.QSize(0, 700))
        font = QtGui.QFont()
        font.setFamily("宋体")
        font.setPointSize(12)
        Task.setFont(font)
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(Task)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.frame = QtWidgets.QFrame(Task)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.frame.sizePolicy().hasHeightForWidth())
        self.frame.setSizePolicy(sizePolicy)
        self.frame.setMinimumSize(QtCore.QSize(0, 0))
        font = QtGui.QFont()
        font.setFamily("宋体")
        font.setPointSize(11)
        self.frame.setFont(font)
        self.frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame.setObjectName("frame")
        self.horizontalLayout_14 = QtWidgets.QHBoxLayout(self.frame)
        self.horizontalLayout_14.setObjectName("horizontalLayout_14")
        self.label = QtWidgets.QLabel(self.frame)
        font = QtGui.QFont()
        font.setFamily("幼圆")
        font.setPointSize(11)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.horizontalLayout_14.addWidget(self.label, 0, QtCore.Qt.AlignLeft)
        self.Host_label = QtWidgets.QLabel(self.frame)
        self.Host_label.setMinimumSize(QtCore.QSize(0, 0))
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(11)
        self.Host_label.setFont(font)
        self.Host_label.setObjectName("Host_label")
        self.horizontalLayout_14.addWidget(self.Host_label)
        self.label_3 = QtWidgets.QLabel(self.frame)
        font = QtGui.QFont()
        font.setFamily("幼圆")
        font.setPointSize(11)
        self.label_3.setFont(font)
        self.label_3.setObjectName("label_3")
        self.horizontalLayout_14.addWidget(self.label_3)
        self.account_label = QtWidgets.QLabel(self.frame)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(11)
        self.account_label.setFont(font)
        self.account_label.setObjectName("account_label")
        self.horizontalLayout_14.addWidget(self.account_label)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_14.addItem(spacerItem)
        self.logout_pushButton = QtWidgets.QPushButton(self.frame)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.logout_pushButton.sizePolicy().hasHeightForWidth())
        self.logout_pushButton.setSizePolicy(sizePolicy)
        self.logout_pushButton.setMinimumSize(QtCore.QSize(0, 0))
        font = QtGui.QFont()
        font.setFamily("幼圆")
        font.setPointSize(11)
        self.logout_pushButton.setFont(font)
        self.logout_pushButton.setObjectName("logout_pushButton")
        self.horizontalLayout_14.addWidget(self.logout_pushButton, 0, QtCore.Qt.AlignRight)
        self.verticalLayout_3.addWidget(self.frame)
        self.widget_2 = QtWidgets.QWidget(Task)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.widget_2.sizePolicy().hasHeightForWidth())
        self.widget_2.setSizePolicy(sizePolicy)
        self.widget_2.setMinimumSize(QtCore.QSize(0, 0))
        self.widget_2.setObjectName("widget_2")
        self.horizontalLayout_11 = QtWidgets.QHBoxLayout(self.widget_2)
        self.horizontalLayout_11.setObjectName("horizontalLayout_11")
        self.groupBox = QtWidgets.QGroupBox(self.widget_2)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.groupBox.sizePolicy().hasHeightForWidth())
        self.groupBox.setSizePolicy(sizePolicy)
        self.groupBox.setMinimumSize(QtCore.QSize(400, 0))
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(10)
        self.groupBox.setFont(font)
        self.groupBox.setObjectName("groupBox")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.groupBox)
        self.verticalLayout.setObjectName("verticalLayout")
        self.Task_name_textEdit = QtWidgets.QTextEdit(self.groupBox)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Task_name_textEdit.sizePolicy().hasHeightForWidth())
        self.Task_name_textEdit.setSizePolicy(sizePolicy)
        self.Task_name_textEdit.setMinimumSize(QtCore.QSize(0, 0))
        self.Task_name_textEdit.setObjectName("Task_name_textEdit")
        self.verticalLayout.addWidget(self.Task_name_textEdit)
        self.horizontalLayout_11.addWidget(self.groupBox)
        self.groupBox_2 = QtWidgets.QGroupBox(self.widget_2)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.groupBox_2.sizePolicy().hasHeightForWidth())
        self.groupBox_2.setSizePolicy(sizePolicy)
        self.groupBox_2.setMinimumSize(QtCore.QSize(0, 0))
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(10)
        self.groupBox_2.setFont(font)
        self.groupBox_2.setObjectName("groupBox_2")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.groupBox_2)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.Scan_Template_label = QtWidgets.QLabel(self.groupBox_2)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(1)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Scan_Template_label.sizePolicy().hasHeightForWidth())
        self.Scan_Template_label.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(10)
        self.Scan_Template_label.setFont(font)
        self.Scan_Template_label.setObjectName("Scan_Template_label")
        self.horizontalLayout.addWidget(self.Scan_Template_label)
        self.TemplateList_comboBox = QtWidgets.QComboBox(self.groupBox_2)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(2)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.TemplateList_comboBox.sizePolicy().hasHeightForWidth())
        self.TemplateList_comboBox.setSizePolicy(sizePolicy)
        self.TemplateList_comboBox.setObjectName("TemplateList_comboBox")
        self.horizontalLayout.addWidget(self.TemplateList_comboBox)
        self.verticalLayout_2.addLayout(self.horizontalLayout)
        self.verticalLayout_5 = QtWidgets.QVBoxLayout()
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        spacerItem1 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.verticalLayout_5.addItem(spacerItem1)
        self.verticalLayout_2.addLayout(self.verticalLayout_5)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.SetPost_label = QtWidgets.QLabel(self.groupBox_2)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(10)
        self.SetPost_label.setFont(font)
        self.SetPost_label.setObjectName("SetPost_label")
        self.horizontalLayout_2.addWidget(self.SetPost_label)
        self.DefaultPort_checkBox = QtWidgets.QCheckBox(self.groupBox_2)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(10)
        self.DefaultPort_checkBox.setFont(font)
        self.DefaultPort_checkBox.setChecked(True)
        self.DefaultPort_checkBox.setObjectName("DefaultPort_checkBox")
        self.horizontalLayout_2.addWidget(self.DefaultPort_checkBox)
        self.AllPort_checkBox = QtWidgets.QCheckBox(self.groupBox_2)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(10)
        self.AllPort_checkBox.setFont(font)
        self.AllPort_checkBox.setChecked(False)
        self.AllPort_checkBox.setObjectName("AllPort_checkBox")
        self.horizontalLayout_2.addWidget(self.AllPort_checkBox)
        self.verticalLayout_2.addLayout(self.horizontalLayout_2)
        self.verticalLayout_6 = QtWidgets.QVBoxLayout()
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        spacerItem2 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.verticalLayout_6.addItem(spacerItem2)
        self.verticalLayout_2.addLayout(self.verticalLayout_6)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.survival_label = QtWidgets.QLabel(self.groupBox_2)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(10)
        self.survival_label.setFont(font)
        self.survival_label.setObjectName("survival_label")
        self.horizontalLayout_3.addWidget(self.survival_label)
        self.survival_cancel_checkBox = QtWidgets.QCheckBox(self.groupBox_2)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(10)
        self.survival_cancel_checkBox.setFont(font)
        self.survival_cancel_checkBox.setObjectName("survival_cancel_checkBox")
        self.horizontalLayout_3.addWidget(self.survival_cancel_checkBox)
        self.survival_Definition_checkBox = QtWidgets.QCheckBox(self.groupBox_2)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(10)
        self.survival_Definition_checkBox.setFont(font)
        self.survival_Definition_checkBox.setObjectName("survival_Definition_checkBox")
        self.horizontalLayout_3.addWidget(self.survival_Definition_checkBox)
        self.verticalLayout_2.addLayout(self.horizontalLayout_3)
        self.horizontalLayout_12 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_12.setObjectName("horizontalLayout_12")
        spacerItem3 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.horizontalLayout_12.addItem(spacerItem3)
        self.verticalLayout_2.addLayout(self.horizontalLayout_12)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.wordbook_label = QtWidgets.QLabel(self.groupBox_2)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(1)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.wordbook_label.sizePolicy().hasHeightForWidth())
        self.wordbook_label.setSizePolicy(sizePolicy)
        self.wordbook_label.setAlignment(QtCore.Qt.AlignCenter)
        self.wordbook_label.setObjectName("wordbook_label")
        self.horizontalLayout_4.addWidget(self.wordbook_label)
        self.Enable_wordbook_checkBox = QtWidgets.QCheckBox(self.groupBox_2)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(1)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Enable_wordbook_checkBox.sizePolicy().hasHeightForWidth())
        self.Enable_wordbook_checkBox.setSizePolicy(sizePolicy)
        self.Enable_wordbook_checkBox.setObjectName("Enable_wordbook_checkBox")
        self.horizontalLayout_4.addWidget(self.Enable_wordbook_checkBox, 0, QtCore.Qt.AlignHCenter)
        self.wordbook_label_2 = QtWidgets.QLabel(self.groupBox_2)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(2)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.wordbook_label_2.sizePolicy().hasHeightForWidth())
        self.wordbook_label_2.setSizePolicy(sizePolicy)
        self.wordbook_label_2.setAlignment(QtCore.Qt.AlignCenter)
        self.wordbook_label_2.setObjectName("wordbook_label_2")
        self.horizontalLayout_4.addWidget(self.wordbook_label_2)
        self.verticalLayout_2.addLayout(self.horizontalLayout_4)
        self.verticalLayout_10 = QtWidgets.QVBoxLayout()
        self.verticalLayout_10.setObjectName("verticalLayout_10")
        self.verticalLayout_2.addLayout(self.verticalLayout_10)
        self.groupBox_3 = QtWidgets.QGroupBox(self.groupBox_2)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.groupBox_3.sizePolicy().hasHeightForWidth())
        self.groupBox_3.setSizePolicy(sizePolicy)
        self.groupBox_3.setMinimumSize(QtCore.QSize(0, 120))
        self.groupBox_3.setMaximumSize(QtCore.QSize(16777215, 400))
        self.groupBox_3.setObjectName("groupBox_3")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.groupBox_3)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.SMB_wordbook_checkBox = QtWidgets.QCheckBox(self.groupBox_3)
        self.SMB_wordbook_checkBox.setChecked(True)
        self.SMB_wordbook_checkBox.setObjectName("SMB_wordbook_checkBox")
        self.horizontalLayout_5.addWidget(self.SMB_wordbook_checkBox)
        self.RDP_wordbook_checkBox = QtWidgets.QCheckBox(self.groupBox_3)
        self.RDP_wordbook_checkBox.setChecked(True)
        self.RDP_wordbook_checkBox.setObjectName("RDP_wordbook_checkBox")
        self.horizontalLayout_5.addWidget(self.RDP_wordbook_checkBox)
        self.TELENT_wordbook_checkBox = QtWidgets.QCheckBox(self.groupBox_3)
        self.TELENT_wordbook_checkBox.setChecked(True)
        self.TELENT_wordbook_checkBox.setObjectName("TELENT_wordbook_checkBox")
        self.horizontalLayout_5.addWidget(self.TELENT_wordbook_checkBox)
        self.FTP_wordbook_checkBox = QtWidgets.QCheckBox(self.groupBox_3)
        self.FTP_wordbook_checkBox.setChecked(True)
        self.FTP_wordbook_checkBox.setObjectName("FTP_wordbook_checkBox")
        self.horizontalLayout_5.addWidget(self.FTP_wordbook_checkBox)
        self.SSH_wordbook_checkBox = QtWidgets.QCheckBox(self.groupBox_3)
        self.SSH_wordbook_checkBox.setChecked(True)
        self.SSH_wordbook_checkBox.setObjectName("SSH_wordbook_checkBox")
        self.horizontalLayout_5.addWidget(self.SSH_wordbook_checkBox)
        self.Tomcat_wordbook_checkBox = QtWidgets.QCheckBox(self.groupBox_3)
        self.Tomcat_wordbook_checkBox.setChecked(True)
        self.Tomcat_wordbook_checkBox.setObjectName("Tomcat_wordbook_checkBox")
        self.horizontalLayout_5.addWidget(self.Tomcat_wordbook_checkBox)
        self.POP3_wordbook_checkBox = QtWidgets.QCheckBox(self.groupBox_3)
        self.POP3_wordbook_checkBox.setChecked(True)
        self.POP3_wordbook_checkBox.setObjectName("POP3_wordbook_checkBox")
        self.horizontalLayout_5.addWidget(self.POP3_wordbook_checkBox)
        self.verticalLayout_4.addLayout(self.horizontalLayout_5)
        self.verticalLayout_9 = QtWidgets.QVBoxLayout()
        self.verticalLayout_9.setObjectName("verticalLayout_9")
        self.verticalLayout_4.addLayout(self.verticalLayout_9)
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        self.SQL_SERVER_wordbook_checkBox = QtWidgets.QCheckBox(self.groupBox_3)
        self.SQL_SERVER_wordbook_checkBox.setChecked(True)
        self.SQL_SERVER_wordbook_checkBox.setObjectName("SQL_SERVER_wordbook_checkBox")
        self.horizontalLayout_6.addWidget(self.SQL_SERVER_wordbook_checkBox)
        self.MySQL_wordbook_checkBox = QtWidgets.QCheckBox(self.groupBox_3)
        self.MySQL_wordbook_checkBox.setChecked(True)
        self.MySQL_wordbook_checkBox.setObjectName("MySQL_wordbook_checkBox")
        self.horizontalLayout_6.addWidget(self.MySQL_wordbook_checkBox)
        self.Orcle_wordbook_checkBox = QtWidgets.QCheckBox(self.groupBox_3)
        self.Orcle_wordbook_checkBox.setChecked(True)
        self.Orcle_wordbook_checkBox.setObjectName("Orcle_wordbook_checkBox")
        self.horizontalLayout_6.addWidget(self.Orcle_wordbook_checkBox)
        self.Sybase_wordbook_checkBox = QtWidgets.QCheckBox(self.groupBox_3)
        self.Sybase_wordbook_checkBox.setChecked(True)
        self.Sybase_wordbook_checkBox.setObjectName("Sybase_wordbook_checkBox")
        self.horizontalLayout_6.addWidget(self.Sybase_wordbook_checkBox)
        self.DB2_wordbook_checkBox = QtWidgets.QCheckBox(self.groupBox_3)
        self.DB2_wordbook_checkBox.setChecked(True)
        self.DB2_wordbook_checkBox.setObjectName("DB2_wordbook_checkBox")
        self.horizontalLayout_6.addWidget(self.DB2_wordbook_checkBox)
        self.MONGODB_wordbook_checkBox = QtWidgets.QCheckBox(self.groupBox_3)
        self.MONGODB_wordbook_checkBox.setChecked(True)
        self.MONGODB_wordbook_checkBox.setObjectName("MONGODB_wordbook_checkBox")
        self.horizontalLayout_6.addWidget(self.MONGODB_wordbook_checkBox)
        self.SNMP_wordbook_checkBox = QtWidgets.QCheckBox(self.groupBox_3)
        self.SNMP_wordbook_checkBox.setChecked(True)
        self.SNMP_wordbook_checkBox.setObjectName("SNMP_wordbook_checkBox")
        self.horizontalLayout_6.addWidget(self.SNMP_wordbook_checkBox)
        self.verticalLayout_4.addLayout(self.horizontalLayout_6)
        self.verticalLayout_2.addWidget(self.groupBox_3)
        self.horizontalLayout_7 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_7.setObjectName("horizontalLayout_7")
        self.Scan_Time_label = QtWidgets.QLabel(self.groupBox_2)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(1)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Scan_Time_label.sizePolicy().hasHeightForWidth())
        self.Scan_Time_label.setSizePolicy(sizePolicy)
        self.Scan_Time_label.setObjectName("Scan_Time_label")
        self.horizontalLayout_7.addWidget(self.Scan_Time_label)
        self.Scan_Time_lineEdit = QtWidgets.QLineEdit(self.groupBox_2)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(2)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Scan_Time_lineEdit.sizePolicy().hasHeightForWidth())
        self.Scan_Time_lineEdit.setSizePolicy(sizePolicy)
        self.Scan_Time_lineEdit.setText("")
        self.Scan_Time_lineEdit.setObjectName("Scan_Time_lineEdit")
        self.horizontalLayout_7.addWidget(self.Scan_Time_lineEdit)
        self.verticalLayout_2.addLayout(self.horizontalLayout_7)
        self.verticalLayout_7 = QtWidgets.QVBoxLayout()
        self.verticalLayout_7.setObjectName("verticalLayout_7")
        spacerItem4 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.verticalLayout_7.addItem(spacerItem4)
        self.verticalLayout_2.addLayout(self.verticalLayout_7)
        self.horizontalLayout_8 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_8.setObjectName("horizontalLayout_8")
        self.Report_Type_label = QtWidgets.QLabel(self.groupBox_2)
        self.Report_Type_label.setObjectName("Report_Type_label")
        self.horizontalLayout_8.addWidget(self.Report_Type_label)
        self.HTML_Report_checkBox = QtWidgets.QCheckBox(self.groupBox_2)
        self.HTML_Report_checkBox.setCheckable(True)
        self.HTML_Report_checkBox.setChecked(True)
        self.HTML_Report_checkBox.setObjectName("HTML_Report_checkBox")
        self.horizontalLayout_8.addWidget(self.HTML_Report_checkBox)
        self.World_Report_checkBox = QtWidgets.QCheckBox(self.groupBox_2)
        self.World_Report_checkBox.setObjectName("World_Report_checkBox")
        self.horizontalLayout_8.addWidget(self.World_Report_checkBox)
        self.Excel_Report_checkBox = QtWidgets.QCheckBox(self.groupBox_2)
        self.Excel_Report_checkBox.setChecked(True)
        self.Excel_Report_checkBox.setObjectName("Excel_Report_checkBox")
        self.horizontalLayout_8.addWidget(self.Excel_Report_checkBox)
        self.PDF_Report_checkBox = QtWidgets.QCheckBox(self.groupBox_2)
        self.PDF_Report_checkBox.setObjectName("PDF_Report_checkBox")
        self.horizontalLayout_8.addWidget(self.PDF_Report_checkBox)
        self.verticalLayout_2.addLayout(self.horizontalLayout_8)
        self.verticalLayout_8 = QtWidgets.QVBoxLayout()
        self.verticalLayout_8.setObjectName("verticalLayout_8")
        spacerItem5 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.verticalLayout_8.addItem(spacerItem5)
        self.verticalLayout_2.addLayout(self.verticalLayout_8)
        self.horizontalLayout_9 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_9.setObjectName("horizontalLayout_9")
        self.Report_Content_label = QtWidgets.QLabel(self.groupBox_2)
        self.Report_Content_label.setObjectName("Report_Content_label")
        self.horizontalLayout_9.addWidget(self.Report_Content_label)
        self.Summary_Report_checkBox = QtWidgets.QCheckBox(self.groupBox_2)
        self.Summary_Report_checkBox.setCheckable(True)
        self.Summary_Report_checkBox.setChecked(True)
        self.Summary_Report_checkBox.setObjectName("Summary_Report_checkBox")
        self.horizontalLayout_9.addWidget(self.Summary_Report_checkBox)
        self.Host_Report_checkBox = QtWidgets.QCheckBox(self.groupBox_2)
        self.Host_Report_checkBox.setChecked(True)
        self.Host_Report_checkBox.setObjectName("Host_Report_checkBox")
        self.horizontalLayout_9.addWidget(self.Host_Report_checkBox)
        self.Auto_Report_checkBox = QtWidgets.QCheckBox(self.groupBox_2)
        self.Auto_Report_checkBox.setChecked(True)
        self.Auto_Report_checkBox.setObjectName("Auto_Report_checkBox")
        self.horizontalLayout_9.addWidget(self.Auto_Report_checkBox)
        self.verticalLayout_2.addLayout(self.horizontalLayout_9)
        spacerItem6 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.verticalLayout_2.addItem(spacerItem6)
        self.horizontalLayout_10 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_10.setObjectName("horizontalLayout_10")
        self.Working_label = QtWidgets.QLabel(self.groupBox_2)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(2)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Working_label.sizePolicy().hasHeightForWidth())
        self.Working_label.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(10)
        self.Working_label.setFont(font)
        self.Working_label.setObjectName("Working_label")
        self.horizontalLayout_10.addWidget(self.Working_label)
        self.start_Button = QtWidgets.QPushButton(self.groupBox_2)
        self.start_Button.setEnabled(True)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(1)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.start_Button.sizePolicy().hasHeightForWidth())
        self.start_Button.setSizePolicy(sizePolicy)
        self.start_Button.setMinimumSize(QtCore.QSize(0, 25))
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(10)
        self.start_Button.setFont(font)
        self.start_Button.setStyleSheet("QPushButton {\n"
"    background-color: rgb(85, 170, 255);\n"
"    border-radius: 5px;\n"
"    color: white;\n"
"    spacing: 500px;\n"
"}\n"
"QPushButton:hover {\n"
"    background-color: rgb(0, 170, 255);\n"
"}\n"
"QPushButton:pressed {\n"
"    background-color:rgb(170, 255, 127);\n"
"}\n"
"")
        self.start_Button.setAutoRepeatDelay(0)
        self.start_Button.setAutoRepeatInterval(0)
        self.start_Button.setObjectName("start_Button")
        self.horizontalLayout_10.addWidget(self.start_Button)
        self.verticalLayout_2.addLayout(self.horizontalLayout_10)
        self.verticalLayout_2.setStretch(0, 1)
        self.verticalLayout_2.setStretch(1, 1)
        self.verticalLayout_2.setStretch(2, 1)
        self.verticalLayout_2.setStretch(3, 1)
        self.verticalLayout_2.setStretch(4, 1)
        self.verticalLayout_2.setStretch(5, 1)
        self.verticalLayout_2.setStretch(6, 1)
        self.verticalLayout_2.setStretch(7, 1)
        self.verticalLayout_2.setStretch(8, 3)
        self.verticalLayout_2.setStretch(9, 1)
        self.verticalLayout_2.setStretch(10, 1)
        self.verticalLayout_2.setStretch(11, 1)
        self.verticalLayout_2.setStretch(12, 1)
        self.verticalLayout_2.setStretch(13, 1)
        self.verticalLayout_2.setStretch(14, 1)
        self.verticalLayout_2.setStretch(15, 1)
        self.horizontalLayout_11.addWidget(self.groupBox_2)
        self.verticalLayout_3.addWidget(self.widget_2)
        self.frame_2 = QtWidgets.QFrame(Task)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.frame_2.sizePolicy().hasHeightForWidth())
        self.frame_2.setSizePolicy(sizePolicy)
        self.frame_2.setMinimumSize(QtCore.QSize(0, 0))
        font = QtGui.QFont()
        font.setFamily("宋体")
        font.setPointSize(12)
        self.frame_2.setFont(font)
        self.frame_2.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_2.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_2.setObjectName("frame_2")
        self.horizontalLayout_13 = QtWidgets.QHBoxLayout(self.frame_2)
        self.horizontalLayout_13.setObjectName("horizontalLayout_13")
        self.Status_label = QtWidgets.QLabel(self.frame_2)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Status_label.sizePolicy().hasHeightForWidth())
        self.Status_label.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(11)
        self.Status_label.setFont(font)
        self.Status_label.setObjectName("Status_label")
        self.horizontalLayout_13.addWidget(self.Status_label)
        self.verticalLayout_3.addWidget(self.frame_2, 0, QtCore.Qt.AlignHCenter)

        self.retranslateUi(Task)
        self.logout_pushButton.clicked['bool'].connect(Task.logout_clicked)
        QtCore.QMetaObject.connectSlotsByName(Task)

    def retranslateUi(self, Task):
        _translate = QtCore.QCoreApplication.translate
        Task.setWindowTitle(_translate("Task", "Form"))
        self.label.setText(_translate("Task", "扫描器："))
        self.Host_label.setText(_translate("Task", "TextLabel"))
        self.label_3.setText(_translate("Task", "登录名："))
        self.account_label.setText(_translate("Task", "TextLabel"))
        self.logout_pushButton.setText(_translate("Task", "注销"))
        self.groupBox.setTitle(_translate("Task", "任务名称|2021-1-1 11:11:11："))
        self.groupBox_2.setTitle(_translate("Task", "任务参数："))
        self.Scan_Template_label.setText(_translate("Task", "扫描模板配置："))
        self.SetPost_label.setText(_translate("Task", "端口扫描配置："))
        self.DefaultPort_checkBox.setText(_translate("Task", "标准端口扫描"))
        self.AllPort_checkBox.setText(_translate("Task", "全部端口扫描"))
        self.survival_label.setText(_translate("Task", "存活探测配置："))
        self.survival_cancel_checkBox.setText(_translate("Task", "取消存活探测"))
        self.survival_Definition_checkBox.setText(_translate("Task", "定义探测端口"))
        self.wordbook_label.setText(_translate("Task", "口令猜测："))
        self.Enable_wordbook_checkBox.setText(_translate("Task", "启用"))
        self.wordbook_label_2.setText(_translate("Task", "（如不启用，则下方口令选项不会生效）"))
        self.groupBox_3.setTitle(_translate("Task", "口令猜测"))
        self.SMB_wordbook_checkBox.setText(_translate("Task", "SMB"))
        self.RDP_wordbook_checkBox.setText(_translate("Task", "RDP"))
        self.TELENT_wordbook_checkBox.setText(_translate("Task", "TELENT"))
        self.FTP_wordbook_checkBox.setText(_translate("Task", "FTP"))
        self.SSH_wordbook_checkBox.setText(_translate("Task", "SSH"))
        self.Tomcat_wordbook_checkBox.setText(_translate("Task", "Tomcat"))
        self.POP3_wordbook_checkBox.setText(_translate("Task", "POP3"))
        self.SQL_SERVER_wordbook_checkBox.setText(_translate("Task", "SQL SERVER"))
        self.MySQL_wordbook_checkBox.setText(_translate("Task", "MySQL"))
        self.Orcle_wordbook_checkBox.setText(_translate("Task", "Orcle"))
        self.Sybase_wordbook_checkBox.setText(_translate("Task", "Sybase"))
        self.DB2_wordbook_checkBox.setText(_translate("Task", "DB2"))
        self.MONGODB_wordbook_checkBox.setText(_translate("Task", "MONGODB"))
        self.SNMP_wordbook_checkBox.setText(_translate("Task", "SNMP"))
        self.Scan_Time_label.setText(_translate("Task", "扫描时间段："))
        self.Report_Type_label.setText(_translate("Task", "报表类型："))
        self.HTML_Report_checkBox.setText(_translate("Task", "HTML"))
        self.World_Report_checkBox.setText(_translate("Task", "World"))
        self.Excel_Report_checkBox.setText(_translate("Task", "Excel"))
        self.PDF_Report_checkBox.setText(_translate("Task", "PDF"))
        self.Report_Content_label.setText(_translate("Task", "报表内容："))
        self.Summary_Report_checkBox.setText(_translate("Task", "综述报表"))
        self.Host_Report_checkBox.setText(_translate("Task", "主机报表"))
        self.Auto_Report_checkBox.setText(_translate("Task", "自动生成报表"))
        self.Working_label.setText(_translate("Task", "共个任务，正在下达第个任务..."))
        self.start_Button.setText(_translate("Task", "开始下任务"))
        self.Status_label.setText(_translate("Task", "状态：当前有10个任务正在进行,10个任务等待扫描"))
# !/usr/bin/python3
# -*- coding: utf-8 -*-
"""
@Author         :  matchawat
@Email          :  aaadmin@88.com
------------------------------------
@File           :  login_pane.py
@Version        :  
@Description    :  
@CreateTime     :  2021/1/26/0026 20:33
------------------------------------
@Software       :  PyCharm
"""

import os
import re
import sys

from PyQt5.QtSql import QSqlTableModel

import pycode.favicon
import time
from PyQt5 import QtGui, QtWidgets
from PyQt5.QtCore import Qt, QTimer, QUrl, QSettings, QThread, pyqtSignal, QAbstractTableModel
from PyQt5.QtGui import QDesktopServices, QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QWidget, QLineEdit, QPushButton, QDialog, QVBoxLayout, QFrame, QDesktopWidget, QTabWidget, \
    QHeaderView
from pycode.Login_ui import Ui_LoginForm
from pycode.Task_ui import Ui_Task
from pycode.RSAS import *
from pycode.ECC_Encryption import *

import requests

requests.packages.urllib3.disable_warnings()

RSAS_Requests = RSAS_Requests()


################################################
#######登录界面
################################################
class login_pane(QWidget, Ui_LoginForm):
    def __init__(self, mode=0, parent=None):
        super(login_pane, self).__init__(parent)
        self.mode = mode
        self.setupUi(self)

        self.setWindowTitle("登陆")
        self.setWindowIcon(QtGui.QIcon(':/favicon.ico'))

        ######  登录页面头图设置 完美显示图片，并自适应大小
        pix = QtGui.QPixmap("./md7699.png")
        self.login_top_bg_label.setPixmap(pix)
        self.login_top_bg_label.setScaledContents(True)

        ###### 显示窗口在屏幕中间
        self.center()

        ###### 初始化登录信息
        self.init_login_info()

        ###### 自动登录
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.goto_autologin)
        self.timer.setSingleShot(True)
        self.timer.start(1000)

        ###### 从配置文件取出扫描器的IP
        try:
            with open('config.ini') as content:
                self.localhost = content.readlines()[1:3]
                self.host = self.localhost[0].split('=')[1].strip()
                self.port = self.localhost[1].split('=')[1].strip()
                global SCANNER_URL
                if self.port == '443':
                    SCANNER_URL = 'https://{}'.format(self.host)
                else:
                    SCANNER_URL = 'https://{}:{}'.format(self.host, self.port)
                # print("配置文件读取：", self.host, self.port)
        except Exception as e:
            self.open_config_pane()

        ###### 创建资产文件夹
        try:
            os.mkdir('Host_Assets')
            os.mkdir('URL_Assets')
        except Exception as e:
            pass

    ###### 显示窗口在屏幕中间
    def center(self):
        # 获得窗口
        qr = self.frameGeometry()
        # 获得屏幕中心点
        cp = QDesktopWidget().availableGeometry().center()
        # 显示到屏幕中心
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    ###### 配置信息按钮----槽函数
    def open_config_pane(self):
        dialog = configdialog()
        if dialog.exec_() == QDialog.Accepted:
            # the_window = login_pane()
            # the_window.show()
            self.host = host
            self.port = port
            global SCANNER_URL
            if self.port == '443':
                SCANNER_URL = 'https://{}'.format(self.host)
            else:
                SCANNER_URL = 'https://{}:{}'.format(self.host, self.port)
            # print("配置页面设置：", self.host, self.port, server)

    ###### 自动登录 and 记住密码 联动
    def auto_login(self, checked):
        if checked:
            self.remember_passwd_checkBox.setChecked(True)

    ###### 记住密码 and 自动登录 联动
    def remember_pwd(self, checked):
        if not checked:
            self.Auto_login_checkBox.setChecked(False)

    ###### 账户 and 密码 and 登录按钮  有效性联动
    def enable_login_btn(self):
        account = self.username_lineEdit.text()
        passwd = self.passwd_lineEdit.text()
        if len(account) > 0 and len(passwd) > 0:
            self.login_pushButton.setEnabled(True)
        else:
            self.login_pushButton.setEnabled(False)

    ###### 登录按钮--槽函数
    def ckeck_login(self):
        self.on_pushButton_enter_clicked()

    ###### 网页登录按钮--槽函数
    def open_url_link(self):
        QDesktopServices.openUrl(QUrl(SCANNER_URL))

    ###### 自动登录
    def goto_autologin(self):
        if self.Auto_login_checkBox.isChecked() == True and self.mode == 0:
            self.on_pushButton_enter_clicked()

    ###### 保存登录信息
    def save_login_info(self):
        settings = QSettings("config.ini", QSettings.IniFormat)  # 方法1：使用配置文件
        # settings = QSettings("mysoft","myapp")                   # 方法2：使用注册表
        settings.setValue("host", self.host)
        settings.setValue("port", self.port)
        # account_Encrypt = Encrypt(self.username_lineEdit.text())
        settings.setValue("account", self.username_lineEdit.text())

        ###### 对密码进行椭圆曲线加密并保存
        passwd_Encrypt = Encrypt(self.passwd_lineEdit.text())
        settings.setValue("password", passwd_Encrypt)

        settings.setValue("remeberpassword", self.remember_passwd_checkBox.isChecked())
        settings.setValue("autologin", self.Auto_login_checkBox.isChecked())

    ###### 初始化登录信息
    def init_login_info(self):
        settings = QSettings("config.ini", QSettings.IniFormat)  # 方法1：使用配置文件
        # settings = QSettings("mysoft","myapp")                   # 方法2：使用注册表
        # account_Decryption = Decryption(settings.value("account"))
        the_account = settings.value("account")

        ###### 对密码进行椭圆曲线解密并设置
        password_Decryption = settings.value("password")
        if password_Decryption == "" or password_Decryption == None:
            the_password = password_Decryption
        else:
            the_password = Decryption(password_Decryption)

        the_remeberpassword = settings.value("remeberpassword")
        the_autologin = settings.value("autologin")

        self.username_lineEdit.setText(the_account)
        if the_remeberpassword == "true" or the_remeberpassword == True:
            self.remember_passwd_checkBox.setChecked(True)
            self.passwd_lineEdit.setText(the_password)

        if the_autologin == "true" or the_autologin == True:
            self.Auto_login_checkBox.setChecked(True)

    ###### 登录事件执行
    def on_pushButton_enter_clicked(self):
        self.username = self.username_lineEdit.text()
        self.passwd = self.passwd_lineEdit.text()
        # print(self.username, self.passwd, self.login_url)
        try:
            ###### 登陆扫描器，成功跳转到主界面
            cooker = RSAS_Requests.RSAS_Login(SCANNER_URL, self.username, self.passwd)
            ######  获取重定向url地址
            if cooker.headers['location'] == '/':
                ######  到这里就是登陆成功了，开始保存登录信息
                self.save_login_info()
                global account
                account = self.username
                print("[+] 登录成功....")
        except Exception as e:
            QtWidgets.QMessageBox.about(None, '提示！', '密码错误！')

        if account != '':
            try:
                ######  关闭登录界面，打开主界面
                self.close()
                self.task_window = task_pane()
                self.task_window.show()
            except Exception as e:
                QtWidgets.QMessageBox.information(None, "提示！", f"{e}",QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,QtWidgets.QMessageBox.Yes)


################################################
#######配置页面对话框
################################################
class configdialog(QDialog):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setWindowTitle('配置界面')
        self.resize(300, 200)
        self.setFixedSize(self.width(), self.height())
        ###### 设置只显示关闭按钮
        self.setWindowFlags(Qt.WindowCloseButtonHint)

        ###### 设置界面控件
        self.frame = QFrame(self)
        self.verticalLayout = QVBoxLayout(self.frame)
        self.verticalLayout.alignment()
        self.lineEdit_host = QLineEdit()
        self.lineEdit_host.setPlaceholderText("请输入ip地址")
        self.verticalLayout.addWidget(self.lineEdit_host)

        self.lineEdit_port = QLineEdit()
        self.lineEdit_port.setPlaceholderText("请输入端口")
        self.verticalLayout.addWidget(self.lineEdit_port)

        self.pushButton_enter = QPushButton()
        self.pushButton_enter.setText("确定")
        self.verticalLayout.addWidget(self.pushButton_enter)

        self.pushButton_quit = QPushButton()
        self.pushButton_quit.setText("取消")
        self.verticalLayout.addWidget(self.pushButton_quit)

        ###### 绑定按钮事件
        self.pushButton_enter.clicked.connect(self.pushButton_enter_clicked)
        self.pushButton_quit.clicked.connect(self.pushButton_quit_clicked)

        ###### 初始化配置信息
        self.init_config_info()

    ###### 初始化配置信息
    def init_config_info(self):
        settings = QSettings("config.ini", QSettings.IniFormat)
        the_host = settings.value("host")
        the_port = settings.value("port")
        self.set_host_port(the_host, the_port)

    ###### 确定按钮
    def pushButton_enter_clicked(self):
        global host
        global port
        if self.lineEdit_host.text() == "":
            self.pushButton_quit_clicked
        else:
            host = self.lineEdit_host.text()
            port = self.lineEdit_port.text()
            self.accept()

    ###### 取消按钮
    def pushButton_quit_clicked(self):
        # 关闭对话框
        self.accept()

    def set_host_port(self, host, port):
        self.lineEdit_host.setText(host)
        if port == None:
            self.lineEdit_port.setText("443")
        else:
            self.lineEdit_port.setText(port)
        # print("初始化配置信息成功！")


################################################
#######任务界面
################################################
class task_pane(QWidget, Ui_Task):
    def __init__(self, parent=None):
        super(task_pane, self).__init__(parent)
        self.setupUi(self)

        self.setWindowTitle("RSAS_Task_Tool")
        self.setWindowIcon(QtGui.QIcon(':/favicon.ico'))
        ###### 显示窗口在屏幕中间
        self.center()
        ###### 任务界面提示用户名&&扫描器地址
        self.Host_label.setText(re.search(r'https://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', SCANNER_URL).group(1))
        self.account_label.setText(account)
        self.host_scan_tab()
        class_text = RSAS_Requests.check_scan_tab()
        if class_text[0] == 'quick_task_btn':
            self.web_scan_tab()

        ###### 扫描器的任务状态
        self.Status = RSAS_Status()
        self.Status.log_return.connect(self.status_finish)
        self.Status.start()

        ###### 扫描器的任务列表
        self.set_task_view()

    ###### 显示窗口在屏幕中间
    def center(self):
        # 获得窗口
        qr = self.frameGeometry()
        # 获得屏幕中心点
        cp = QDesktopWidget().availableGeometry().center()
        # 显示到屏幕中心
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    ###### 网页登录--槽函数
    def url_login_clicked(self):
        QDesktopServices.openUrl(QUrl(SCANNER_URL))

    ###### 注销按钮--槽函数
    def logout_clicked(self):
        self.close()
        self.login_window = login_pane(mode=1)
        # self.windowList.append(self.login_window)  # 这句一定要写，不然无法重新登录
        self.login_window.show()

    ###### todo 这个是主界面修改显示用的
    def status_finish(self, status_msg):
        number = status_msg.split('|')
        self.Status_Ongoing_label.setText(f"{number[0]}")
        self.Status_Waiting_label.setText(f"{number[1]}")

    ################################################
    #######主机扫描标签窗口
    ################################################
    def host_scan_tab(self):

        # 扫描器的漏洞模板
        self.host_template = {'0': '自动匹配扫描'}
        ###### 获取扫描器的漏洞模板，保存为软件的下拉框
        content_re = """<tr class=".*?">.*?<th>漏洞模板</th>.*?<td>.*?<select id='.*?'.*?style=".*?">(.*?)</select>.*?</td>.*?</tr>"""
        template_re = """<option value='(\d+)' >(.*?)</option>"""
        content = RSAS_Requests.Host_scanning_template()
        cont = re.findall(content_re, content.text, re.S | re.M)
        ###### 把扫描器的漏洞模板生成下拉框
        self.host_template.update(dict(re.findall(template_re, cont[0], re.S | re.M)))
        self.TemplateList_Host_comboBox.addItems(self.host_template.values())
        self.TemplateList_Host_comboBox.setCurrentIndex(0)

        self.L_chk = [self.SMB_wordbook_checkBox, self.RDP_wordbook_checkBox, self.TELENT_wordbook_checkBox,
                      self.FTP_wordbook_checkBox, self.SSH_wordbook_checkBox, self.Tomcat_wordbook_checkBox,
                      self.POP3_wordbook_checkBox, self.SQL_SERVER_wordbook_checkBox, self.MySQL_wordbook_checkBox,
                      self.Orcle_wordbook_checkBox, self.Sybase_wordbook_checkBox, self.DB2_wordbook_checkBox,
                      self.MONGODB_wordbook_checkBox, self.SNMP_wordbook_checkBox]

        self.Start_Host_Button.clicked.connect(self.Start_Host_Scan)

    # todo 字典全选联动
    def all_wordbook(self,checked):
        if checked:
            for i in self.L_chk:
                i.setChecked(True)
        else:
            for i in self.L_chk:
                i.setChecked(False)


    ###### 加载Host资产文件下的资产文件到任务名称窗口
    def Load_Task_Name_Host(self):
        self.Task_name_Host_textEdit.setText("")
        HostAssets_dir = './Host_Assets/'

        #  web资产文件列表
        HostAssets_list = []

        for file in os.listdir(HostAssets_dir):
            if os.path.splitext(file)[1] == '.txt':
                HostAssets_list.append(file)
                self.Task_name_Host_textEdit.append(file[0:-4])

    ###### Host标签窗口开始任务按钮--槽函数
    def Start_Host_Scan(self):
        # 获取当前下拉框的字符
        host_template_mode = self.TemplateList_Host_comboBox.currentText()
        # 通过字符找到模板对应的数字，就是字典，通过值取键。扫描器的扫描模板对应不同的数字，扫描器在下任务时依照该数字选择对应的模板
        host_template_number = list(self.host_template.keys())[list(self.host_template.values()).index(host_template_mode)]

        ###### 这里就获取主界面的按钮勾选状态了
        # 端口扫描
        DefaultPort_status = self.DefaultPort_checkBox.isChecked()
        AllPost_status = self.AllPort_checkBox.isChecked()
        # 存活探测
        survival_cancel_status = self.survival_cancel_checkBox.isChecked()
        survival_Definition_status = self.survival_Definition_checkBox.isChecked()
        # 口令猜测
        Enable_wordbook_status = self.Enable_wordbook_checkBox.isChecked()
        SMB_wordbook_status = self.SMB_wordbook_checkBox.isChecked()
        RDP_wordbook_status = self.RDP_wordbook_checkBox.isChecked()
        TELENT_wordbook_status = self.TELENT_wordbook_checkBox.isChecked()
        FTP_wordbook_status = self.FTP_wordbook_checkBox.isChecked()
        SSH_wordbook_status = self.SSH_wordbook_checkBox.isChecked()
        Tomcat_wordbook_status = self.Tomcat_wordbook_checkBox.isChecked()
        POP3_wordbook_status = self.POP3_wordbook_checkBox.isChecked()
        SQL_SERVER_wordbook_status = self.SQL_SERVER_wordbook_checkBox.isChecked()
        MySQL_wordbook_status = self.MySQL_wordbook_checkBox.isChecked()
        Orcle_wordbook_status = self.Orcle_wordbook_checkBox.isChecked()
        Sybase_wordbook_status = self.Sybase_wordbook_checkBox.isChecked()
        DB2_wordbook_status = self.DB2_wordbook_checkBox.isChecked()
        MONGODB_wordbook_status = self.MONGODB_wordbook_checkBox.isChecked()
        SNMP_wordbook_status = self.SNMP_wordbook_checkBox.isChecked()

        # 报表类型
        HTML_Report_Host_status = self.HTML_Report_Host_checkBox.isChecked()
        World_Report_Host_status = self.World_Report_Host_checkBox.isChecked()
        Excel_Report_Host_status = self.Excel_Report_Host_checkBox.isChecked()
        PDF_Report_Host_status = self.PDF_Report_Host_checkBox.isChecked()
        # 报表内容
        Summary_Report_Host_status = self.Summary_Report_Host_checkBox.isChecked()
        Host_Report_Host_status = self.Host_Report_Host_checkBox.isChecked()
        Auto_Report_Host_status = self.Auto_Report_Host_checkBox.isChecked()

        # todo 这里可以对扫描时间段进行输入校验
        # scan_time_re = QRegExp("(((([0]{1}[0-9]{1})|([1][0-9]{1})|([2][0-4]{1})):([0-5]+[0-9]+)-(([0]{1}[0-9]{1})|([1][0-9]{1})|([2][0-4]{1})):([0-5]+[0-9]+));+)*")
        # validator = QRegExpValidator(scan_time_re, self.edit)
        # self.Scan_Time_lineEdit.setValidator(validator)
        host_Scan_time_status = self.Scan_Time_Host_lineEdit.text()

        # todo 这里可以对扫描任务名&&任务开始时间进行输入校验
        host_task_list = self.Task_name_Host_textEdit.toPlainText().split("\n")
        host_task_list = [i for i in host_task_list if i !='']

        ###### 这里就是下任务了，使用线程，避免卡界面
        self.Start_Host_Button.setChecked(True)
        self.Start_Host_Button.setDisabled(True)
        self.Start_Host_Scan_Working = Start_Host_Scan_Working(host_template_number, DefaultPort_status, AllPost_status,
                                                               survival_cancel_status, survival_Definition_status,
                                                               Enable_wordbook_status, SMB_wordbook_status,
                                                               RDP_wordbook_status, TELENT_wordbook_status,
                                                               FTP_wordbook_status, SSH_wordbook_status,
                                                               Tomcat_wordbook_status, POP3_wordbook_status,
                                                               SQL_SERVER_wordbook_status, MySQL_wordbook_status,
                                                               Orcle_wordbook_status, Sybase_wordbook_status,
                                                               DB2_wordbook_status, MONGODB_wordbook_status,
                                                               SNMP_wordbook_status,
                                                               HTML_Report_Host_status, World_Report_Host_status,
                                                               Excel_Report_Host_status,
                                                               PDF_Report_Host_status, Summary_Report_Host_status,
                                                               Host_Report_Host_status, Auto_Report_Host_status,
                                                               host_Scan_time_status, host_task_list)
        self.Start_Host_Scan_Working.start_host_return.connect(self.Start_Host_Scan_Finish)
        self.Start_Host_Scan_Working.start()

    ###### 显示Host扫描任务下达状态
    def Start_Host_Scan_Finish(self, start_msg):
        self.Working_Host_label.setText(start_msg)
        if '所有任务下达完成' in start_msg:
            self.Start_Host_Button.setChecked(False)
            self.Start_Host_Button.setDisabled(False)

    ################################################
    #######web扫描标签窗口
    ################################################
    def web_scan_tab(self):

        # 扫描器的漏洞模板
        self.web_template = {'0': '自动匹配扫描'}
        ###### 获取扫描器的漏洞模板，保存为软件的下拉框
        content_re = """<tr class=".*?">.*?<th>漏洞模板</th>.*?<td>.*?<select id='.*?'.*?style=".*?">(.*?)</select>.*?</td>.*?</tr>"""
        template_re = """<option value="(\d+)" >(.*?)</option>"""
        content = RSAS_Requests.Web_scanning_template()
        cont = re.findall(content_re, content.text, re.S | re.M)
        ###### 把扫描器的漏洞模板生成下拉框
        self.web_template.update(dict(re.findall(template_re, cont[0], re.S | re.M)))
        self.TemplateList_Web_comboBox.addItems(self.web_template.values())
        self.TemplateList_Web_comboBox.setCurrentIndex(0)

        # 设置扫描范围下拉框的选项
        range_items = ["按域名扫描", "扫描当前目录及子目录", "只扫描任务目标链接"]
        self.Scan_Range_comboBox.addItems(range_items)
        self.Scan_Range_comboBox.setCurrentIndex(1)  # 设置默认值

        # 设置并发线程数默认值
        self.Concurrent_Threads_lineEdit.setText("20")

        # 设置超时限制默认值
        self.Webscan_Timeout_lineEdit.setText("30")

        # 设置目录猜测范围下拉框的选项
        level_items = ["0", "1", "2", "3"]
        self.Dir_level_comboBox.addItems(level_items)
        self.Dir_level_comboBox.setCurrentIndex(1)  # 设置默认值

        # 设置目录猜测深度默认值
        self.Dir_limit_lineEdit.setText("3")

        self.Start_Web_Button.clicked.connect(self.Start_Web_Scan)

    ###### 加载URL资产文件下的资产文件到任务名称窗口
    def Load_Task_Name_Web(self):
        self.Task_name_Web_textEdit.setText("")
        self.WebAssets_dir = './URL_Assets/'

        #  web资产文件列表
        self.WebAssets_list = []

        for file in os.listdir(self.WebAssets_dir):
            if os.path.splitext(file)[1] == '.txt':
                self.WebAssets_list.append(file)
                self.Task_name_Web_textEdit.append(file[0:-4])

    ###### 因web扫描单个任务限制15个URL，需要对任务进行拆分
    def Check_WebAssets_list(self,WebAssets_list):

        New_WebAssets_list = []

        ######  print('[+] 正在遍历url列表，读取url文件...')
        for _task in WebAssets_list:
            task_info = _task.split('|')
            try:
                task_name = task_info[0].strip()
                task_time = task_info[1].strip()
            except Exception as e:
                task_name = _task.strip()
                task_time = ""
            with open('./URL_Assets/' + task_name + '.txt') as url_file:
                url_range = url_file.read()
            url_list = url_range.split('\n')
            # print(url_list)

            while True:
                try:
                    url_list.remove('')
                except ValueError:
                    break

            url_list_len = len(url_list)
            new_url_list = list(set(url_list))

            if len(new_url_list) < url_list_len:
                url_list = new_url_list

            if len(url_list) > 15:

                # 计数器
                flag = 0
                # 文件名
                name = 1
                # 存放数据
                dataList = []

                for line in url_list:
                    flag += 1
                    dataList.append(line)
                    if flag == 15:
                        with open('./URL_Assets/' + task_name + "--" + str(name) + ".txt",'w+') as f_target:  # str[0:-1]为切片，意思是从前面开始截取到后面-1为止
                            for data in dataList:
                                f_target.write(data + "\n")

                        dataList = []
                        if task_time == "":
                            New_WebAssets_list.append(task_name + "--" + str(name))
                        else:
                            New_WebAssets_list.append(task_name + "--" + str(name) + "|" + task_time)
                        name += 1
                        flag = 0

                # 处理最后一批行数少于15行的
                with open('./URL_Assets/' + task_name + "--" + str(name) + ".txt", 'w+') as f_target:
                    for data in dataList:
                        f_target.write(data + "\n")
                # print(f'[*] 拆分任务已完成，共生成{str(name)}子文件')
                if task_time == "":
                    New_WebAssets_list.append(task_name + "--" + str(name))
                else:
                    New_WebAssets_list.append(task_name + "--" + str(name) + "|" + task_time)
                os.remove('./URL_Assets/' + task_name + '.txt')
            else:
                New_WebAssets_list.append(_task)
        return New_WebAssets_list

    ###### Web标签窗口开始任务按钮--槽函数
    def Start_Web_Scan(self):

        ###### 这里就获取主界面的任务参数
        # 获取扫描范围下标
        web_range_number = self.Scan_Range_comboBox.currentIndex()

        # 获取扫描模板当前下拉框的字符
        web_template_mode = self.TemplateList_Web_comboBox.currentText()
        # 通过字符找到模板对应的数字，就是字典，通过值取键。扫描器的扫描模板对应不同的数字，扫描器在下任务时依照该数字选择对应的模板
        web_template_number = list(self.web_template.keys())[list(self.web_template.values()).index(web_template_mode)]

        # 并发线程数
        Concurrent_Threads_status = self.Concurrent_Threads_lineEdit.text()
        # 超时限制
        Webscan_Timeout_status = self.Webscan_Timeout_lineEdit.text()
        # 目录猜测范围
        Dir_level_status = self.Dir_level_comboBox.currentIndex()
        # 目录猜测深度
        Dir_limit_status = self.Dir_limit_lineEdit.text()
        # 报表类型
        HTML_Report_Web_status = self.HTML_Report_Web_checkBox.isChecked()
        World_Report_Web_status = self.World_Report_Web_checkBox.isChecked()
        Excel_Report_Web_status = self.Excel_Report_Web_checkBox.isChecked()
        PDF_Report_Web_status = self.PDF_Report_Web_checkBox.isChecked()
        # 报表内容
        Summary_Report_Web_status = self.Summary_Report_Web_checkBox.isChecked()
        Host_Report_Web_status = self.Host_Report_Web_checkBox.isChecked()
        Auto_Report_Web_status = self.Auto_Report_Web_checkBox.isChecked()

        # todo 这里可以对扫描时间段进行输入校验
        # scan_time_re = QRegExp("(((([0]{1}[0-9]{1})|([1][0-9]{1})|([2][0-4]{1})):([0-5]+[0-9]+)-(([0]{1}[0-9]{1})|([1][0-9]{1})|([2][0-4]{1})):([0-5]+[0-9]+));+)*")
        # validator = QRegExpValidator(scan_time_re, self.edit)
        # self.Scan_Time_lineEdit.setValidator(validator)
        Scan_time_web_status = self.Scan_Time_Web_lineEdit.text()

        # todo 这里可以对扫描任务名&&任务开始时间进行输入校验
        task_list_web = self.Task_name_Web_textEdit.toPlainText().split("\n")
        task_list_web = [i for i in task_list_web if i != '']
        New_WebAssets_list = self.Check_WebAssets_list(task_list_web)

        ###### 这里就是下任务了，使用线程，避免卡界面
        self.Start_Web_Button.setChecked(True)
        self.Start_Web_Button.setDisabled(True)
        self.Start_Web_Scan_Working = Start_Web_Scan_Working(web_range_number, web_template_number,
                                                             Concurrent_Threads_status, Webscan_Timeout_status,
                                                             Dir_level_status, Dir_limit_status,
                                                             HTML_Report_Web_status, World_Report_Web_status,
                                                             Excel_Report_Web_status,
                                                             PDF_Report_Web_status, Summary_Report_Web_status,
                                                             Host_Report_Web_status, Auto_Report_Web_status,
                                                             Scan_time_web_status, New_WebAssets_list)
        self.Start_Web_Scan_Working.start_web_return.connect(self.Start_Web_Scan_Finish)
        self.Start_Web_Scan_Working.start()

    ###### 显示Web扫描任务下达状态
    def Start_Web_Scan_Finish(self, start_msg):
        self.Working_Web_label.setText(start_msg)
        if '所有任务下达完成' in start_msg:
            self.Start_Web_Button.setChecked(False)
            self.Start_Web_Button.setDisabled(False)




###### PyQt5的Model/View/Delegate的设计模式，即Model持有数据，下与数据源交互（数据的查询、修改与添加），上与View交互，
###### 主要为View提供要显示的数据。View提供数据的显示和与用户交互。Delegate可以实现定制数据显示的方式和编辑方式

################################################
#######任务列表展示
################################################
    def set_task_view(self):
        task_list_tableView = self.task_list_tableView

        task_list_tableView.setSelectionBehavior(QHeaderView.SelectRows)  # 选择行为：行选择
        task_list_tableView.setAlternatingRowColors(True)  # 隔行变色
        # 设置表格充满这个布局QHeaderView
        # list_tableview.horizontalHeader().setStretchLastSection(True)     # 最后一列决定充满剩下的界面
        task_list_tableView.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)  # 所有列自动拉伸，充满界面
        # list_tableview.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)  # 根据每栏/每行内容来调整最优大小。用户与代码都不可调整其大小。
        # 设置数据层次结构，4行4列
        self.model = QStandardItemModel(2, 6)
        # 视图加载模型
        self.model = MyModel()
        # 设置水平方向四个头标签文本内容
        self.model.setHorizontalHeaderLabels(['任务号', '任务名称', '开始时间', '结束时间', '进度', '操作'])
        task_list_tableView.setModel(self.model)

        task_num = "666"
        task_name = "任务名称"
        task_start_time = "2021-02-02 22:22:22"
        task_end_time = ""
        task_progress = "66%"

        for row in range(4):
            self.model.setItem(row, 0, QStandardItem(f"{task_num}"))
            self.model.setItem(row, 1, QStandardItem(f"{task_name}"))
            self.model.setItem(row, 2, QStandardItem(f"{task_start_time}"))
            self.model.setItem(row, 3, QStandardItem(f"{task_end_time}"))
            self.model.setItem(row, 4, QStandardItem(f"{task_progress}"))


######  重写QStandardItemModel的data函数以使item居中显示
class MyModel(QStandardItemModel):
    def __init__(self):
        QStandardItemModel.__init__(self)

    def data(self, index, role=None):
        if role == Qt.TextAlignmentRole:
            return Qt.AlignCenter
        return QStandardItemModel.data(self, index, role)


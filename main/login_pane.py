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

import favicon
import time
import requests
from PyQt5 import QtGui, QtWidgets
from PyQt5.QtCore import Qt, QTimer, QUrl, QSettings, QThread, pyqtSignal
from PyQt5.QtGui import QDesktopServices
from PyQt5.QtWidgets import QWidget, QLineEdit, QPushButton, QDialog, QVBoxLayout, QFrame, QDesktopWidget
from Login_ui import Ui_LoginForm
from Task_ui import Ui_Task
from ECC_Encryption import *

requests.packages.urllib3.disable_warnings()


class login_pane(QWidget, Ui_LoginForm):
    def __init__(self, mode=0, parent=None):
        super(login_pane, self).__init__(parent)
        self.mode = mode
        # pyqt5设置窗体透明控件不透明
        # self.setAttribute(Qt.WA_TranslucentBackground,True)
        self.setupUi(self)

        self.setWindowTitle("登陆")
        self.setWindowIcon(QtGui.QIcon(':/favicon.ico'))

        # ###### 登录页面头图设置
        # movie = QMovie("./mdv76m99.png")
        # movie.setScaledSize(QSize(600, 250))
        # self.login_top_bg_label.setMovie(movie)
        # movie.start()

        ###### 登录页面头图设置 完美显示图片，并自适应大小
        pix = QtGui.QPixmap("./mdv76m99.png")
        self.login_top_bg_label.setPixmap(pix)
        # self.login_top_bg_label.setStyleSheet("border: 2px solid blue")
        self.login_top_bg_label.setScaledContents(True)

        # # 获取显示器的分辨率
        # screen = QtWidgets.QDesktopWidget().screenGeometry()
        # # 获取程序的宽和高
        # size = self.geometry()
        # # 实现在屏幕中间显示程序
        # self.move((screen.width() - size.width()) / 2, (screen.height() - size.height()) / 2)

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
                # print("配置文件读取：", self.host, self.port)
            global server
            if self.port == '443':
                server = 'https://{}'.format(self.host)
            else:
                server = 'https://{}:{}'.format(self.host, self.port)
        except Exception as e:
            self.open_config_pane()

        ###### 创建资产文件夹
        try:
            os.mkdir('Assets')
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

    ###### 配置信息----槽函数
    def open_config_pane(self):
        dialog = configdialog()
        if dialog.exec_() == QDialog.Accepted:
            # the_window = login_pane()
            # the_window.show()
            self.host = host
            self.port = port
            global server
            if self.port == '443':
                server = 'https://{}'.format(self.host)
            else:
                server = 'https://{}:{}'.format(self.host, self.port)
            #print("配置页面设置：", self.host, self.port, server)

    ###### 自动登录 and 记住密码 联动
    def auto_login(self, checked):
        # print("自动登录", checked)
        if checked:
            self.remember_passwd_checkBox.setChecked(True)

    ###### 记住密码 and 自动登录 联动
    def remember_pwd(self, checked):
        # print("记住密码", checked)
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
        QDesktopServices.openUrl(QUrl(server))

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
        # print("保存的：", self.host, self.port)
        # account_Encrypt = Encrypt(self.username_lineEdit.text())
        settings.setValue("account", self.username_lineEdit.text())

        ###### 密码加密并保存
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

        ###### 密码解密并设置
        password_Decryption = settings.value("password")
        if password_Decryption == "" or password_Decryption == None:
            the_password = password_Decryption
        else:
            the_password = Decryption(password_Decryption)

        the_remeberpassword = settings.value("remeberpassword")
        the_autologin = settings.value("autologin")
        ########
        self.username_lineEdit.setText(the_account)
        if the_remeberpassword == "true" or the_remeberpassword == True:
            self.remember_passwd_checkBox.setChecked(True)
            self.passwd_lineEdit.setText(the_password)

        if the_autologin == "true" or the_autologin == True:
            self.Auto_login_checkBox.setChecked(True)

        # if the_autologin == "true":  # 防止注销时，自动登录
        #     threading.Timer(1, self.on_pushButton_enter_clicked).start()
        #     # self.on_pushButton_enter_clicked()
        # print(settings.value("password"))
        # print("初始化登录信息成功！")

    ###### 登录事件执行
    def on_pushButton_enter_clicked(self):
        self.username = self.username_lineEdit.text()
        self.passwd = self.passwd_lineEdit.text()

        self.login_url = '{}/accounts/'.format(server)
        # print(self.username, self.passwd, self.login_url)
        ###### 登陆扫描器，成功跳转到主界面
        try:
            global cookies
            global account
            ###### 获取扫描器未登录状态的CSRF值
            self.csrftoken = self.get_token(self.login_url)
            # print(self.csrftoken)
            ###### 登陆扫描器
            cooker = self.post_login(self.login_url, self.csrftoken, self.username, self.passwd)
            #print(cooker)
            #print(self.login_url, self.csrftoken, self.username, self.passwd)
            ###### 获取重定向url地址
            new_url = cooker.headers["Location"]
            #print("重定向url地址:",new_url)
            ###### 获取登陆扫描器成功后的cookie
            cookies = requests.utils.dict_from_cookiejar(cooker.cookies)
            #print(cookies)
            ###### 到这里就是登陆成功了
            ###### 保存登录信息
            self.save_login_info()
            account = self.username
            # print("保存登录信息成功！")
            ###### 关闭登录界面，打开主界面
            self.close()
            self.task_window = task_pane()
            self.task_window.show()
        except Exception as e:
            # print(e)
            # QtWidgets.QMessageBox.about(None, '提示！', '密码错误！')
            QtWidgets.QMessageBox.information(None, "提示！", "密码错误！",
                                              QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                                              QtWidgets.QMessageBox.Yes)

    ###### 获取扫描器未登录状态的CSRF值
    def get_token(self, login_url):
        content = requests.get(self.login_url, verify=False, allow_redirects=False, timeout=3)
        return re.findall("""<input type='hidden' name='csrfmiddlewaretoken' value="(.*)">""", content.text)[0]

    ###### 登陆扫描器
    def post_login(self, login_url, csrftoken, username, passwd):
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.87 Safari/537.36",
            "Referer": self.login_url,
            "Cookie": "csrftoken={}".format(self.csrftoken)
        }
        postdata = {
            'username': self.username,
            'password': self.passwd,
            'csrfmiddlewaretoken': self.csrftoken
        }
        return requests.post(self.login_url + 'login_view/', headers=headers, data=postdata, verify=False,
                             allow_redirects=False, timeout=3)


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

        self.setWindowTitle("RSAS 批量下达任务2.0")
        self.setWindowIcon(QtGui.QIcon(':/favicon.ico'))
        ###### 显示窗口在屏幕中间
        self.center()
        ###### 任务界面提示扫描器地址&&用户名
        self.Host_label.setText(server)
        self.account_label.setText(account)

        # 扫描器的扫描模板
        self.template = {'0': '自动匹配扫描'}
        ######扫描器的任务状态，没什么用的，使用线程，避免卡界面
        self.Status = Status(server, cookies['csrftoken'], cookies['sessionid'])
        self.Status.log_return.connect(self.status_finish)
        self.Status.start()
        ###### 获取扫描器的扫描模板，保存为软件的下拉框
        self.start_Button.clicked.connect(self.admin)
        self.scanning_template(server, cookies['csrftoken'], cookies['sessionid'])

    ###### 显示窗口在屏幕中间
    def center(self):
        # 获得窗口
        qr = self.frameGeometry()
        # 获得屏幕中心点
        cp = QDesktopWidget().availableGeometry().center()
        # 显示到屏幕中心
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    ###### 注销按钮--槽函数
    def logout_clicked(self):
        self.close()
        self.login_window = login_pane(mode=1)
        # self.windowList.append(self.login_window)  # 这句一定要写，不然无法重新登录
        self.login_window.show()

    ###### 获取扫描器的扫描模板
    def scanning_template(self, server, csrftoken, sessionid):
        content_re = """<tr class=".*?">.*?<th>漏洞模板</th>.*?<td>.*?<select id='.*?'.*?style=".*?">(.*?)</select>.*?</td>.*?</tr>"""
        template_re = """<option value='(\d+)' >(.*?)</option>"""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.87 Safari/537.36",
            "Cookie": "csrftoken={}; sessionid={}".format(csrftoken, sessionid)
        }
        headers['Referer'] = server
        content = requests.get(server + '/task/', headers=headers, verify=False, allow_redirects=False)
        cont = re.findall(content_re, content.text, re.S | re.M)
        ###### 把扫描器的扫描模板生成下拉框
        self.template.update(dict(re.findall(template_re, cont[0], re.S | re.M)))
        self.TemplateList_comboBox.addItems(self.template.values())
        self.TemplateList_comboBox.setCurrentIndex(0)

    def admin(self):
        # 获取当前下拉框的字符
        scan_mode = self.TemplateList_comboBox.currentText()
        # 通过字符找到模板对应的数字，就是字典，通过值取键。扫描器的扫描模板对应不同的数字，扫描器在下任务时依照该数字选择对应的模板
        tpl = list(self.template.keys())[list(self.template.values()).index(scan_mode)]

        ###### 这里就是主界面的按钮勾选状态了
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
        # todo 这里可以对扫描时间段进行输入校验(未完成)
        self.Scan_Time_lineEdit.setPlaceholderText("格式如00:00-12:00，多个时间段用分号隔开")
        # scan_time_re = QRegExp("(((([0]{1}[0-9]{1})|([1][0-9]{1})|([2][0-4]{1})):([0-5]+[0-9]+)-(([0]{1}[0-9]{1})|([1][0-9]{1})|([2][0-4]{1})):([0-5]+[0-9]+));+)*")
        # validator = QRegExpValidator(scan_time_re, self.edit)
        # self.Scan_Time_lineEdit.setValidator(validator)
        Scan_time_status = self.Scan_Time_lineEdit.text()
        # print(Scan_time_status)
        # 报表类型
        HTML_Report_status = self.HTML_Report_checkBox.isChecked()
        World_Report_status = self.World_Report_checkBox.isChecked()
        Excel_Report_status = self.Excel_Report_checkBox.isChecked()
        PDF_Report_status = self.PDF_Report_checkBox.isChecked()
        # 报表内容
        Summary_Report_status = self.Summary_Report_checkBox.isChecked()
        Host_Report_status = self.Host_Report_checkBox.isChecked()
        Auto_Report_status = self.Auto_Report_checkBox.isChecked()
        # todo 这里可以对扫描任务名&&任务开始时间进行输入校验(未完成)
        task_list = self.Task_name_textEdit.toPlainText().split("\n")

        ###### 这里就是下任务了，使用线程，避免卡界面
        self.start_Button.setChecked(True)
        self.start_Button.setDisabled(True)
        self.Start = Working(server, cookies['csrftoken'], cookies['sessionid'], task_list, tpl, DefaultPort_status,
                             AllPost_status, survival_cancel_status, survival_Definition_status, Enable_wordbook_status,
                             SMB_wordbook_status, RDP_wordbook_status, TELENT_wordbook_status, FTP_wordbook_status,
                             SSH_wordbook_status, Tomcat_wordbook_status, POP3_wordbook_status,
                             SQL_SERVER_wordbook_status, MySQL_wordbook_status, Orcle_wordbook_status,
                             Sybase_wordbook_status, DB2_wordbook_status, MONGODB_wordbook_status, SNMP_wordbook_status,
                             Scan_time_status, HTML_Report_status, World_Report_status, Excel_Report_status,
                             PDF_Report_status, Summary_Report_status, Host_Report_status, Auto_Report_status)
        self.Start.start_return.connect(self.start_finish)
        self.Start.start()

    ###### 这个是主界面修改显示用的
    def start_finish(self, start_msg):
        self.Working_label.setText(start_msg)
        if '所有任务下达完成' in start_msg:
            self.start_Button.setChecked(False)
            self.start_Button.setDisabled(False)

    ###### 这个是主界面修改显示用的
    def status_finish(self, status_msg):
        global number
        number = status_msg.split('|')
        self.Status_label.setText("状态：当前有{}个任务正在进行,{}个任务等待扫描".format(number[0], number[1]))


class Working(QThread):
    start_return = pyqtSignal(str)

    def __init__(self, server, csrftoken, sessionid, task_list, tpl, DefaultPort_status, AllPost_status,
                 survival_cancel_status, survival_Definition_status, Enable_wordbook_status, SMB_wordbook_status,
                 RDP_wordbook_status, TELENT_wordbook_status, FTP_wordbook_status, SSH_wordbook_status,
                 Tomcat_wordbook_status, POP3_wordbook_status, SQL_SERVER_wordbook_status, MySQL_wordbook_status,
                 Orcle_wordbook_status, Sybase_wordbook_status, DB2_wordbook_status, MONGODB_wordbook_status,
                 SNMP_wordbook_status, Scan_time_status, HTML_Report_status, World_Report_status, Excel_Report_status,
                 PDF_Report_status, Summary_Report_status, Host_Report_status, Auto_Report_status):
        super(Working, self).__init__()
        self.server = server
        self.csrftoken = csrftoken
        self.sessionid = sessionid
        self.tpl = tpl
        self.DefaultPort_status = DefaultPort_status
        self.AllPost_status = AllPost_status
        self.survival_cancel_status = survival_cancel_status
        self.survival_Definition_status = survival_Definition_status
        self.Enable_wordbook_status = Enable_wordbook_status
        self.SMB_wordbook_status = SMB_wordbook_status
        self.RDP_wordbook_status = RDP_wordbook_status
        self.TELENT_wordbook_status = TELENT_wordbook_status
        self.FTP_wordbook_status = FTP_wordbook_status
        self.SSH_wordbook_status = SSH_wordbook_status
        self.Tomcat_wordbook_status = Tomcat_wordbook_status
        self.POP3_wordbook_status = POP3_wordbook_status
        self.SQL_SERVER_wordbook_status = SQL_SERVER_wordbook_status
        self.MySQL_wordbook_status = MySQL_wordbook_status
        self.Orcle_wordbook_status = Orcle_wordbook_status
        self.Sybase_wordbook_status = Sybase_wordbook_status
        self.DB2_wordbook_status = DB2_wordbook_status
        self.MONGODB_wordbook_status = MONGODB_wordbook_status
        self.SNMP_wordbook_status = SNMP_wordbook_status
        self.Scan_time_status = Scan_time_status
        self.HTML_Report_status = HTML_Report_status
        self.World_Report_status = World_Report_status
        self.Excel_Report_status = Excel_Report_status
        self.PDF_Report_status = PDF_Report_status
        self.Summary_Report_status = Summary_Report_status
        self.Host_Report_status = Host_Report_status
        self.Auto_Report_status = Auto_Report_status
        self.task_list = task_list

    def run(self):

        ###### 扫描器下的任务要很多的参数，下边都是POST请求要发送的准备数据
        if self.DefaultPort_status == True:
            port_strategy = 'standard'
            port_strategy_userports = '1-100,443,445'
        if self.AllPost_status == True:
            port_strategy = 'allports'
            port_strategy_userports = '1-65535'

        # if self.survival_Definition_status == True:
        #     with open('set.ini') as cent:
        #         live_tcp_ports = cent.readlines()[3:4][0].split('=')[1].strip()
        # else:
        #     live_tcp_ports = '21,22,23,25,80,443,445,139,3389,6000'

        # 扫描时间段
        if self.Scan_time_status == '':
            self.scan_time = ""
        else:
            self.scan_time = self.Scan_time_status

        i = 1
        for _task in self.task_list:
            self.start_return.emit('共{}个任务，正在下达第{}个任务...'.format(len(self.task_list), i))
            task_info = _task.split('|')
            try:
                task_name = task_info[0].strip()
                task_time = task_info[1].strip()
                task_start_time = 'timing'
            except Exception as e:
                task_name = _task.strip()
                task_time = number[2]
                task_start_time = 'immediate'

            iplist = ''
            loginarray = []
            ips = set()
            try:
                with open('./Assets/' + task_name + '.txt') as cent:
                    for ip in cent:
                        ips.add(ip.strip())
                    _iplist = list(ips)

                    for i in range(len(_iplist)):
                        loginarray.append(
                            {"ip_range": "{}".format(_iplist[i]), "admin_id": "", "protocol": "", "port": "", "os": "",
                             "user_name": "", "user_pwd": "", "ostpls": [], "apptpls": [], "dbtpls": [], "virttpls": [],
                             "devtpls": [], "statustpls": "", "tpl_industry": "", "tpllist": [], "tpllistlen": 0,
                             "jhosts": [], "tpltype": "", "protect": "", "protect_level": "", "jump_ifuse": "",
                             "host_ifsave": "", "oracle_ifuse": "", "ora_username": "", "ora_userpwd": "",
                             "ora_port": "", "ora_usersid": "", "weblogic_ifuse": "", "weblogic_system": "",
                             "weblogic_version": "", "weblogic_user": "", "weblogic_path": ""})
                        iplist += ';' + _iplist[i]
            except Exception as e:
                self.start_return.emit('警告！找不到相关资产，请检查！'.format(len(self.task_list), i))
                with open('log.txt', 'a') as content:
                    content.write('找不到资产：{}\n'.format(task_name))
                time.sleep(1)
                break

            data = {
                "csrfmiddlewaretoken": self.csrftoken,
                "vul_or_pwd": "vul",
                "config_task": "taskname",
                "task_config": "",
                "diff": "write something",
                "target": "ip",
                "ipList": iplist[1:],
                "domainList": "",
                "name": task_name,
                "exec": task_start_time,
                "exec_timing_date": task_time,
                "exec_everyday_time": "00:00",
                "exec_everyweek_day": "1",
                "exec_everyweek_time": "00:00",
                "exec_emonthdate_day": "1",
                "exec_emonthdate_time": "00:00",
                "exec_emonthweek_pre": "1",
                "exec_emonthweek_day": "1",
                "exec_emonthweek_time": "00:00",
                "tpl": self.tpl,
                "login_check_type": "login_check_type_vul",
                "isguesspwd": "yes",
                "exec_range": self.scan_time,
                "scan_pri": "2",
                "taskdesc": "",
                "report_type_html": "html",
                "report_type_doc": "doc",
                "report_type_xls": "xls",
                "report_type_pdf": "pdf",
                "report_content_sum": "sum",
                "report_content_host": "host",
                "report_tpl_sum": "1",
                "report_tpl_host": "101",
                "report_ifcreate": "yes",
                "report_ifsent_type": "html",
                "report_ifsent_email": "",
                "port_strategy": port_strategy,
                "port_strategy_userports": port_strategy_userports,
                "port_speed": "3",
                "port_tcp": "T",
                "live": "on",
                "live_icmp": "on",
                "live_tcp": "on",
                "live_tcp_ports": "21,22,23,25,80,443,445,139,3389,6000",
                "scan_level": "3",
                "timeout_plugins": "40",
                "timeout_read": "5",
                "alert_msg": "远程安全评估系统将对您的主机进行安全评估。",
                "scan_oracle": "yes",
                "encoding": "GBK",
                "bvs_task": "no",
                "pwd_smb": "yes",
                "pwd_type_smb": "c",
                "pwd_user_smb": "smb_user.default",
                "pwd_pass_smb": "smb_pass.default",
                "pwd_rdp": "yes",
                "pwd_type_rdp": "c",
                "pwd_user_rdp": "rdp_user.default",
                "pwd_pass_rdp": "rdp_pass.default",
                "pwd_telnet": "yes",
                "pwd_type_telnet": "c",
                "pwd_user_telnet": "telnet_user.default",
                "pwd_pass_telnet": "telnet_pass.default",
                "pwd_userpass_telnet": "telnet_userpass.default",
                "pwd_ftp": "yes",
                "pwd_type_ftp": "c",
                "pwd_user_ftp": "ftp_user.default",
                "pwd_pass_ftp": "ftp_pass.default",
                "pwd_ssh": "yes",
                "pwd_type_ssh": "c",
                "pwd_user_ssh": "ssh_user.default",
                "pwd_pass_ssh": "ssh_pass.default",
                "pwd_userpass_ssh": "ssh_userpass.default",
                "pwd_pop3": "yes",
                "pwd_type_pop3": "c",
                "pwd_user_pop3": "pop3_user.default",
                "pwd_pass_pop3": "pop3_pass.default",
                "pwd_tomcat": "yes",
                "pwd_type_tomcat": "c",
                "pwd_user_tomcat": "tomcat_user.default",
                "pwd_pass_tomcat": "tomcat_pass.default",
                "pwd_mssql": "yes",
                "pwd_type_mssql": "c",
                "pwd_user_mssql": "mssql_user.default",
                "pwd_pass_mssql": "mssql_pass.default",
                "pwd_mysql": "yes",
                "pwd_type_mysql": "c",
                "pwd_user_mysql": "mysql_user.default",
                "pwd_pass_mysql": "mysql_pass.default",
                "pwd_oracle": "yes",
                "pwd_type_oracle": "c",
                "pwd_user_oracle": "oracle_user.default",
                "pwd_pass_oracle": "oracle_pass.default",
                "pwd_sybase": "yes",
                "pwd_type_sybase": "c",
                "pwd_user_sybase": "sybase_user.default",
                "pwd_pass_sybase": "sybase_pass.default",
                "pwd_db2": "yes",
                "pwd_type_db2": "c",
                "pwd_user_db2": "db2_user.default",
                "pwd_pass_db2": "db2_pass.default",
                "pwd_mongodb": "yes",
                "pwd_type_mongodb": "c",
                "pwd_user_mongodb": "mongodb_user.default",
                "pwd_pass_mongodb": "mongodb_pass.default",
                "pwd_snmp": "yes",
                "pwd_pass_snmp": "snmp_pass.default",
                "pwd_timeout": "5",
                "pwd_timeout_time": "120",
                "pwd_interval": "0",
                "pwd_num": "0",
                "pwd_threadnum": "5",
                "loginarray": loginarray
            }

            # 是否进行存活探测
            if self.survival_cancel_status == True:
                data.pop('live')
                data.pop('live_icmp')
                data.pop('live_tcp')
                data.pop('live_tcp_ports')

            # 是否启用口令猜测，最少勾选一项，默认一直勾选SSH
            if self.Enable_wordbook_status == True:
                if self.SMB_wordbook_status == False:
                    data.pop('pwd_smb')
                    data.pop('pwd_type_smb')
                    data.pop('pwd_user_smb')
                    data.pop('pwd_pass_smb')
                    data.pop('pwd_userpass_smb')
                if self.RDP_wordbook_status == False:
                    data.pop('pwd_rdp')
                    data.pop('pwd_type_rdp')
                    data.pop('pwd_user_rdp')
                    data.pop('pwd_pass_rdp')
                if self.TELENT_wordbook_status == False:
                    data.pop('pwd_telnet')
                    data.pop('pwd_type_telnet')
                    data.pop('pwd_user_telnet')
                    data.pop('pwd_pass_telnet')
                    data.pop('pwd_userpass_telnet')
                if self.FTP_wordbook_status == False:
                    data.pop('pwd_ftp')
                    data.pop('pwd_type_ftp')
                    data.pop('pwd_user_ftp')
                    data.pop('pwd_pass_ftp')
                # if self.SSH_wordbook_status == False:
                #     data.pop('pwd_ssh')
                #     data.pop('pwd_type_ssh')
                #     data.pop('pwd_user_ssh')
                #     data.pop('pwd_pass_ssh')
                #     data.pop('pwd_userpass_ssh')
                if self.Tomcat_wordbook_status == False:
                    data.pop('pwd_tomcat')
                    data.pop('pwd_type_tomcat')
                    data.pop('pwd_user_tomcat')
                    data.pop('pwd_pass_tomcat')
                if self.POP3_wordbook_status == False:
                    data.pop('pwd_pop3')
                    data.pop('pwd_type_pop3')
                    data.pop('pwd_user_pop3')
                    data.pop('pwd_pass_pop3')
                if self.SQL_SERVER_wordbook_status == False:
                    data.pop('pwd_mssql')
                    data.pop('pwd_type_mssql')
                    data.pop('pwd_user_mssql')
                    data.pop('pwd_pass_mssql')
                if self.MySQL_wordbook_status == False:
                    data.pop('pwd_mysql')
                    data.pop('pwd_type_mysql')
                    data.pop('pwd_user_mysql')
                    data.pop('pwd_pass_mysql')
                if self.Orcle_wordbook_status == False:
                    data.pop('pwd_oracle')
                    data.pop('pwd_type_oracle')
                    data.pop('pwd_user_oracle')
                    data.pop('pwd_pass_oracle')
                if self.Sybase_wordbook_status == False:
                    data.pop('pwd_sybase')
                    data.pop('pwd_type_sybase')
                    data.pop('pwd_user_sybase')
                    data.pop('pwd_pass_sybase')
                if self.DB2_wordbook_status == False:
                    data.pop('pwd_db2')
                    data.pop('pwd_type_db2')
                    data.pop('pwd_user_db2')
                    data.pop('pwd_pass_db2')
                if self.MONGODB_wordbook_status == False:
                    data.pop('pwd_mongodb')
                    data.pop('pwd_type_mongodb')
                    data.pop('pwd_user_mongodb')
                    data.pop('pwd_pass_mongodb')
                if self.SNMP_wordbook_status == False:
                    data.pop('pwd_snmp')
                    data.pop('pwd_pass_snmp')
            else:
                data.pop('isguesspwd')
                # data.pop('pwd_smb')
                # data.pop('pwd_type_smb')
                # data.pop('pwd_user_smb')
                # data.pop('pwd_pass_smb')
                # data.pop('pwd_userpass_smb')
                data.pop('pwd_rdp')
                data.pop('pwd_type_rdp')
                data.pop('pwd_user_rdp')
                data.pop('pwd_pass_rdp')
                # data.pop('pwd_telnet')
                # data.pop('pwd_type_telnet')
                # data.pop('pwd_user_telnet')
                # data.pop('pwd_pass_telnet')
                # data.pop('pwd_userpass_telnet')
                data.pop('pwd_ftp')
                data.pop('pwd_type_ftp')
                data.pop('pwd_user_ftp')
                data.pop('pwd_pass_ftp')
                # data.pop('pwd_ssh')
                # data.pop('pwd_type_ssh')
                # data.pop('pwd_user_ssh')
                # data.pop('pwd_pass_ssh')
                # data.pop('pwd_userpass_ssh')
                data.pop('pwd_tomcat')
                data.pop('pwd_type_tomcat')
                data.pop('pwd_user_tomcat')
                data.pop('pwd_pass_tomcat')
                data.pop('pwd_pop3')
                data.pop('pwd_type_pop3')
                data.pop('pwd_user_pop3')
                data.pop('pwd_pass_pop3')
                data.pop('pwd_mssql')
                data.pop('pwd_type_mssql')
                data.pop('pwd_user_mssql')
                data.pop('pwd_pass_mssql')
                data.pop('pwd_mysql')
                data.pop('pwd_type_mysql')
                data.pop('pwd_user_mysql')
                data.pop('pwd_pass_mysql')
                data.pop('pwd_oracle')
                data.pop('pwd_type_oracle')
                data.pop('pwd_user_oracle')
                data.pop('pwd_pass_oracle')
                data.pop('pwd_sybase')
                data.pop('pwd_type_sybase')
                data.pop('pwd_user_sybase')
                data.pop('pwd_pass_sybase')
                data.pop('pwd_db2')
                data.pop('pwd_type_db2')
                data.pop('pwd_user_db2')
                data.pop('pwd_pass_db2')
                data.pop('pwd_mongodb')
                data.pop('pwd_type_mongodb')
                data.pop('pwd_user_mongodb')
                data.pop('pwd_pass_mongodb')
                data.pop('pwd_snmp')
                data.pop('pwd_pass_snmp')
                # data.pop('pwd_timeout')
                # data.pop('pwd_timeout_time')
                # data.pop('pwd_interval')
                # data.pop('pwd_num')
                # data.pop('pwd_threadnum')

            # 最少勾选一项报表类型，默认一直勾选HTML报表
            if self.World_Report_status == False:
                data.pop('report_type_doc')
            if self.Excel_Report_status == False:
                data.pop('report_type_xls')
            if self.PDF_Report_status == False:
                data.pop('report_type_pdf')

            # 最少勾选一项报表内容，默认一直勾选综述报表
            if self.Host_Report_status == False:
                data.pop('report_content_host')

            if self.Auto_Report_status == False:
                data.pop('report_ifcreate')

            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.87 Safari/537.36",
                "Cookie": "csrftoken={}; sessionid={}".format(self.csrftoken, self.sessionid)
            }
            headers['Referer'] = self.server + '/task/'
            ###### 到了这里才是下任务的请求包
            content = requests.post(self.server + '/task/vul/tasksubmit', headers=headers, data=data, verify=False,
                                    allow_redirects=False)
            Errors_text = content.text
            if 'Errors' in content.text:
                self.start_return.emit('第{}个任务下达任务失败...(详情见log.txt)'.format(i))
                with open('log.txt', 'a') as content:
                    content.write('失败任务名：{}\n'.format(task_name))
                    content.write(Errors_text + '\n')
                time.sleep(1)
            else:
                self.start_return.emit('共{}个任务，任务 {} 创建成功...'.format(len(self.task_list), content.text.split(':')[2]))
            i += 1
            time.sleep(1)
        self.start_return.emit('共{}个任务，所有任务下达完成...'.format(len(self.task_list)))


###### 线程获取扫描器进行/等待任务数量，以及扫描时间
class Status(QThread):
    log_return = pyqtSignal(str)

    def __init__(self, server, csrftoken, sessionid):
        super(Status, self).__init__()
        self.server = server
        self.csrftoken = csrftoken
        self.sessionid = sessionid

    def run(self):

        task_re = """<input type='hidden' value='(.*?)' id = 'taskids' />"""
        time_re = """<span id ="sys_time">(.*?)</span>"""

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.87 Safari/537.36",
            "Cookie": "csrftoken={}; sessionid={}".format(self.csrftoken, self.sessionid)
        }
        headers['Referer'] = self.server
        while True:
            ###### 获取任务的数量
            now_list = requests.get(self.server + '/list/getScaning/status/3', headers=headers, verify=False,
                                    allow_redirects=False)
            # print(now_list.text)
            list_id = re.findall(task_re, now_list.text)[0]
            nowtask_id = []
            for _id in list_id.split(';'):
                if _id:
                    nowtask_id.append(_id)
            ###### 获取等待扫描任务的数量
            wait_list = requests.get(self.server + '/list/getScaning/status/12', headers=headers, verify=False,
                                     allow_redirects=False)
            list_id = re.findall(task_re, wait_list.text)[0]
            waittask_id = []
            for _id in list_id.split(';'):
                if _id:
                    waittask_id.append(_id)
            ###### todo 获取扫描器的时间
            content = requests.get(self.server, headers=headers, verify=False, allow_redirects=False)
            server_time = re.findall(time_re, content.text, re.S | re.M)[0].split(' ')
            servertime = '{} {}:{}:00'.format(server_time[1], server_time[0].split(':')[0],
                                              int(server_time[0].split(':')[1]) + 2)
            self.log_return.emit('{}|{}|{}'.format(len(nowtask_id), len(waittask_id), servertime))
            time.sleep(1)

            ###### todo 获取扫描器进行任务名&&任务时间&&任务进度(未完成)

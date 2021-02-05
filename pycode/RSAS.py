# !/usr/bin/python3
# -*- coding: utf-8 -*-
"""
@Author         :  sqandan
@Email          :  aaadmin@88.com
------------------------------------
@File           :  RSAS.py
@Version        :  
@Description    :  
@CreateTime     :  2021/1/30/0030 19:09
------------------------------------
@Software       :  PyCharm
"""
import json
import re
import time
from lxml import etree
import requests
from PyQt5.QtCore import QThread, pyqtSignal

requests.packages.urllib3.disable_warnings()


################################################
#######所有的与扫描器交互的请求都在这里执行
################################################

s = requests.Session()

log_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))

class RSAS_Requests:

    def __init__(self):
        pass

    ######  登录请求
    def RSAS_Login(self, scanner_url, username, password):
        global SCANNER_URL
        SCANNER_URL = scanner_url if not scanner_url.endswith('/') else scanner_url[0:-1]
        #self.SCANNER_ADDRESS = re.search(r'([^/:]+)(:\d*)?', SCANNER_URL).group(2)
        self.SCANNER_ADDRESS = SCANNER_URL.split('://')[1]

        self.USERNAME = username
        self.PASSWORD = password

        # 生成用于登录页面的初始请求头
        s.headers = {
            'Host': f'{self.SCANNER_ADDRESS}',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.97 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Referer': f'{SCANNER_URL}',
            'Upgrade-Insecure-Requests': '1',
        }
        # 访问登陆页面，获取用于登录的csrfmiddlewaretoken
        res = s.get(f'{SCANNER_URL}/accounts/login/?next=/',verify=False)  ##禁止重定向：allow_redirects=False（allow_redirects=True 是启动重定向）#关闭ssl认证：verify=False#设置请求超时：timeout=20
        csrfmiddlewaretoken = re.findall("""<input type='hidden' name='csrfmiddlewaretoken' value="(.*)">""", res.text)[0]

        data = {
            'username': self.USERNAME,
            'password': self.PASSWORD,
            'csrfmiddlewaretoken': csrfmiddlewaretoken
        }
        # 提交登录请求
        cookie_html = s.post(f'{SCANNER_URL}/accounts/login_view/', data=data, verify=False, allow_redirects=False,timeout=3)
        # 获取登陆扫描器成功后的cookie
        # cookies = requests.utils.dict_from_cookiejar(cookie_html.cookies)

        return cookie_html
    
    ###### 判断扫描器支持的扫描模块
    def check_scan_tab(self):
        s.headers['Referer'] = SCANNER_URL
        s.cookies['left_menustatue_NSFOCUSRSAS'] = f"0|0|{SCANNER_URL}/task/task_entry/"
        content = s.get(f'{SCANNER_URL}/task/task_entry/', verify=False)
        html = etree.HTML(content.text)
        class_text = html.xpath('//ul[@id="web_scan"]//input[@type="button"]/@class')

        return class_text

    ###### 获取主机扫描任务的扫描模板
    def Host_scanning_template(self):
        # 更新请求头用于新建信息
        s.headers['Referer'] = f'{SCANNER_URL}/task/task_entry/'
        s.cookies['left_menustatue_NSFOCUSRSAS'] = f"0|0|{SCANNER_URL}/task/task_entry/"
        content = s.get(f'{SCANNER_URL}/task/index/1', verify=False, allow_redirects=False)

        return content

    ###### 获取Web扫描任务的扫描模板
    def Web_scanning_template(self):
        # 更新请求头用于新建信息
        s.headers['Referer'] = f'{SCANNER_URL}/task/task_entry/'
        s.cookies['left_menustatue_NSFOCUSRSAS'] = f"0|0|{SCANNER_URL}/task/task_entry/"
        content = s.get(f'{SCANNER_URL}/task/index/8', verify=False, allow_redirects=False)

        return content


################################################
#######这里是主机扫描多线程下任务鸭
################################################
class Start_Host_Scan_Working(QThread):
    start_host_return = pyqtSignal(str)

    def __init__(self, host_template_number, DefaultPort_status, AllPost_status,
                 survival_cancel_status, survival_Definition_status,
                 Enable_wordbook_status, SMB_wordbook_status,
                 RDP_wordbook_status, TELENT_wordbook_status,
                 FTP_wordbook_status, SSH_wordbook_status,
                 Tomcat_wordbook_status, POP3_wordbook_status,
                 SQL_SERVER_wordbook_status, MySQL_wordbook_status,
                 Orcle_wordbook_status, Sybase_wordbook_status,
                 DB2_wordbook_status, MONGODB_wordbook_status,
                 SNMP_wordbook_status,HTML_Report_Host_status,
                 World_Report_Host_status,Excel_Report_Host_status,
                 PDF_Report_Host_status, Summary_Report_Host_status,
                 Host_Report_Host_status, Auto_Report_Host_status, 
                 host_Scan_time_status, host_task_list):
        super(Start_Host_Scan_Working, self).__init__()
        self.host_template_number = host_template_number
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
        self.HTML_Report_Host_status = HTML_Report_Host_status
        self.World_Report_Host_status = World_Report_Host_status
        self.Excel_Report_Host_status = Excel_Report_Host_status
        self.PDF_Report_Host_status = PDF_Report_Host_status
        self.Summary_Report_Host_status = Summary_Report_Host_status
        self.Host_Report_Host_status = Host_Report_Host_status
        self.Auto_Report_Host_status = Auto_Report_Host_status
        self.host_Scan_time_status = host_Scan_time_status
        self.task_list_host = host_task_list

    def run(self):

        # 更新请求头用于新建信息
        s.headers['Referer'] = f'{SCANNER_URL}/task/task_entry/'
        s.cookies['left_menustatue_NSFOCUSRSAS'] = f"0|0|{SCANNER_URL}/task/task_entry/"
        content = s.get(f'{SCANNER_URL}/task/index/1', verify=False, allow_redirects=False)

        ###### 获取主机扫描任务的csrfmiddlewaretoken
        global host_csrfmiddlewaretoken
        host_csrfmiddlewaretoken = re.findall("""csrfmiddlewaretoken":\'(.+)\'""", content.text)[0]
        print("登录成功后的host_csrfmiddlewaretoken: " + str(host_csrfmiddlewaretoken))

        ###### 扫描器下的任务要很多的参数，下边都是POST请求要发送的准备数据
        if self.DefaultPort_status == True:
            port_strategy = 'standard'
            port_strategy_userports = '1-100,443,445'
        if self.AllPost_status == True:
            port_strategy = 'allports'
            port_strategy_userports = '1-65535'

        # todo 存活探测自定义端口
        # if self.survival_Definition_status == True:
        #     with open('set.ini') as cent:
        #         live_tcp_ports = cent.readlines()[3:4][0].split('=')[1].strip()
        # else:
        #     live_tcp_ports = '21,22,23,25,80,443,445,139,3389,6000'

        # 扫描时间段
        if self.host_Scan_time_status == '':
            self.host_Scan_time = ""
        else:
            self.host_Scan_time = self.host_Scan_time_status

        i = 1
        for _task in self.task_list_host:
            self.start_host_return.emit('共{}个任务，正在下达第{}个任务...'.format(len(self.task_list_host), i))
            task_info = _task.split('|')
            try:
                task_name = task_info[0].strip()
                task_time = task_info[1].strip()
                task_start_time = 'timing'
            except Exception as e:
                task_name = _task.strip()
                task_time = servertime
                task_start_time = 'immediate'

            iplist = ''
            loginarray = []
            ips = set()
            try:
                with open('./Host_Assets/' + task_name + '.txt') as cent:
                    for ip in cent:
                        ips.add(ip.strip())
                    _iplist = [i for i in list(ips) if i != '']

                    for i in range(len(_iplist)):
                        loginarray.append(
                            {"ip_range": "{}".format(_iplist[i]), "admin_id": "", "protocol": "", "port": "","os": "",
                             "user_name": "", "user_pwd": "", "ostpls": [], "apptpls": [], "dbtpls": [],"virttpls": [],
                             "devtpls": [], "statustpls": "", "tpl_industry": "", "tpllist": [], "tpllistlen": 0,"jhosts": [],
                             "tpltype": "", "protect": "", "protect_level": "", "jump_ifuse": "","host_ifsave": "",
                             "oracle_ifuse": "", "ora_username": "", "ora_userpwd": "","ora_port": "", "ora_usersid": "",
                             "weblogic_ifuse": "", "weblogic_system": "","weblogic_version": "", "weblogic_user": "", "weblogic_path": ""})
                        iplist += ';' + _iplist[i]
            except Exception as e:
                self.start_host_return.emit('警告！找不到相关资产，请检查！'.format(len(self.task_list_host), i))
                with open('log.txt', 'a') as content:
                    content.write('找不到资产：{}\n'.format(task_name))
                time.sleep(1)
                break

            host_payload = {
                "csrfmiddlewaretoken": host_csrfmiddlewaretoken,
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
                "tpl": self.host_template_number,
                "login_check_type": "login_check_type_vul",
                "isguesspwd": "yes",
                "exec_range": self.host_Scan_time,
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
                host_payload.pop('live')
                host_payload.pop('live_icmp')
                host_payload.pop('live_tcp')
                host_payload.pop('live_tcp_ports')

            # 是否启用口令猜测，最少勾选一项，默认一直勾选SSH
            if self.Enable_wordbook_status == True:
                if self.SMB_wordbook_status == False:
                    host_payload.pop('pwd_smb')
                    host_payload.pop('pwd_type_smb')
                    host_payload.pop('pwd_user_smb')
                    host_payload.pop('pwd_pass_smb')
                    host_payload.pop('pwd_userpass_smb')

                if self.RDP_wordbook_status == False:
                    host_payload.pop('pwd_rdp')
                    host_payload.pop('pwd_type_rdp')
                    host_payload.pop('pwd_user_rdp')
                    host_payload.pop('pwd_pass_rdp')

                if self.TELENT_wordbook_status == False:
                    host_payload.pop('pwd_telnet')
                    host_payload.pop('pwd_type_telnet')
                    host_payload.pop('pwd_user_telnet')
                    host_payload.pop('pwd_pass_telnet')
                    host_payload.pop('pwd_userpass_telnet')

                if self.FTP_wordbook_status == False:
                    host_payload.pop('pwd_ftp')
                    host_payload.pop('pwd_type_ftp')
                    host_payload.pop('pwd_user_ftp')
                    host_payload.pop('pwd_pass_ftp')

                # if self.SSH_wordbook_status == False:
                #     host_payload.pop('pwd_ssh')
                #     host_payload.pop('pwd_type_ssh')
                #     host_payload.pop('pwd_user_ssh')
                #     host_payload.pop('pwd_pass_ssh')
                #     host_payload.pop('pwd_userpass_ssh')

                if self.Tomcat_wordbook_status == False:
                    host_payload.pop('pwd_tomcat')
                    host_payload.pop('pwd_type_tomcat')
                    host_payload.pop('pwd_user_tomcat')
                    host_payload.pop('pwd_pass_tomcat')

                if self.POP3_wordbook_status == False:
                    host_payload.pop('pwd_pop3')
                    host_payload.pop('pwd_type_pop3')
                    host_payload.pop('pwd_user_pop3')
                    host_payload.pop('pwd_pass_pop3')

                if self.SQL_SERVER_wordbook_status == False:
                    host_payload.pop('pwd_mssql')
                    host_payload.pop('pwd_type_mssql')
                    host_payload.pop('pwd_user_mssql')
                    host_payload.pop('pwd_pass_mssql')

                if self.MySQL_wordbook_status == False:
                    host_payload.pop('pwd_mysql')
                    host_payload.pop('pwd_type_mysql')
                    host_payload.pop('pwd_user_mysql')
                    host_payload.pop('pwd_pass_mysql')

                if self.Orcle_wordbook_status == False:
                    host_payload.pop('pwd_oracle')
                    host_payload.pop('pwd_type_oracle')
                    host_payload.pop('pwd_user_oracle')
                    host_payload.pop('pwd_pass_oracle')

                if self.Sybase_wordbook_status == False:
                    host_payload.pop('pwd_sybase')
                    host_payload.pop('pwd_type_sybase')
                    host_payload.pop('pwd_user_sybase')
                    host_payload.pop('pwd_pass_sybase')

                if self.DB2_wordbook_status == False:
                    host_payload.pop('pwd_db2')
                    host_payload.pop('pwd_type_db2')
                    host_payload.pop('pwd_user_db2')
                    host_payload.pop('pwd_pass_db2')

                if self.MONGODB_wordbook_status == False:
                    host_payload.pop('pwd_mongodb')
                    host_payload.pop('pwd_type_mongodb')
                    host_payload.pop('pwd_user_mongodb')
                    host_payload.pop('pwd_pass_mongodb')

                if self.SNMP_wordbook_status == False:
                    host_payload.pop('pwd_snmp')
                    host_payload.pop('pwd_pass_snmp')
            else:
                host_payload.pop('isguesspwd')

                # host_payload.pop('pwd_smb')
                # host_payload.pop('pwd_type_smb')
                # host_payload.pop('pwd_user_smb')
                # host_payload.pop('pwd_pass_smb')
                # host_payload.pop('pwd_userpass_smb')

                host_payload.pop('pwd_rdp')
                host_payload.pop('pwd_type_rdp')
                host_payload.pop('pwd_user_rdp')
                host_payload.pop('pwd_pass_rdp')

                # host_payload.pop('pwd_telnet')
                # host_payload.pop('pwd_type_telnet')
                # host_payload.pop('pwd_user_telnet')
                # host_payload.pop('pwd_pass_telnet')
                # host_payload.pop('pwd_userpass_telnet')

                host_payload.pop('pwd_ftp')
                host_payload.pop('pwd_type_ftp')
                host_payload.pop('pwd_user_ftp')
                host_payload.pop('pwd_pass_ftp')

                # host_payload.pop('pwd_ssh')
                # host_payload.pop('pwd_type_ssh')
                # host_payload.pop('pwd_user_ssh')
                # host_payload.pop('pwd_pass_ssh')
                # host_payload.pop('pwd_userpass_ssh')

                host_payload.pop('pwd_tomcat')
                host_payload.pop('pwd_type_tomcat')
                host_payload.pop('pwd_user_tomcat')
                host_payload.pop('pwd_pass_tomcat')

                host_payload.pop('pwd_pop3')
                host_payload.pop('pwd_type_pop3')
                host_payload.pop('pwd_user_pop3')
                host_payload.pop('pwd_pass_pop3')

                host_payload.pop('pwd_mssql')
                host_payload.pop('pwd_type_mssql')
                host_payload.pop('pwd_user_mssql')
                host_payload.pop('pwd_pass_mssql')

                host_payload.pop('pwd_mysql')
                host_payload.pop('pwd_type_mysql')
                host_payload.pop('pwd_user_mysql')
                host_payload.pop('pwd_pass_mysql')

                host_payload.pop('pwd_oracle')
                host_payload.pop('pwd_type_oracle')
                host_payload.pop('pwd_user_oracle')
                host_payload.pop('pwd_pass_oracle')

                host_payload.pop('pwd_sybase')
                host_payload.pop('pwd_type_sybase')
                host_payload.pop('pwd_user_sybase')
                host_payload.pop('pwd_pass_sybase')

                host_payload.pop('pwd_db2')
                host_payload.pop('pwd_type_db2')
                host_payload.pop('pwd_user_db2')
                host_payload.pop('pwd_pass_db2')

                host_payload.pop('pwd_mongodb')
                host_payload.pop('pwd_type_mongodb')
                host_payload.pop('pwd_user_mongodb')
                host_payload.pop('pwd_pass_mongodb')

                host_payload.pop('pwd_snmp')
                host_payload.pop('pwd_pass_snmp')

                # host_payload.pop('pwd_timeout')
                # host_payload.pop('pwd_timeout_time')
                # host_payload.pop('pwd_interval')
                # host_payload.pop('pwd_num')
                # host_payload.pop('pwd_threadnum')

            # 最少勾选一项报表类型，默认一直勾选HTML报表
            if self.World_Report_Host_status == False:
                host_payload.pop('report_type_doc')
            if self.Excel_Report_Host_status == False:
                host_payload.pop('report_type_xls')
            if self.PDF_Report_Host_status == False:
                host_payload.pop('report_type_pdf')

            # 最少勾选一项报表内容，默认一直勾选综述报表
            if self.Host_Report_Host_status == False:
                host_payload.pop('report_content_host')

            if self.Auto_Report_Host_status == False:
                host_payload.pop('report_ifcreate')

            # 更新请求头用于新建信息
            s.headers['Accept'] = '*/*'
            s.headers['Content-Type'] = 'application/x-www-form-urlencoded'
            s.headers['Origin'] = f'{SCANNER_URL}'
            s.headers['Connection'] = 'close'
            s.headers['Referer'] = f'{SCANNER_URL}/task/index/1'
            s.headers['X-Requested-With'] = 'XMLHttpRequest'
            s.cookies['left_menustatue_NSFOCUSRSAS'] = f"0|0|{SCANNER_URL}/task/task_entry/"

            ###### 到了这里才是下任务的请求包
            host_resp = s.post(f'{SCANNER_URL}/task/vul/tasksubmit', data=host_payload, verify=False)
            print(host_resp.text)
            if 'suc' in host_resp.text:
                self.start_host_return.emit('共{}个任务，任务 {} 创建成功...'.format(len(self.task_list_host), host_resp.text.split(':')[2]))
            else:
                self.start_host_return.emit('第{}个任务下达任务失败...(详情见log.txt)'.format(i))
                with open('log.txt', 'a') as content:
                    content.write(log_time)
                    content.write('     失败任务名：{}     失败原因：'.format(task_name))
                    content.write(host_resp.text + '\n')
                time.sleep(1)
            i += 1
            time.sleep(1)
        self.start_host_return.emit('共{}个任务，所有任务下达完成...'.format(len(self.task_list_host)))


################################################
#######这里是Web扫描多线程下任务鸭
################################################
class Start_Web_Scan_Working(QThread):
    start_web_return = pyqtSignal(str)

    def __init__(self, web_range_number, web_template_number,
                 Concurrent_Threads_status, Webscan_Timeout_status,
                 Dir_level_status, Dir_limit_status,HTML_Report_Web_status,
                 World_Report_Web_status,Excel_Report_Web_status,
                 PDF_Report_Web_status, Summary_Report_Web_status,
                 Host_Report_Web_status, Auto_Report_Web_status,
                 Scan_time_web_status, New_WebAssets_list):
        super(Start_Web_Scan_Working, self).__init__()

        self.web_range = web_range_number
        self.web_template = web_template_number
        self.Concurrent_Threads_status = Concurrent_Threads_status
        self.Webscan_Timeout_status = Webscan_Timeout_status
        self.Dir_level_status = Dir_level_status
        self.Dir_limit_status = Dir_limit_status
        self.HTML_Report_Web_status = HTML_Report_Web_status
        self.World_Report_Web_status = World_Report_Web_status
        self.Excel_Report_Web_status = Excel_Report_Web_status
        self.PDF_Report_Web_status = PDF_Report_Web_status
        self.Summary_Report_Web_status = Summary_Report_Web_status
        self.Host_Report_Web_status = Host_Report_Web_status
        self.Auto_Report_Web_status = Auto_Report_Web_status
        self.Scan_time_web_status = Scan_time_web_status
        self.task_list_web = New_WebAssets_list

    def run(self):

        # 更新请求头用于新建信息
        s.headers['Referer'] = f'{SCANNER_URL}/task/task_entry/'
        s.cookies['left_menustatue_NSFOCUSRSAS'] = f"0|0|{SCANNER_URL}/task/task_entry/"
        content = s.get(f'{SCANNER_URL}/task/index/8', verify=False, allow_redirects=False)

        ###### 获取Web扫描任务的csrfmiddlewaretoken
        global web_csrfmiddlewaretoken
        web_csrfmiddlewaretoken = re.findall("""csrfmiddlewaretoken":\'(.+)\'""", content.text)[0]
        print("获取Web扫描任务的csrfmiddlewaretoken: " + str(web_csrfmiddlewaretoken))

        ###### 扫描器下的任务要很多的参数，下边都是POST请求要发送的准备数据
        # 扫描时间段
        if self.Scan_time_web_status == '':
            self.Scan_time_web = ""
        else:
            self.Scan_time_web = self.Scan_time_web_status

        i = 1
        for _task in self.task_list_web:
            self.start_web_return.emit('共{}个任务，正在下达第{}个任务...'.format(len(self.task_list_web), i))
            task_info = _task.split('|')
            try:
                task_name = task_info[0].strip()
                task_time = task_info[1].strip()
                task_start_time = 'timing'
            except Exception as e:
                task_name = _task.strip()
                task_time = servertime
                task_start_time = 'immediate'

            # web扫描任务名称和资产处理
            urllist = ''
            global url_count
            url_count = 0
            try:
                with open('./URL_Assets/' + task_name + '.txt') as cent:
                    for url in cent:
                        urllist += ';'+url.strip()
                        url_count += 1
            except Exception as e:
                self.start_web_return.emit('警告！找不到相关资产，请检查！'.format(len(self.task_list_web), i))
                with open('log.txt', 'a') as content:
                    content.write('找不到资产：{}\n'.format(task_name))
                time.sleep(1)
                break

            web_payload = {
                'csrfmiddlewaretoken': web_csrfmiddlewaretoken,
                'target_count': url_count,  # 该参数输入扫描地址数量
                'config_task': 'taskname',
                'task_config': '',
                'task_target': urllist[1:],  # 该参数输入扫描地址
                'task_name': task_name,  # 该参数输入任务名称
                'scan_method': self.web_range,  # 该参数输入漏洞模板
                'subdomains_scan': '0',
                'subdomains': '',
                'exec': task_start_time,  # 该参数输入扫描时间属性
                'exec_timing_date': task_time,  # 该参数输入扫描时间
                'exec_everyday_time': '00:00',
                'exec_everyweek_day': '1',
                'exec_everyweek_time': '00:00',
                'exec_emonthdate_day': '1',
                'exec_emonthdate_time': '00:00',
                'exec_emonthweek_pre': '1',
                'exec_emonthweek_day': '1',
                'exec_emonthweek_time': '00:00',
                'tpl': self.web_template,  # 该参数控制漏洞模板
                'ws_proxy_type': 'HTTP',
                'ws_proxy_auth': 'Basic',
                'ws_proxy_server': '',
                'ws_proxy_port': '',
                'ws_proxy_username': '',
                'ws_proxy_password': '',
                'cron_range': self.Scan_time_web,  # 该参数控制扫描时间段
                'dispatchLevel': '2',
                'target_description': '',
                'report_type_html': 'html',
                'report_type_doc': 'doc',
                'report_type_xls': 'xls',
                'report_type_pdf': 'pdf',
                'summarizeReport': 'yes',
                'oneSiteReport': 'yes',
                'sum_report_tpl': '201',
                'site_report_tpl': '301',
                'auto_export': 'yes',
                'sendReport_type': 'html',
                'email_address': '',
                'plugin_threads': self.Concurrent_Threads_status,  # 该参数控制并发线程数
                'webscan_timeout': self.Webscan_Timeout_status,  # 该参数控制超时限制
                'page_encoding': '0',
                'coding': 'UTF8',
                'login_ifuse': 'yes',
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.97 Safari/537.36',
                'dir_level': self.Dir_level_status,  # 该参数控制目录猜测范围
                'dir_limit': self.Dir_limit_status,  # 该参数控制目录猜测深度
                'filetype_to_check_backup': 'shtml,php,jsp,asp,aspx',
                'backup_filetype': 'bak,old',
                'scan_type': '0',
                'dir_files_limit': '-1',  # 该参数控制单文件目录数
                'dir_depth_limit': '15',  # 该参数控制目录深度
                'scan_link_limit': '-1',  # 该参数控制链接总数
                'case_sensitive': '1',
                'if_javascript': '1',
                'if_repeat': '2',
                'protocalarray': '[{"target": "%s", "protocal_type": "auto", "protocal_name": "", "protocal_pwd": "", "login_scan_type": "no", "cookies": "", "cookie_type": "set_cookie", "black_links": "", "wihte_links": "", "form_switch": "yes", "form_cont": "no", "form_str": ""}]' %urllist[1],
            }

            # 最少勾选一项报表类型，默认一直勾选HTML报表
            if self.World_Report_Web_status == False:
                web_payload.pop('report_type_doc')
            if self.Excel_Report_Web_status == False:
                web_payload.pop('report_type_xls')
            if self.PDF_Report_Web_status == False:
                web_payload.pop('report_type_pdf')

            # 最少勾选一项报表内容，默认一直勾选综述报表
            if self.Host_Report_Web_status == False:
                web_payload.pop('oneSiteReport')

            if self.Auto_Report_Web_status == False:
                web_payload.pop('auto_export')

            # 更新请求头用于新建信息
            s.headers['Accept'] = '*/*'
            s.headers['Content-Type'] = 'application/x-www-form-urlencoded'
            s.headers['Origin'] = f'{SCANNER_URL}'
            s.headers['Connection'] = 'close'
            s.headers['Referer'] = f'{SCANNER_URL}/task/index/8'
            s.headers['X-Requested-With'] = 'XMLHttpRequest'
            s.cookies['left_menustatue_NSFOCUSRSAS'] = f"0|0|{SCANNER_URL}/task/task_entry/"

            ###### 到了这里才是下任务的请求包
            web_resp = s.post(f'{SCANNER_URL}/task/vul/web_newtask/', data=web_payload, verify=False)
            print(web_resp.text)
            if 'suc' in web_resp.text:
                self.start_web_return.emit('共{}个任务，任务 {} 创建成功...'.format(len(self.task_list_web), web_resp.text.split(':')[2]))
            else:
                self.start_web_return.emit('第{}个任务下达任务失败...(详情见log.txt)'.format(i))
                with open('log.txt', 'a') as content:
                    content.write(log_time)
                    content.write('     失败任务名：{}     失败原因：'.format(task_name))
                    content.write(web_resp.text + '\n')
                time.sleep(1)
            i += 1
            time.sleep(1)
        self.start_web_return.emit('共{}个任务，所有任务下达完成...'.format(len(self.task_list_web)))


################################################
#######这里是线程获取扫描器进行/等待任务数量，以及扫描时间
################################################
class RSAS_Status(QThread):
    log_return = pyqtSignal(str)

    def __init__(self):
        super(RSAS_Status, self).__init__()

    def run(self):

        task_re = """<input type='hidden' value='(.*?)' id = 'taskids' />"""
        time_re = """<span id ="sys_time">(.*?)</span>"""
        # 更新请求头用于新建信息
        s.headers['Connection'] = 'keep-alive'
        s.headers['Referer'] = f'{SCANNER_URL}'
        while True:
            ###### 获取当前运行任务数量
            now_task = s.get(SCANNER_URL + '/system/get_task_num/', verify=False,allow_redirects=False)
            nowtask_num = now_task.text
            # list_id = re.findall(task_re, now_task.text)[0]
            # nowtask_id = []
            # for _id in list_id.split(';'):
            #     if _id:
            #         nowtask_id.append(_id)
            #print("当前运行任务数量："+str(nowtask_num))

            ###### 获取等待扫描任务数量
            wait_task = s.get(SCANNER_URL + '/system/get_remain_task/',verify=False,allow_redirects=False)
            waittask_num = wait_task.text
            # list_id = re.findall(task_re, wait_task.text)[0]
            # waittask_id = []
            # for _id in list_id.split(';'):
            #     if _id:
            #         waittask_id.append(_id)
            #print("等待扫描任务数量："+str(waittask_num))

            ###### 获取扫描器的时间
            global servertime
            sys_time = s.get(SCANNER_URL + '/system/getInfo/',verify=False, allow_redirects=False)
            json_response = sys_time.content.decode()  # 获取r的文本 就是一个json字符串
            servertime = json.loads(json_response).get('time')  # 根据字符串书写格式，将字符串自动转换成 字典类型
            #print("当前扫描器的时间："+str(servertime))


            ###### todo 获取扫描器进行任务名&&任务时间&&任务进度(未完成)
            # s.headers['Referer'] = f'{SCANNER_URL}'
            # resp = requests.get(f'{SCANNER_URL}/list/', verify=False, allow_redirects=False)
            # num_list = []
            # html = etree.HTML(resp.text)  # 初始化生成一个XPath解析对象
            # # xpath匹配当前页的所有任务信息
            # # 提取任务ID
            # task_num = html.xpath('//td/a[@id and @href and @style]/parent::td/preceding-sibling::td[1]/text()')
            # for num in task_num:
            #     num_list.append(num.strip())
            # print("-----------------------task-num-----------------------")
            # print(len(num_list))
            # print(num_list)
            # # 提取任务名称
            # task_name = html.xpath('//a[@id and @href and @style]/@title')
            # print("-----------------------task_name-----------------------")
            # print(len(task_name))
            # print(task_name)
            # # 提取任务开始时间
            # task_start_time = html.xpath('//td/a[@id and @href and @style]/parent::td/following-sibling::td[2]/div/text()')
            # print("-----------------------task_start_time-----------------------")
            # print(len(task_start_time))
            # print(task_start_time)
            # # 提取任务结束时间
            # task_end_time = html.xpath('//td/a[@id and @href and @style]/parent::td/following-sibling::td[3]/div/text()')
            # print("-----------------------task_end_time-----------------------")
            # print(len(task_end_time))
            # print(task_end_time)
            # # 提取任务进度
            # task_progress = html.xpath('//td/a[@id and @href and @style]/parent::td/following-sibling::td[4]/child::text()')
            # for progress in task_progress:
            #     print(progress.strip())
            # print("-----------------------task_progress-----------------------")
            # print(len(task_progress))
            # print(task_progress)







            self.log_return.emit('{}|{}|{}'.format(nowtask_num, waittask_num, servertime))
            time.sleep(10)
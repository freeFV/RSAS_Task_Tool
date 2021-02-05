# !/usr/bin/python3
# -*- coding: utf-8 -*-
"""
@Author         :  matchawat
@Email          :  aaadmin@88.com
------------------------------------
@File           :  start.py
@Version        :  
@Description    :  
@CreateTime     :  2021/1/26/0026 20:08
------------------------------------
@Software       :  PyCharm
"""

import sys
from pycode.login_pane import *
from PyQt5.QtWidgets import QApplication

################################################
#######程序入门
################################################

if __name__ == "__main__":
    app = QApplication(sys.argv)
    login_window = login_pane(mode=0)
    login_window.show()
    sys.exit(app.exec_())

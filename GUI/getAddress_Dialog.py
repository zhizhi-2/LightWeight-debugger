# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'getAddress_Dialog.ui'
#
# Created by: PyQt5 UI code generator 5.15.2
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Dialog_Address(object):
    def setupUi(self, Dialog_Address):
        Dialog_Address.setObjectName("Dialog_Address")
        Dialog_Address.resize(400, 300)
        self.gridLayout = QtWidgets.QGridLayout(Dialog_Address)
        self.gridLayout.setObjectName("gridLayout")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout()
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.label = QtWidgets.QLabel(Dialog_Address)
        self.label.setObjectName("label")
        self.verticalLayout.addWidget(self.label)
        self.label_2 = QtWidgets.QLabel(Dialog_Address)
        self.label_2.setObjectName("label_2")
        self.verticalLayout.addWidget(self.label_2)
        self.label_3 = QtWidgets.QLabel(Dialog_Address)
        self.label_3.setObjectName("label_3")
        self.verticalLayout.addWidget(self.label_3)
        self.horizontalLayout.addLayout(self.verticalLayout)
        self.verticalLayout_2 = QtWidgets.QVBoxLayout()
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.lineEdit_dll = QtWidgets.QLineEdit(Dialog_Address)
        self.lineEdit_dll.setObjectName("lineEdit_dll")
        self.verticalLayout_2.addWidget(self.lineEdit_dll)
        self.lineEdit_function = QtWidgets.QLineEdit(Dialog_Address)
        self.lineEdit_function.setObjectName("lineEdit_function")
        self.verticalLayout_2.addWidget(self.lineEdit_function)
        self.lineEdit_address = QtWidgets.QLineEdit(Dialog_Address)
        self.lineEdit_address.setReadOnly(True)
        self.lineEdit_address.setObjectName("lineEdit_address")
        self.verticalLayout_2.addWidget(self.lineEdit_address)
        self.horizontalLayout.addLayout(self.verticalLayout_2)
        self.verticalLayout_3.addLayout(self.horizontalLayout)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.pushButton_yes = QtWidgets.QPushButton(Dialog_Address)
        self.pushButton_yes.setObjectName("pushButton_yes")
        self.horizontalLayout_2.addWidget(self.pushButton_yes)
        self.pushButton_cancel = QtWidgets.QPushButton(Dialog_Address)
        self.pushButton_cancel.setObjectName("pushButton_cancel")
        self.horizontalLayout_2.addWidget(self.pushButton_cancel)
        self.verticalLayout_3.addLayout(self.horizontalLayout_2)
        self.gridLayout.addLayout(self.verticalLayout_3, 0, 0, 1, 1)

        self.retranslateUi(Dialog_Address)
        QtCore.QMetaObject.connectSlotsByName(Dialog_Address)
        self.pushButton_cancel.clicked.connect(Dialog_Address.reject)

    def retranslateUi(self, Dialog_Address):
        _translate = QtCore.QCoreApplication.translate
        Dialog_Address.setWindowTitle(_translate("Dialog_Address", "Dialog"))
        self.label.setText(_translate("Dialog_Address", "动态链接库名称"))
        self.label_2.setText(_translate("Dialog_Address", "函数名称"))
        self.label_3.setText(_translate("Dialog_Address", "函数地址"))
        self.pushButton_yes.setText(_translate("Dialog_Address", "确定"))
        self.pushButton_cancel.setText(_translate("Dialog_Address", "取消"))
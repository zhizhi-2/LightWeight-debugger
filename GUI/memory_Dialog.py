# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'memory_Dialog.ui'
#
# Created by: PyQt5 UI code generator 5.15.2
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Dialog_memory(object):
    def setupUi(self, Dialog_memory):
        Dialog_memory.setObjectName("Dialog_memory")
        Dialog_memory.resize(385, 168)
        self.gridLayout_2 = QtWidgets.QGridLayout(Dialog_memory)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.gridLayout = QtWidgets.QGridLayout()
        self.gridLayout.setObjectName("gridLayout")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout()
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.label = QtWidgets.QLabel(Dialog_memory)
        self.label.setObjectName("label")
        self.verticalLayout_2.addWidget(self.label)
        self.lineEdit_address = QtWidgets.QLineEdit(Dialog_memory)
        self.lineEdit_address.setObjectName("lineEdit_address")
        self.verticalLayout_2.addWidget(self.lineEdit_address)
        self.horizontalLayout_2.addLayout(self.verticalLayout_2)
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.label_2 = QtWidgets.QLabel(Dialog_memory)
        self.label_2.setObjectName("label_2")
        self.verticalLayout.addWidget(self.label_2)
        self.lineEdit_length = QtWidgets.QLineEdit(Dialog_memory)
        self.lineEdit_length.setObjectName("lineEdit_length")
        self.verticalLayout.addWidget(self.lineEdit_length)
        self.horizontalLayout_2.addLayout(self.verticalLayout)
        self.gridLayout.addLayout(self.horizontalLayout_2, 0, 0, 1, 1)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.pushButton_ok = QtWidgets.QPushButton(Dialog_memory)
        self.pushButton_ok.setObjectName("pushButton_ok")
        self.horizontalLayout.addWidget(self.pushButton_ok)
        self.pushButton_cancel = QtWidgets.QPushButton(Dialog_memory)
        self.pushButton_cancel.setObjectName("pushButton_cancel")
        self.horizontalLayout.addWidget(self.pushButton_cancel)
        self.gridLayout.addLayout(self.horizontalLayout, 1, 0, 1, 1)
        self.gridLayout_2.addLayout(self.gridLayout, 0, 0, 1, 1)

        self.retranslateUi(Dialog_memory)
        self.pushButton_cancel.clicked.connect(Dialog_memory.reject)
        QtCore.QMetaObject.connectSlotsByName(Dialog_memory)

    def retranslateUi(self, Dialog_memory):
        _translate = QtCore.QCoreApplication.translate
        Dialog_memory.setWindowTitle(_translate("Dialog_memory", "Dialog"))
        self.label.setText(_translate("Dialog_memory", "?????????????????????????????????"))
        self.label_2.setText(_translate("Dialog_memory", "??????????????????????????????"))
        self.pushButton_ok.setText(_translate("Dialog_memory", "??????"))
        self.pushButton_cancel.setText(_translate("Dialog_memory", "??????"))

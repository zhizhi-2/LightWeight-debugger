# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'event_Dialog.ui'
#
# Created by: PyQt5 UI code generator 5.15.2
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Dialog_event(object):
    def setupUi(self, Dialog_event):
        Dialog_event.setObjectName("Dialog_event")
        Dialog_event.resize(520, 321)
        self.gridLayout = QtWidgets.QGridLayout(Dialog_event)
        self.gridLayout.setObjectName("gridLayout")
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.label = QtWidgets.QLabel(Dialog_event)
        self.label.setObjectName("label")
        self.verticalLayout.addWidget(self.label)
        self.textBrowser = QtWidgets.QTextBrowser(Dialog_event)
        self.textBrowser.setObjectName("textBrowser")
        self.verticalLayout.addWidget(self.textBrowser)
        self.gridLayout.addLayout(self.verticalLayout, 0, 0, 1, 1)

        self.retranslateUi(Dialog_event)
        QtCore.QMetaObject.connectSlotsByName(Dialog_event)

    def retranslateUi(self, Dialog_event):
        _translate = QtCore.QCoreApplication.translate
        Dialog_event.setWindowTitle(_translate("Dialog_event", "Dialog"))
        self.label.setText(_translate("Dialog_event", "调试事件类型"))

from PyQt5.QtCore import QThread, pyqtSignal
import time
from debugger import *


class myThread(QThread):
    debugSignal = pyqtSignal(str)
    debugger = Debugger()

    def __init__(self):
        super(myThread, self).__init__()
        self.PID = None
        self.falg = False


    def run(self):
        if not self.falg:
            mes = self.debugger.attach(int(self.PID))
            self.falg = True
            self.debugSignal.emit(mes)
            return True
        if self.falg:
            if self.debugger.debugger_active == True:
                mes = self.debugger.get_debug_event()
                time.sleep(1)
                print(mes)
                self.debugSignal.emit(mes)



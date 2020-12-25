import sys, time, os
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QMainWindow, QInputDialog, QScrollBar, QSplitter, QTableWidgetItem, QTableWidget, QComboBox, \
    QVBoxLayout, QGridLayout, QDialog, QWidget, QPushButton, QApplication, QMainWindow, QAction, QMessageBox, QLabel, \
    QTextEdit, QProgressBar, QLineEdit
from PyQt5.QtCore import QCoreApplication
import socket
from threading import Thread
import time
from socketserver import ThreadingMixIn

conn = None


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1920, 700)
        MainWindow.setCursor(QtGui.QCursor(QtCore.Qt.ArrowCursor))

        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")

        self.widget = QtWidgets.QWidget(self.centralwidget)
        self.widget.setGeometry(QtCore.QRect(9, 9, 781, 541))
        self.widget.setObjectName("widget")

        self.verticalLayout = QtWidgets.QVBoxLayout(self.widget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")

        # self.TextW=QtWidgets.QTextEdit(self.widget)
        # self.TextW.setObjectName("TextW")
        # self.TextW.resize(480,100)
        ##self.TextW.move(10,350)
        # self.verticalLayout.addWidget(self.TextW)

        # self.listWidget = QtWidgets.QListWidget(self.widget)
        # selflistWidget.setObjectName("listWidget")
        # self.verticalLayout.addWidget(self.listWidget)

        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")

        self.pushButton = QtWidgets.QPushButton(self.widget)
        self.pushButton.setObjectName("pushButton")
        self.horizontalLayout.addWidget(self.pushButton)

        self.pushButton_2 = QtWidgets.QPushButton(self.widget)
        self.pushButton_2.setObjectName("pushButton_2")
        self.horizontalLayout.addWidget(self.pushButton_2)

        self.pushButton_3 = QtWidgets.QPushButton(self.widget)
        self.pushButton_3.setObjectName("pushButton_3")
        self.horizontalLayout.addWidget(self.pushButton_3)

        self.verticalLayout.addLayout(self.horizontalLayout)
        MainWindow.setCentralWidget(self.centralwidget)

        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 21))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)

        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        global chatTextField
        self.chatTextField = QLineEdit(self)
        self.chatTextField.resize(781, 100)
        self.chatTextField.move(9, 550)
        self.chatBody = QVBoxLayout(self)
        splitter = QSplitter(QtCore.Qt.Vertical)

        # self.btn = QPushButton('Dialog', self)
        # self.btn.move(20, 20)

        # self.le = QLineEdit(self)
        # self.le.move(130, 22)

        # self.setGeometry(300, 300, 290, 150)
        # self.setWindowTitle('Input dialog')
        # self.show()

        MainWindow.resize(800, 700)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.pushButton.setText(_translate("MainWindow", "start"))
        self.pushButton_2.setText(_translate("MainWindow", "file"))
        self.pushButton_3.setText(_translate("MainWindow", "close"))


editorProgram = 'notepad'


class ExampleApp(QtWidgets.QMainWindow, Ui_MainWindow, QDialog):
    def __init__(self):
        super().__init__()
        self.flag = 0
        self.setupUi(self)
        self.pushButton.clicked.connect(self.send)
        self.pushButton_2.clicked.connect(self.Open)
        self.pushButton_3.clicked.connect(self.close)

        global TextW
        self.TextW = QTextEdit()
        self.TextW.setObjectName("TextW")
        self.TextW.resize(480, 100)
        # self.TextW.move(10,350)
        self.verticalLayout.addWidget(self.TextW)
        self.TextW.setReadOnly(True)

    def Open(self):
        file, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'File',
                                                        './',
                                                        'Text Files (*.txt)')
        if not file:
            return

        process = QtCore.QProcess(self)
        process.start(editorProgram, [file])

        self.setEnabled(False)
        process.finished.connect(lambda: self.setEnabled(True))

    def send(self):
        global text
        text = self.chatTextField.text()
        font = self.TextW.font()
        font.setPointSize(13)
        self.TextW.setFont(font)
        textFormatted = '{:>80}'.format(text)
        self.TextW.append(textFormatted)
        global conn
        conn.send(text.encode())
        conn.send("start".encode())
        self.chatTextField.setText("")

    def close(self):
        global text2
        text2 = self.chatTextField.text()
       # font = self.TextW.font()
        #font.setPointSize(13)
        #self.TextW.setFont(font)
        global conn
        conn.send(text2.encode())
        conn.send("close".encode())


class ServerThread(Thread):
    def __init__(self, ExampleApp):
        Thread.__init__(self)
        self.ExampleApp = ExampleApp

    def run(self):
        TCP_IP = '0.0.0.0'
        TCP_PORT = 80
        BUFFER_SIZE = 20
        tcpServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcpServer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcpServer.bind((TCP_IP, TCP_PORT))
        threads = []
        tcpServer.listen(4)

        while True:
            print("Multithreaded Python server : Waiting for connections from TCP clients...")

            global conn
            (conn, (ip, port)) = tcpServer.accept()
            newthread = ClientThread(ip, port, ExampleApp)
            newthread.start()
            threads.append(newthread)

        for t in threads:
            t.join()


class ClientThread(Thread):

    def __init__(self, ip, port, ExampleApp):
        Thread.__init__(self)
        self.ExampleApp = ExampleApp
        self.ip = ip
        self.port = port
        print("[+] New server socket thread started for " + ip + ":" + str(port))

    def run(self):
        while True:

            global conn
            global data
            data = conn.recv(1024)
            # f=open(time.strftime("%Y%m%d-%H")+".txt","w")
            # print(data.decode())

            if len(data) < 3:
                break
                file.close()
            else:
                if len(data) == 5:
                    f = open(data.decode() + time.strftime("%Y%m%d-%H") + ".txt", "a")
                    # print(data, file=f)
                else:
                    # f.write(data.decode() +"\n")
                    print(data, file=f)
                    # sys.stdout=f
                    # with open (text+time.strftime("%Y%m%d-%H")+".txt","a") as file:
                    # file.write(data.decode()+"\n")


def main():
    app = QApplication(sys.argv)
    window = ExampleApp()
    serverThread = ServerThread(ExampleApp)
    window.show()
    serverThread.start()
    app.exec_()


if __name__ == '__main__':
    main()

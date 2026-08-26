import sys

from PyQt5.QtWidgets import QApplication, QDialog, QMainWindow, QStyleFactory

from gui.authDialog import AuthDialog
from gui.mainWindow import MainWindow


class PasswordManagerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setStyle(QStyleFactory.create("Fusion"))
        self.authDialog = AuthDialog()
        self.authDialog.login_successful.connect(self.onLoginSuccess)
        if self.authDialog.exec_() != QDialog.Accepted:
            sys.exit()

    def onLoginSuccess(self):
        self.mainWindow = MainWindow()
        self.setCentralWidget(self.mainWindow)
        self.setGeometry(300, 300, 800, 600)
        self.setWindowTitle("PetitePass")
        self.show()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = PasswordManagerApp()
    sys.exit(app.exec_())

import sys
from PySide6.QtWidgets import QApplication
from ui.main_window import LoginDialog, MainWindow

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setApplicationName("National Security Language Encryption")

    login = LoginDialog()
    if login.exec() and login.current_user:
        window = MainWindow(login.current_user)
        app._active_window = window
        window.show()
        sys.exit(app.exec())
    sys.exit(0)

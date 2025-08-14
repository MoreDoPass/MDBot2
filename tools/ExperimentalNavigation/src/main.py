# src/main.py
import sys
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt 
from gui.MainWindow import MainWindow

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
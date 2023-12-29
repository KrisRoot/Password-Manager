from PyQt5.QtCore import Qt, QRect, QSize
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QIcon
from PyQt5.QtWidgets import (
    QTableView,
    QApplication,
    QMainWindow,
    QAbstractItemView,
    QDialog,
    QListWidget,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QLineEdit,
    QCheckBox,
    QPushButton,
    QListView,
    QMessageBox,
)
from PyQt5 import QtCore, QtGui, QtWidgets
from pyDes import *
import sqlite3
import qdarkstyle
import hashlib
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii, os
import random, string
import base64

THEME = 'light'


def change_theme(theme):
    with open('settings.txt', 'r+') as f:
        lines = f.readlines()
        f.close()

    with open('settings.txt', 'w+') as f:
        f.write(theme + '\n')
        f.write(lines[1].lstrip())


def encrypt_text(text, key):
    key = key * 2
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    padded_text = pad(text.encode('utf-8'), AES.block_size)
    encrypted_text = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted_text).decode('utf-8')


def decrypt_text(encrypted_text, key):
    key = key * 2
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    decrypted_text = cipher.decrypt(base64.b64decode(encrypted_text))
    return unpad(decrypted_text, AES.block_size).decode('utf-8')


def update_data(_id, _name, _password, _description, key):
    conn = sqlite3.connect("database.sqlite")

    cursor = conn.cursor()
    ciphered_pwd = encrypt_text(_password, key)

    cursor.execute(
        "UPDATE database SET name = ?, password = ?, description = ? WHERE id = ?",
        (_name, ciphered_pwd, _description, _id),
    )
    conn.commit()

    cursor.close()
    conn.close()


def get_data(_id):
    conn = sqlite3.connect("database.sqlite")

    cursor = conn.cursor()

    sql_query = f"SELECT * FROM database WHERE id = {_id};"
    cursor.execute(sql_query)
    results = cursor.fetchall()
    return results[0]

    cursor.close()
    conn.close()


def delete_data(_id):
    conn = sqlite3.connect("database.sqlite")

    cursor = conn.cursor()

    sql_query = f"delete from database where id = {_id};"
    cursor.execute(sql_query)
    cursor.execute("SELECT * FROM database")
    rows = cursor.fetchall()

    for i, row in enumerate(rows):
        cursor.execute("UPDATE database SET id=? WHERE id=?", (i, row[0]))

    cursor.close()
    conn.commit()
    conn.close()


def add_data(_id, _name,_description, _password, key):
    conn = sqlite3.connect("database.sqlite")

    cursor = conn.cursor()

    ciphered_pwd = encrypt_text(_password, key)

    sql_insert_query = f"""INSERT OR IGNORE INTO database (id, name, password, description) VALUES 
                        ({_id}, '{_name}', '{ciphered_pwd}', '{_description}')"""
    cursor.execute(sql_insert_query)
    conn.commit()

    cursor.close()
    conn.close()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setGeometry(QRect(0, 0, 800, 550))
        self.setWindowTitle("Password manager")
        self.setFixedSize(800, 500)

        self.central_widget = QWidget(self)
        self.lineedit_setup = QLineEdit(self)
        self.lineedit_setup.setEchoMode(QtWidgets.QLineEdit.Password)
        self.lineedit_setup.setGeometry(QRect(325, 125, 200, 45))
        self.lineedit_setup.textChanged.connect(self.line_edit_setup)

        self.pushbutton_setup = QPushButton("Set password", self)
        self.pushbutton_setup.setGeometry(QRect(375, 200, 100, 40))
        self.pushbutton_setup.setEnabled(False)
        self.pushbutton_setup.clicked.connect(self.set_password)

        self.lineedit_check = QLineEdit(self)
        self.lineedit_check.setEchoMode(QtWidgets.QLineEdit.Password)
        self.lineedit_check.setGeometry(QRect(325, 125, 200, 45))
        self.lineedit_check.textChanged.connect(self.line_edit_check)

        self.pushbutton_check = QPushButton("Enter password", self)
        self.pushbutton_check.setGeometry(QRect(375, 200, 100, 40))
        self.pushbutton_check.setEnabled(False)
        self.pushbutton_check.clicked.connect(self.check_password)

        if len(open("settings.txt", "r").readlines()) < 2:
            self.lineedit_check.setVisible(False)
            self.pushbutton_check.setVisible(False)
        else:
            self.lineedit_setup.setVisible(False)
            self.pushbutton_setup.setVisible(False)

        self.central_widget.setVisible(False)
        self.setCentralWidget(self.central_widget)
        self.mode = "add"
        self.setup_password = "12345678"

        self.label = QLabel("Name", self.central_widget)
        self.label.setGeometry(QRect(221, 1, 191, 51))

        self.label_2 = QLabel("Password", self.central_widget)
        self.label_2.setGeometry(QRect(413, 1, 191, 51))

        self.label_3 = QLabel("Description", self.central_widget)
        self.label_3.setGeometry(QRect(611, 1, 191, 51))

        self.vertical_layout_widget = QWidget(self.central_widget)
        self.vertical_layout_widget.setGeometry(QRect(-1, 49, 221, 441))

        self.vertical_layout = QVBoxLayout(self.vertical_layout_widget)

        self.lineedit = QLineEdit(self.vertical_layout_widget)
        self.lineedit.setPlaceholderText("Name")
        self.vertical_layout.addWidget(self.lineedit)

        self.lineedit_2 = QLineEdit(self.vertical_layout_widget)
        self.lineedit_2.setPlaceholderText("Password")
        self.vertical_layout.addWidget(self.lineedit_2)

        self.checkbox = QCheckBox(self.vertical_layout_widget)
        self.checkbox.setText("Visible")
        self.checkbox.stateChanged.connect(self.checkbox_check)
        self.vertical_layout.addWidget(self.checkbox)

        self.lineedit_3 = QLineEdit(self.vertical_layout_widget)
        self.lineedit_3.setPlaceholderText("Description")
        self.vertical_layout.addWidget(self.lineedit_3)

        self.pushbutton = QPushButton(self.vertical_layout_widget)
        self.pushbutton.setText("Add Key")
        self.vertical_layout.addWidget(self.pushbutton)
        self.pushbutton.clicked.connect(self.save_changes)

        self.pushbutton_3 = QPushButton("", self.central_widget)
        self.pushbutton_3.setGeometry(QRect(0, 0, 50, 50))
        self.pushbutton_3.clicked.connect(self.add_key_mode)

        self.pushbutton_4 = QPushButton("", self.central_widget)
        self.pushbutton_4.setGeometry(QRect(50, 0, 50, 50))
        self.pushbutton_4.clicked.connect(self.delete_key)

        self.pushbutton_5 = QPushButton("", self.central_widget)
        self.pushbutton_5.setGeometry(QRect(100, 0, 50, 50))
        self.pushbutton_5.clicked.connect(self.open_settings)

        self.pushbutton_6 = QPushButton("", self.central_widget)
        self.pushbutton_6.setGeometry(QRect(150, 0, 50, 50))
        self.pushbutton_6.clicked.connect(self.open_about)

        self.listview = QListWidget(self.central_widget)
        self.listview.setGeometry(QRect(220, 50, 188, 439))
        self.listview.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.listview.doubleClicked.connect(self.list_selected)

        self.listview_2 = QListWidget(self.central_widget)
        self.listview_2.setGeometry(QRect(611, 50, 188, 439))
        self.listview_2.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.lineedit_2.setEchoMode(QtWidgets.QLineEdit.Password)
        self.listview_2.doubleClicked.connect(self.list_selected)

        self.listview_3 = QListWidget(self.central_widget)
        self.listview_3.setGeometry(QRect(415, 50, 189, 439))
        self.listview_3.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.listview_3.doubleClicked.connect(self.list_selected)

        self.listview.verticalScrollBar().valueChanged.connect(self.sync_scrollbars)
        self.listview_2.verticalScrollBar().valueChanged.connect(self.sync_scrollbars)
        self.listview_3.verticalScrollBar().valueChanged.connect(self.sync_scrollbars)

        self.listview.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.listview_2.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.listview_3.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)

        if THEME == 'light':
            self.pushbutton_3.setIcon(QIcon('img/add.png'))
            self.pushbutton_3.setIconSize(QSize(50, 50))

            self.pushbutton_4.setIcon(QIcon('img/delete.png'))
            self.pushbutton_4.setIconSize(QSize(50, 50))

            self.pushbutton_5.setIcon(QIcon('img/gear.png'))
            self.pushbutton_5.setIconSize(QSize(48, 48))

            self.pushbutton_6.setIcon(QIcon('img/question.png'))
            self.pushbutton_6.setIconSize(QSize(48, 48))
        else:
            self.pushbutton_3.setIcon(QIcon('img/add_dark.png'))
            self.pushbutton_3.setIconSize(QSize(50, 50))

            self.pushbutton_4.setIcon(QIcon('img/delete_dark.png'))
            self.pushbutton_4.setIconSize(QSize(50, 50))

            self.pushbutton_5.setIcon(QIcon('img/gear_dark.png'))
            self.pushbutton_5.setIconSize(QSize(48, 48))

            self.pushbutton_6.setIcon(QIcon('img/question_dark.png'))
            self.pushbutton_6.setIconSize(QSize(48, 48))

        con = sqlite3.connect("database.sqlite")
        cur = con.cursor()
        if cur.execute("SELECT id FROM database").fetchall() != []:
            last_id = cur.execute("SELECT id FROM database").fetchall()[-1][0] + 1
            con.close()
            for i in range(1, last_id):
                data = get_data(i)
                self.listview.addItems([data[1]])
                try:
                    self.listview_3.addItems([decrypt_text(data[2], self.setup_password)])
                except ValueError:
                    self.listview_3.addItems([data[2]])
                self.listview_2.addItems([data[3]])

    def sync_scrollbars(self, value):
        self.listview.verticalScrollBar().setValue(value)
        self.listview_2.verticalScrollBar().setValue(value)
        self.listview_3.verticalScrollBar().setValue(value)

    def check_password(self):
        file = open("settings.txt", "r")
        pwd = self.lineedit_check.text()
        hash_object = hashlib.md5(pwd.encode())
        hex_dig = hash_object.hexdigest()
        if hex_dig == file.readlines()[1].rstrip():
            self.setup_password = pwd
            self.lineedit_check.setVisible(False)
            self.pushbutton_check.setVisible(False)
            self.central_widget.setVisible(True)
        else:
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Critical)
            msg.setText("Wrong password")
            msg.setWindowTitle("Error")
            msg.exec_()

    def line_edit_check(self):
        if len(self.lineedit_check.text()) == 8:
            self.pushbutton_check.setEnabled(True)
        else:
            self.pushbutton_check.setEnabled(False)

    def checkbox_check(self):
        if self.checkbox.isChecked():
            self.lineedit_2.setEchoMode(QtWidgets.QLineEdit.Normal)
        else:
            self.lineedit_2.setEchoMode(QtWidgets.QLineEdit.Password)

    def line_edit_setup(self):
        if len(self.lineedit_setup.text()) == 8:
            self.pushbutton_setup.setEnabled(True)
        else:
            self.pushbutton_setup.setEnabled(False)

    def set_password(self):
        file = open("settings.txt", "a")
        pwd = self.lineedit_setup.text()
        hash_object = hashlib.md5(pwd.encode())
        hex_dig = hash_object.hexdigest()
        file.write('\n' + hex_dig)
        self.lineedit_setup.setVisible(False)
        self.pushbutton_setup.setVisible(False)
        self.central_widget.setVisible(True)

    def add_key_mode(self):
        self.mode = "add"
        self.pushbutton.setText("Add key")

    def delete_key(self):
        index = self.listview.currentIndex().row()
        self.listview.takeItem(index)
        self.listview_2.takeItem(index)
        self.listview_3.takeItem(index)
        delete_data(index)

    def list_selected(self):
        self.mode = "change"
        self.pushbutton.setText("Change Value")

        id_select = self.listview.currentRow()
        if id_select == -1:
            id_select = self.listview_2.currentRow()
            if id_select == -1:
                id_select = self.listview_3.currentRow()

        self.lineedit.setText(self.listview.item(id_select).text())
        self.lineedit_2.setText(self.listview_3.item(id_select).text())
        self.lineedit_3.setText(self.listview_2.item(id_select).text())

        self.listview.clearSelection()
        self.listview_2.clearSelection()
        self.listview_3.clearSelection()

    def open_settings(self):
        msg = QMessageBox()
        msg.setText("Choose th theme")
        msg.setWindowTitle("Settings")
        msg_no = msg.addButton("Light", msg.NoRole)
        msg_no.clicked.connect(lambda: change_theme('light'))
        msg_yes = msg.addButton("Dark", msg.YesRole)
        msg_yes.clicked.connect(lambda: change_theme('dark'))

        msg.exec_()

    def open_about(self):
        msg = QMessageBox()
        msg.setText("To enter password adding mode press \"Add\" button\n\n" +
                    "To change values double click on the values which you" +
                    "want to edit and then press \"Change value\" button\n\n" +
                    "To delete values double click on the values which you want" +
                    "to delete and then press \"Delete\" button\n\n" +
                    "To open settings press \"Settings\" button\n\n" +
                    "To get help press \"Help\" button\n\n" +
                    "Program made special for Yandex Lyceum\nMade on PyQT5\nYaroslav Demidov")
        msg.setWindowTitle("About")
        msg_no = msg.addButton("Ok", msg.AcceptRole)
        msg.exec_()

    def save_changes(self):
        if self.lineedit.text() and self.lineedit_2.text():
            if self.mode == "add":
                name = self.lineedit.text()
                password = self.lineedit_3.text()
                description = self.lineedit_2.text()
                con = sqlite3.connect("database.sqlite")
                cur = con.cursor()
                if cur.execute("SELECT id FROM database").fetchall() != []:
                    last_id = cur.execute("SELECT id FROM database").fetchall()[-1][0]
                    add_data(last_id + 1, name, password, description, self.setup_password)
                else:
                    add_data(1, name, password, description, self.setup_password)
                con.close()
                self.listview.clear()
                self.listview_2.clear()
                self.listview_3.clear()
                con = sqlite3.connect("database.sqlite")
                cur = con.cursor()
                last_id = cur.execute("SELECT id FROM database").fetchall()[-1][0] + 1
                con.close()
                for i in range(1, last_id):
                    data = get_data(i)
                    self.listview.addItems([data[1]])
                    self.listview_3.addItems([decrypt_text(data[2], self.setup_password)])
                    self.listview_2.addItems([data[3]])

            elif self.mode == "change":
                id_select = -1
                name = self.lineedit.text()
                password = self.lineedit_2.text()
                description = self.lineedit_3.text()
                con = sqlite3.connect("database.sqlite")
                cur = con.cursor()
                id_select = self.listview.currentRow()

                if id_select == -1:
                    id_select = self.listview_2.currentRow()
                    if id_select == -1:
                        id_select = self.listview_3.currentRow()

                update_data(id_select + 1, name, password, description, self.setup_password)
                con.close()
                self.listview.clear()
                self.listview_2.clear()
                self.listview_3.clear()
                con = sqlite3.connect("database.sqlite")
                cur = con.cursor()
                last_id = cur.execute("SELECT id FROM database").fetchall()[-1][0] + 1
                con.close()

                for i in range(1, last_id):
                    data = get_data(i)
                    self.listview.addItems([data[1]])
                    self.listview_3.addItems([decrypt_text(data[2], self.setup_password)])
                    self.listview_2.addItems([data[3]])


if __name__ == "__main__":
    try:
        if open("settings.txt", "r").readlines()[0].rstrip() == "dark":
            THEME = 'dark'
    except IndexError:
        pass
    app = QApplication([])
    if THEME == 'dark':
        app.setStyleSheet(qdarkstyle.load_stylesheet())
    window = MainWindow()
    window.show()
    app.exec_()

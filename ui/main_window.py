from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QPushButton, QMessageBox, QDialog, QTableWidget, QTableWidgetItem,
    QHeaderView, QDialogButtonBox, QAbstractItemView, QLineEdit, QComboBox,
    QTabWidget, QGroupBox, QFormLayout, QFrame
)
from PySide6.QtCore import Qt

from core.auth import (
    ROLE_ADMIN, ROLE_SUBADMIN, ROLE_ANALYST,
    authenticate, load_users, add_user, remove_user, reset_user_password
)
from core.encryption import (
    DEFAULT_MAPPING, load_mapping, save_mapping,
    validate_mapping, encrypt_text, decrypt_text,
    analyze_message, log_security_event, read_audit_logs
)


STYLE = """
QMainWindow, QDialog { background-color: #0f172a; }
QLabel { color: #f8fafc; font-size: 14px; }
QLineEdit, QComboBox {
    background-color: #1e293b; color: #ffffff;
    border: 1px solid #475569; border-radius: 6px;
    padding: 8px 10px; font-size: 14px;
}
QTextEdit {
    background-color: #1e293b; color: #ffffff;
    border: 1px solid #475569; border-radius: 8px;
    padding: 12px; font-size: 15px;
}
QPushButton {
    background-color: #6366f1; color: white;
    padding: 9px 14px; border: 0; border-radius: 8px;
    font-size: 13px; font-weight: bold;
}
QPushButton:hover { background-color: #818cf8; }
QPushButton:disabled {
    background-color: #334155; color: #64748b;
}
QPushButton#dangerBtn { background-color: #dc2626; }
QPushButton#dangerBtn:hover { background-color: #ef4444; }
QPushButton#secondaryBtn { background-color: #334155; }
QPushButton#secondaryBtn:hover { background-color: #475569; }
QTableWidget {
    background-color: #1e293b; color: white;
    gridline-color: #475569; border: 1px solid #475569;
    alternate-background-color: #263449;
}
QTableWidget QHeaderView::section {
    background-color: #334155; color: white;
    padding: 8px; border: 0; font-weight: bold;
}
QTableWidget::item { padding: 5px; }
QTabWidget::pane {
    border: 1px solid #334155; border-radius: 8px;
    background-color: #0f172a;
}
QTabBar::tab {
    background-color: #1e293b; color: #cbd5e1;
    padding: 10px 18px; border-top-left-radius: 6px;
    border-top-right-radius: 6px; margin-right: 4px;
    font-weight: bold;
}
QTabBar::tab:selected {
    background-color: #6366f1; color: #ffffff;
}
QGroupBox {
    border: 1px solid #334155; border-radius: 8px;
    margin-top: 12px; padding-top: 14px;
    color: #93c5fd; font-weight: bold;
}
QGroupBox::title {
    subcontrol-origin: margin; left: 12px; padding: 0 6px;
}
"""


class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("National Security Department — Authentication")
        self.resize(450, 360)
        self.setMinimumSize(420, 340)
        self.setStyleSheet(STYLE)
        self.current_user = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(12)

        badge = QLabel("NATIONAL SECURITY DEPARTMENT")
        badge.setStyleSheet("font-size: 12px; color: #38bdf8; font-weight: bold; letter-spacing: 1px;")
        heading = QLabel("SECURE SYSTEM LOGIN")
        heading.setStyleSheet("font-size: 22px; color: #818cf8; font-weight: bold;")
        desc = QLabel("Sign in with your assigned department credentials.")
        desc.setStyleSheet("color: #cbd5e1; font-size: 13px;")

        form = QFormLayout()
        form.setSpacing(10)
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.returnPressed.connect(self.attempt_login)

        form.addRow("Username:", self.username_input)
        form.addRow("Password:", self.password_input)

        hint = QLabel(
            "Default Accounts — Admin: admin / admin123 | "
            "Subadmin: subadmin1 / sub123 | Analyst: analyst1 / analyst123"
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #94a3b8; font-size: 11px; background-color: #1e293b; padding: 8px; border-radius: 6px;")

        btn_row = QHBoxLayout()
        login_btn = QPushButton("LOGIN")
        cancel_btn = QPushButton("EXIT")
        cancel_btn.setObjectName("secondaryBtn")
        login_btn.clicked.connect(self.attempt_login)
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(login_btn)

        layout.addWidget(badge)
        layout.addWidget(heading)
        layout.addWidget(desc)
        layout.addLayout(form)
        layout.addWidget(hint)
        layout.addStretch()
        layout.addLayout(btn_row)

    def attempt_login(self):
        username = self.username_input.text().strip()
        password = self.password_input.text()
        if not username or not password:
            QMessageBox.warning(self, "Login Required", "Please enter both username and password.")
            return

        user = authenticate(username, password)
        if not user:
            log_security_event(username or "UNKNOWN", "NONE", "FAILED_LOGIN")
            QMessageBox.critical(self, "Access Denied", "Invalid username or password.")
            self.password_input.clear()
            return

        self.current_user = user
        log_security_event(user["username"], user["role"], "LOGIN_SUCCESS")
        self.accept()


class MappingEditor(QDialog):
    """Restricted exclusively to Admin users."""

    def __init__(self, current_mapping, actor, parent=None):
        super().__init__(parent)
        self.actor = actor
        self.setWindowTitle("Admin — Edit Encryption Language Mapping")
        self.resize(610, 720)
        self.setMinimumSize(520, 540)
        self.setStyleSheet(STYLE)
        self.mapping = None

        layout = QVBoxLayout(self)
        heading = QLabel("ADMIN: CUSTOM ENCRYPTION LANGUAGE")
        heading.setStyleSheet("font-size: 20px; color: #818cf8; font-weight: bold;")
        info = QLabel(
            "Only the Chief Administrator can modify the department cipher dictionary. "
            "Subadmins and Analysts use this active cipher in read-only mode."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color: #cbd5e1; font-size: 13px;")
        layout.addWidget(heading)
        layout.addWidget(info)

        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["Original Character", "Cipher Character"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table, 1)

        for source, replacement in current_mapping.items():
            self.add_mapping_row(source, replacement)

        controls = QHBoxLayout()
        add_btn = QPushButton("+ ADD")
        remove_btn = QPushButton("REMOVE SELECTED")
        reset_btn = QPushButton("RESET DEFAULT")
        reset_btn.setObjectName("secondaryBtn")
        add_btn.clicked.connect(self.add_empty_row)
        remove_btn.clicked.connect(self.remove_selected_rows)
        reset_btn.clicked.connect(self.reset_defaults)
        controls.addWidget(add_btn)
        controls.addWidget(remove_btn)
        controls.addStretch()
        controls.addWidget(reset_btn)
        layout.addLayout(controls)

        dialog_buttons = QDialogButtonBox(
            QDialogButtonBox.Save | QDialogButtonBox.Cancel
        )
        dialog_buttons.accepted.connect(self.save_changes)
        dialog_buttons.rejected.connect(self.reject)
        layout.addWidget(dialog_buttons)

    def add_mapping_row(self, source="", replacement=""):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(source))
        self.table.setItem(row, 1, QTableWidgetItem(replacement))

    def add_empty_row(self):
        self.add_mapping_row("", "")
        self.table.setCurrentCell(self.table.rowCount() - 1, 0)
        self.table.editItem(self.table.item(self.table.rowCount() - 1, 0))

    def remove_selected_rows(self):
        rows = sorted({index.row() for index in self.table.selectionModel().selectedRows()},
                      reverse=True)
        if not rows:
            QMessageBox.information(self, "Remove", "Select a row to remove first.")
            return
        for row in rows:
            self.table.removeRow(row)

    def reset_defaults(self):
        self.table.setRowCount(0)
        for source, replacement in DEFAULT_MAPPING.items():
            self.add_mapping_row(source, replacement)

    def save_changes(self):
        if self.actor.get("role") != ROLE_ADMIN:
            QMessageBox.critical(self, "Access Denied", "Only the Admin can modify the encryption language.")
            return

        self.table.clearFocus()
        mapping = {}
        for row in range(self.table.rowCount()):
            source_item = self.table.item(row, 0)
            replacement_item = self.table.item(row, 1)
            source = source_item.text() if source_item else ""
            replacement = replacement_item.text() if replacement_item else ""

            if not source.strip() and not replacement.strip():
                continue
            if not source.strip() or not replacement.strip():
                QMessageBox.warning(
                    self, "Incomplete Row",
                    f"Please complete both columns in row {row + 1}, or remove that row."
                )
                return
            if source in mapping:
                QMessageBox.warning(
                    self, "Duplicate Original",
                    f'"{source}" appears more than once. Each original entry must be unique.'
                )
                return
            mapping[source] = replacement

        error = validate_mapping(mapping)
        if error:
            QMessageBox.warning(self, "Invalid Mapping", error)
            return

        self.mapping = mapping
        self.accept()


class UserManagementDialog(QDialog):
    """Restricted exclusively to Admin: create & manage Subadmins and Analysts."""

    def __init__(self, actor, parent=None):
        super().__init__(parent)
        self.actor = actor
        self.setWindowTitle("Admin — Manage Subadmins & Analysts")
        self.resize(680, 560)
        self.setMinimumSize(600, 480)
        self.setStyleSheet(STYLE)

        layout = QVBoxLayout(self)
        heading = QLabel("ADMIN: OFFICIALS & ANALYST ACCOUNT CONTROL")
        heading.setStyleSheet("font-size: 19px; color: #818cf8; font-weight: bold;")
        sub = QLabel(
            "Only the Admin can register new Subadmins (officials) or Analysts, reset passwords, or revoke access."
        )
        sub.setWordWrap(True)
        sub.setStyleSheet("color: #cbd5e1; font-size: 13px;")
        layout.addWidget(heading)
        layout.addWidget(sub)

        create_box = QGroupBox("Add New Subadmin / Analyst")
        form_layout = QHBoxLayout(create_box)

        self.full_name_input = QLineEdit()
        self.full_name_input.setPlaceholderText("Official Full Name")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Initial Password")
        self.password_input.setEchoMode(QLineEdit.Password)

        self.role_combo = QComboBox()
        self.role_combo.addItems([ROLE_SUBADMIN, ROLE_ANALYST])

        add_user_btn = QPushButton("+ CREATE ACCOUNT")
        add_user_btn.clicked.connect(self.handle_add_user)

        form_layout.addWidget(self.full_name_input, 2)
        form_layout.addWidget(self.username_input, 1)
        form_layout.addWidget(self.password_input, 1)
        form_layout.addWidget(self.role_combo, 1)
        form_layout.addWidget(add_user_btn)
        layout.addWidget(create_box)

        self.users_table = QTableWidget(0, 3)
        self.users_table.setHorizontalHeaderLabels(["Username", "Official Name", "Assigned Role"])
        self.users_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.users_table.verticalHeader().setVisible(False)
        self.users_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.users_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.users_table.setAlternatingRowColors(True)
        layout.addWidget(self.users_table, 1)

        action_row = QHBoxLayout()
        reset_pw_btn = QPushButton("RESET PASSWORD")
        reset_pw_btn.setObjectName("secondaryBtn")
        delete_btn = QPushButton("REVOKE ACCOUNT")
        delete_btn.setObjectName("dangerBtn")
        close_btn = QPushButton("CLOSE")

        reset_pw_btn.clicked.connect(self.handle_reset_password)
        delete_btn.clicked.connect(self.handle_remove_user)
        close_btn.clicked.connect(self.accept)

        action_row.addWidget(reset_pw_btn)
        action_row.addWidget(delete_btn)
        action_row.addStretch()
        action_row.addWidget(close_btn)
        layout.addLayout(action_row)

        self.refresh_table()

    def refresh_table(self):
        users = load_users()
        self.users_table.setRowCount(0)
        for username, info in users.items():
            row = self.users_table.rowCount()
            self.users_table.insertRow(row)
            self.users_table.setItem(row, 0, QTableWidgetItem(username))
            self.users_table.setItem(row, 1, QTableWidgetItem(info.get("full_name", username)))
            self.users_table.setItem(row, 2, QTableWidgetItem(info.get("role", "")))

    def handle_add_user(self):
        ok, msg = add_user(
            self.actor,
            self.username_input.text(),
            self.password_input.text(),
            self.role_combo.currentText(),
            self.full_name_input.text(),
        )
        if not ok:
            QMessageBox.warning(self, "Cannot Create Account", msg)
            return

        log_security_event(
            self.actor["username"],
            self.actor["role"],
            "CREATE_ACCOUNT",
            f"target={self.username_input.text().strip()} role={self.role_combo.currentText()}",
        )
        self.full_name_input.clear()
        self.username_input.clear()
        self.password_input.clear()
        self.refresh_table()
        QMessageBox.information(self, "Account Created", msg)

    def _selected_username(self):
        rows = self.users_table.selectionModel().selectedRows()
        if not rows:
            return None
        return self.users_table.item(rows[0].row(), 0).text()

    def handle_remove_user(self):
        target = self._selected_username()
        if not target:
            QMessageBox.information(self, "Select Account", "Select an account from the list first.")
            return
        ok, msg = remove_user(self.actor, target)
        if not ok:
            QMessageBox.warning(self, "Action Blocked", msg)
            return
        log_security_event(self.actor["username"], self.actor["role"], "REVOKE_ACCOUNT", f"target={target}")
        self.refresh_table()
        QMessageBox.information(self, "Account Revoked", msg)

    def handle_reset_password(self):
        target = self._selected_username()
        if not target:
            QMessageBox.information(self, "Select Account", "Select an account from the list first.")
            return

        pw_dialog = QDialog(self)
        pw_dialog.setWindowTitle(f"Reset Password — {target}")
        pw_dialog.setStyleSheet(STYLE)
        v = QVBoxLayout(pw_dialog)
        v.addWidget(QLabel(f'Enter a new password for "{target}":'))
        pw_edit = QLineEdit()
        pw_edit.setEchoMode(QLineEdit.Password)
        v.addWidget(pw_edit)
        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(pw_dialog.accept)
        btns.rejected.connect(pw_dialog.reject)
        v.addWidget(btns)

        if pw_dialog.exec():
            ok, msg = reset_user_password(self.actor, target, pw_edit.text())
            if not ok:
                QMessageBox.warning(self, "Password Reset Failed", msg)
                return
            log_security_event(self.actor["username"], self.actor["role"], "RESET_PASSWORD", f"target={target}")
            QMessageBox.information(self, "Password Updated", msg)


class MainWindow(QMainWindow):
    def __init__(self, current_user: dict):
        super().__init__()
        self.current_user = current_user
        self.role = current_user.get("role", ROLE_ANALYST)
        self.mapping = load_mapping()

        self.setWindowTitle(f"National Security Encryption System — [{self.role}]")
        self.resize(1120, 880)
        self.setMinimumSize(840, 680)
        self.setStyleSheet(STYLE)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(26, 20, 26, 20)
        layout.setSpacing(12)

        # Header & Role Badge Bar
        header_row = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("NATIONAL SECURITY LANGUAGE ENCRYPTION")
        title.setStyleSheet("font-size: 24px; color: #8186ff; font-weight: bold;")
        subtitle = QLabel("Classified Substitution & Intelligence Analysis Workstation")
        subtitle.setStyleSheet("color: #94a3b8; font-size: 13px;")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)

        role_colors = {
            ROLE_ADMIN: "#dc2626",
            ROLE_SUBADMIN: "#0284c7",
            ROLE_ANALYST: "#059669",
        }
        badge_color = role_colors.get(self.role, "#475569")

        user_info = QLabel(
            f'{current_user.get("full_name", current_user["username"])}  |  ROLE: {self.role.upper()}'
        )
        user_info.setStyleSheet(
            f"background-color: {badge_color}; color: white; font-weight: bold; "
            "padding: 8px 14px; border-radius: 8px; font-size: 12px;"
        )

        switch_user_btn = QPushButton("SWITCH USER")
        switch_user_btn.setObjectName("secondaryBtn")
        switch_user_btn.clicked.connect(self.request_switch_user)

        header_row.addLayout(title_box)
        header_row.addStretch()
        header_row.addWidget(user_info)
        header_row.addWidget(switch_user_btn)
        layout.addLayout(header_row)

        # Role Permission Banner
        perm_descriptions = {
            ROLE_ADMIN: "ADMIN PRIVILEGES: Full access to edit the encryption language, add/revoke Subadmins & Analysts, encrypt/decrypt, and inspect security audit logs.",
            ROLE_SUBADMIN: "SUBADMIN (OFFICIAL) PRIVILEGES: Authorized to encrypt and decrypt official communications. Cipher dictionary editing and user management are locked to Admin.",
            ROLE_ANALYST: "ANALYST PRIVILEGES: Authorized to perform intelligence frequency/coverage analysis and inspect ciphertexts. Cipher editing and account management are restricted.",
        }
        perm_banner = QLabel(perm_descriptions.get(self.role, ""))
        perm_banner.setWordWrap(True)
        perm_banner.setStyleSheet(
            "background-color: #1e293b; color: #e2e8f0; border-left: 4px solid #6366f1; "
            "padding: 10px 12px; border-radius: 6px; font-size: 13px;"
        )
        layout.addWidget(perm_banner)

        # Workspace Tabs
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)

        # Tab 1: Encryption / Decryption Operations
        ops_tab = QWidget()
        ops_layout = QVBoxLayout(ops_tab)
        ops_layout.setContentsMargins(16, 16, 16, 16)
        ops_layout.setSpacing(12)

        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Enter plaintext or intercepted ciphertext here...")

        self.output_text = QTextEdit()
        self.output_text.setPlaceholderText("Processed output will appear here...")
        self.output_text.setReadOnly(True)

        encrypt_btn = QPushButton("ENCRYPT")
        decrypt_btn = QPushButton("DECRYPT")
        analyze_quick_btn = QPushButton("ANALYZE TEXT")
        copy_btn = QPushButton("COPY")
        clear_btn = QPushButton("CLEAR")
        clear_btn.setObjectName("secondaryBtn")

        encrypt_btn.clicked.connect(self.encrypt)
        decrypt_btn.clicked.connect(self.decrypt)
        analyze_quick_btn.clicked.connect(self.run_analysis_from_ops)
        copy_btn.clicked.connect(self.copy_result)
        clear_btn.clicked.connect(self.clear_all)

        # Analysts focus on analysis; Admin & Subadmins perform operational encryption/decryption
        if self.role == ROLE_ANALYST:
            encrypt_btn.setEnabled(False)
            encrypt_btn.setToolTip("Restricted: Only Admin and Subadmin officials can encrypt messages.")
            decrypt_btn.setEnabled(False)
            decrypt_btn.setToolTip("Restricted: Only Admin and Subadmin officials can decrypt messages.")

        btn_row = QHBoxLayout()
        for btn in (encrypt_btn, decrypt_btn, analyze_quick_btn, copy_btn, clear_btn):
            btn_row.addWidget(btn)

        # Admin-only controls bar
        admin_row = QHBoxLayout()
        self.edit_lang_btn = QPushButton("EDIT ENCRYPTION LANGUAGE (ADMIN ONLY)")
        self.manage_users_btn = QPushButton("MANAGE SUBADMINS & ANALYSTS (ADMIN ONLY)")

        self.edit_lang_btn.clicked.connect(self.edit_mapping)
        self.manage_users_btn.clicked.connect(self.manage_users)

        is_admin = self.role == ROLE_ADMIN
        self.edit_lang_btn.setEnabled(is_admin)
        self.manage_users_btn.setEnabled(is_admin)
        if not is_admin:
            self.edit_lang_btn.setToolTip("Locked: Only the Admin can modify the encryption language.")
            self.manage_users_btn.setToolTip("Locked: Only the Admin can add Subadmins or Analysts.")

        admin_row.addWidget(self.edit_lang_btn)
        admin_row.addWidget(self.manage_users_btn)
        admin_row.addStretch()

        ops_layout.addWidget(QLabel("INPUT MESSAGE / CIPHERTEXT"))
        ops_layout.addWidget(self.input_text, 1)
        ops_layout.addLayout(btn_row)
        ops_layout.addLayout(admin_row)
        ops_layout.addWidget(QLabel("OUTPUT RESULT"))
        ops_layout.addWidget(self.output_text, 1)

        self.tabs.addTab(ops_tab, "Operations")

        # Tab 2: Intelligence & Cipher Analysis (Primary workspace for Analyst; also viewable by Admin)
        analysis_tab = QWidget()
        analysis_layout = QVBoxLayout(analysis_tab)
        analysis_layout.setContentsMargins(16, 16, 16, 16)
        analysis_layout.setSpacing(12)

        analysis_info = QLabel(
            "Intelligence Analysis Module: Evaluate symbol frequency, cipher coverage, "
            "and structural patterns on plaintext or intercepted messages."
        )
        analysis_info.setWordWrap(True)
        analysis_info.setStyleSheet("color: #cbd5e1;")

        self.analysis_input = QTextEdit()
        self.analysis_input.setPlaceholderText("Paste message or ciphertext to analyze...")

        run_analysis_btn = QPushButton("RUN INTELLIGENCE ANALYSIS")
        load_from_ops_btn = QPushButton("IMPORT FROM OPERATIONS TAB")
        load_from_ops_btn.setObjectName("secondaryBtn")
        run_analysis_btn.clicked.connect(self.run_analysis)
        load_from_ops_btn.clicked.connect(self.import_to_analysis)

        a_btn_row = QHBoxLayout()
        a_btn_row.addWidget(run_analysis_btn)
        a_btn_row.addWidget(load_from_ops_btn)
        a_btn_row.addStretch()

        self.analysis_report = QTextEdit()
        self.analysis_report.setReadOnly(True)
        self.analysis_report.setPlaceholderText("Analysis metrics and symbol frequency distribution will appear here...")

        analysis_layout.addWidget(analysis_info)
        analysis_layout.addWidget(QLabel("TARGET TEXT FOR ANALYSIS"))
        analysis_layout.addWidget(self.analysis_input, 1)
        analysis_layout.addLayout(a_btn_row)
        analysis_layout.addWidget(QLabel("INTELLIGENCE ANALYSIS REPORT"))
        analysis_layout.addWidget(self.analysis_report, 1)

        self.tabs.addTab(analysis_tab, "Intelligence Analysis")

        # Tab 3: Security Audit Log (Admin only)
        if is_admin:
            audit_tab = QWidget()
            audit_layout = QVBoxLayout(audit_tab)
            audit_layout.setContentsMargins(16, 16, 16, 16)
            audit_layout.setSpacing(10)

            self.audit_view = QTextEdit()
            self.audit_view.setReadOnly(True)
            self.audit_view.setPlainText(read_audit_logs())

            refresh_log_btn = QPushButton("REFRESH AUDIT LOG")
            refresh_log_btn.clicked.connect(lambda: self.audit_view.setPlainText(read_audit_logs()))

            audit_layout.addWidget(QLabel("DEPARTMENT SECURITY AUDIT TRAIL (ADMIN ONLY)"))
            audit_layout.addWidget(self.audit_view, 1)
            audit_layout.addWidget(refresh_log_btn)
            self.tabs.addTab(audit_tab, "Security Audit Log")

        # Default Analyst directly to Intelligence Analysis tab
        if self.role == ROLE_ANALYST:
            self.tabs.setCurrentIndex(1)

        footer = QLabel(
            f"National Security Encryption System | Active User: {current_user['username']} ({self.role})"
        )
        footer.setStyleSheet("color: #94a3b8; font-size: 11px;")
        layout.addWidget(footer)

    def encrypt(self):
        if self.role not in (ROLE_ADMIN, ROLE_SUBADMIN):
            QMessageBox.critical(self, "Access Denied", "Only Admin or Subadmin officials can encrypt messages.")
            return
        text = self.input_text.toPlainText()
        if not text.strip():
            QMessageBox.warning(self, "Warning", "Enter some text first.")
            return
        self.output_text.setPlainText(encrypt_text(text, self.mapping))
        log_security_event(self.current_user["username"], self.role, "ENCRYPT_MESSAGE", f"chars={len(text)}")

    def decrypt(self):
        if self.role not in (ROLE_ADMIN, ROLE_SUBADMIN):
            QMessageBox.critical(self, "Access Denied", "Only Admin or Subadmin officials can decrypt messages.")
            return
        text = self.input_text.toPlainText()
        if not text.strip():
            text = self.output_text.toPlainText()
            if not text.strip():
                QMessageBox.warning(self, "Warning", "Enter encrypted text first.")
                return
            self.input_text.setPlainText(text)
        self.output_text.setPlainText(decrypt_text(text, self.mapping))
        log_security_event(self.current_user["username"], self.role, "DECRYPT_MESSAGE", f"chars={len(text)}")

    def copy_result(self):
        result = self.output_text.toPlainText()
        if not result:
            QMessageBox.information(self, "Copy", "There is no output to copy.")
            return
        QApplication.clipboard().setText(result)
        QMessageBox.information(self, "Copied", "Output copied successfully.")

    def clear_all(self):
        self.input_text.clear()
        self.output_text.clear()

    def edit_mapping(self):
        if self.role != ROLE_ADMIN:
            QMessageBox.critical(self, "Access Denied", "Only the Admin can edit the encryption language.")
            return
        dialog = MappingEditor(self.mapping, self.current_user, self)
        if dialog.exec():
            self.mapping = dialog.mapping
            save_mapping(self.mapping)
            log_security_event(
                self.current_user["username"],
                self.role,
                "UPDATE_CIPHER_LANGUAGE",
                f"entries={len(self.mapping)}",
            )
            QMessageBox.information(
                self, "Mapping Saved",
                "The updated encryption language has been saved and deployed to all officials."
            )

    def manage_users(self):
        if self.role != ROLE_ADMIN:
            QMessageBox.critical(self, "Access Denied", "Only the Admin can manage Subadmins and Analysts.")
            return
        dialog = UserManagementDialog(self.current_user, self)
        dialog.exec()

    def import_to_analysis(self):
        source = self.output_text.toPlainText().strip() or self.input_text.toPlainText().strip()
        if not source:
            QMessageBox.information(self, "No Text", "Enter or generate text in the Operations tab first.")
            return
        self.analysis_input.setPlainText(source)

    def run_analysis_from_ops(self):
        source = self.output_text.toPlainText().strip() or self.input_text.toPlainText().strip()
        if not source:
            QMessageBox.warning(self, "Warning", "Enter text to analyze first.")
            return
        self.analysis_input.setPlainText(source)
        self.tabs.setCurrentIndex(1)
        self.run_analysis()

    def run_analysis(self):
        text = self.analysis_input.toPlainText()
        if not text.strip():
            QMessageBox.warning(self, "Warning", "Enter or import text to analyze first.")
            return

        stats = analyze_message(text, self.mapping)
        top_lines = "\n".join(
            f"  • '{sym}' : {count} occurrence(s) ({round((count / stats['non_space_chars']) * 100, 1)}%)"
            for sym, count in stats["top_symbols"]
        ) or "  • None"

        unmapped_lines = ", ".join(
            f"'{ch}' ({cnt})" for ch, cnt in stats["unmapped_chars"]
        ) or "None (100% mapped)"

        report = (
            "=== INTELLIGENCE & CIPHER ANALYSIS REPORT ===\n"
            f"Analyst / Operator : {self.current_user.get('full_name')} ({self.role})\n"
            f"Detected Format    : {stats['detected_mode']}\n"
            f"Total Characters   : {stats['total_chars']} (Non-whitespace: {stats['non_space_chars']})\n"
            f"Word Count         : {stats['word_count']}\n"
            f"Line Count         : {stats['line_count']}\n"
            f"Unique Symbols     : {stats['unique_symbols']}\n"
            f"Cipher Coverage    : {stats['coverage_pct']}%\n\n"
            "Top Symbol Frequencies:\n"
            f"{top_lines}\n\n"
            f"Unmapped Characters: {unmapped_lines}\n"
        )
        self.analysis_report.setPlainText(report)
        log_security_event(
            self.current_user["username"],
            self.role,
            "ANALYZE_MESSAGE",
            f"mode={stats['detected_mode']} chars={stats['total_chars']}",
        )

    def request_switch_user(self):
        log_security_event(self.current_user["username"], self.role, "LOGOUT")
        self.close()
        login = LoginDialog()
        if login.exec() and login.current_user:
            new_win = MainWindow(login.current_user)
            new_win.show()
            QApplication.instance()._active_window = new_win

from PyQt5.QtWidgets import QDialog, QFormLayout, QLabel, QLineEdit, QMessageBox, QPushButton

from petitepass.core.strength import evaluate, is_common

_SCORE_LABEL = {
    0: "Very weak", 1: "Weak", 2: "Fair", 3: "Strong", 4: "Very strong",
}


class CheckPasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
        self.setFixedHeight(220)
        self.setFixedWidth(420)
        self.setWindowTitle("Check password strength")

    def initUI(self):
        self.scoreLabel = QLabel("Strength:")
        self.crackTimeLabel = QLabel("Estimated crack time:")
        self.feedbackLabel = QLabel("")
        self.feedbackLabel.setWordWrap(True)

        layout = QFormLayout(self)
        self.passwordField = QLineEdit(self)
        self.checkButton = QPushButton("Check Password", self)
        self.checkButton.clicked.connect(self.checkPassword)
        layout.addRow(QLabel("Password:"), self.passwordField)
        layout.addWidget(self.checkButton)
        layout.addRow(QLabel())
        layout.addRow(self.scoreLabel)
        layout.addRow(self.crackTimeLabel)
        layout.addRow(self.feedbackLabel)

    def checkPassword(self):
        password = self.passwordField.text()
        if password == "":
            QMessageBox.warning(self, "Error", "The password cannot be empty.")
            return

        result = evaluate(password)
        self.scoreLabel.setText(
            f"Strength: {_SCORE_LABEL.get(result.score, result.score)} "
            f"({result.score}/4)")
        self.crackTimeLabel.setText(
            f"Estimated crack time (offline, slow hash): {result.crack_time}")

        messages = []
        if is_common(password):
            messages.append("This password is in the list of most common passwords.")
        if result.warning:
            messages.append(result.warning)
        messages.extend(result.suggestions)
        self.feedbackLabel.setText("\n".join(messages) if messages
                                   else "This is a strong password.")

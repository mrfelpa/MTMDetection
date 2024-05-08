import sys
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QVBoxLayout,
    QWidget,
    QLabel,
    QPushButton,
    QTextEdit,
)
from scapy.all import sniff, ARP, conf
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline

# Placeholder function for feature extraction
def extract_features(pkt):
    return [1, 2, 3, 4] 

class MITM_Detector(QMainWindow):
    def __init__(self):
        super().__init__()

        self.ml_model = make_pipeline(StandardScaler(), RandomForestClassifier())  # Initialize machine learning model
        self.alert_threshold = 0.9  # Confidence threshold for triggering an alert

        self.setWindowTitle("MITM Attack Detector")

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout()
        central_widget.setLayout(layout)

        self.label = QLabel("MITM Attack Detection")
        layout.addWidget(self.label)

        self.start_button = QPushButton("Start Detection")
        self.start_button.clicked.connect(self.start_detection)
        layout.addWidget(self.start_button)

        self.log_text = QTextEdit()
        layout.addWidget(self.log_text)

        self.train_model()

    def train_model(self):
        # Replace this with actual training data and logic
        X_train = [[1, 2, 3, 4], [2, 3, 4, 5]]  
        y_train = [0, 1]  
        self.ml_model.fit(X_train, y_train)

    def ml_prediction(self, pkt):
        features = extract_features(pkt)

        # Make prediction using the machine learning model
        confidence = self.ml_model.predict_proba([features])[0][1]

        # Check if prediction confidence exceeds threshold
        if confidence > self.alert_threshold:
            self.trigger_alert(pkt, confidence)

    def trigger_alert(self, pkt, confidence):
        alert_msg = f"Alert: Potential MITM attack detected with confidence {confidence}: {pkt.summary()}\n"
        self.log_text.append(alert_msg)

    def real_time_monitoring(self):
        self.log_text.append("MITM Detection started...\n")
        sniff(prn=self.ml_prediction, store=0, iface=conf.iface, filter="arp")

    def start_detection(self):
        self.real_time_monitoring()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MITM_Detector()
    window.show()
    sys.exit(app.exec_())

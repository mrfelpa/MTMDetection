import sys
import logging
import numpy as np
from scapy.all import sniff, ARP, conf
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QVBoxLayout,
    QWidget,
    QLabel,
    QPushButton,
    QTextEdit,
)

def extract_arp_features(pkt):
    features = [
        pkt.op,  # ARP operation (request or reply)
        len(pkt.hwsrc),  # Length of hardware source address
        len(pkt.psrc),  # Length of protocol source address
        len(pkt.hwdst),  # Length of hardware destination address
        len(pkt.pdst),  # Length of protocol destination address
    ]
    return features

def extract_tcp_features(pkt):
    features = [
        pkt.sport,  # Source port
        pkt.dport,  # Destination port
        pkt.seq,  # TCP sequence number
        pkt.ack,  # TCP acknowledgment number
        pkt.window,  # TCP window size
    ]
    return features

def extract_features(pkt):
    if pkt.haslayer(ARP):
        return extract_arp_features(pkt[ARP])
    elif pkt.haslayer("TCP"):
        return extract_tcp_features(pkt[TCP]) # type: ignore
    else:
        return []  # Return empty features for unsupported packet types

class MITM_Detector(QMainWindow):
    def __init__(self):
        super().__init__()

        self.ml_model = make_pipeline(StandardScaler(), RandomForestClassifier())  
        self.alert_threshold = 0.9  

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

        self.setup_logging()
        self.train_model()

    def setup_logging(self):
        logging.basicConfig(filename='mitm_detector.log', level=logging.INFO, format='%(asctime)s - %(message)s')

    def train_model(self):
        # Replace this with actual training data and logic
        X_train = [extract_arp_features(pkt) for pkt in arp_packets] # type: ignore
        y_train = [0, 1]  
        self.ml_model.fit(X_train, y_train)

    def ml_prediction(self, pkt):
        features = extract_features(pkt)

        confidence = self.ml_model.predict_proba([features])[0][1]

        if confidence > self.alert_threshold:
            self.trigger_alert(pkt, confidence)

    def trigger_alert(self, pkt, confidence):
        alert_msg = f"Alert: Potential MITM attack detected with confidence {confidence}: {pkt.summary()}\n"
        self.log_text.append(alert_msg)
        logging.info(alert_msg)

    def real_time_monitoring(self):
        self.log_text.append("MITM Detection started...\n")
        sniff(prn=self.ml_prediction, store=0, iface=conf.iface, filter="arp or tcp")

    def start_detection(self):
        self.real_time_monitoring()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MITM_Detector()
    window.show()
    sys.exit(app.exec_())
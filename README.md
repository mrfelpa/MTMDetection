# Features

- Real-time network traffic monitoring
- Feature extraction for analysis of network packets (placeholder implementation provided)
- Machine learning model for MITM attack detection (placeholder training data used)
- Confidence threshold for triggering alerts
  
![mtm_AI](https://github.com/mrfelpa/MTMDetection/assets/65371336/7fb6400a-4425-4ae9-8523-314b1d42c842)

# Prerequisites:

- Python 3.x (https://www.python.org/downloads/)
- PyQt5 
- Scapy 
- scikit-learn 
  
- Install the required libraries using the following command:

        pip install -r requirements.txt

# Using the Application

- Click the ***"Start Detection"*** button to initiate real-time network traffic monitoring.
- The application will begin capturing network packets ***(specifically ARP packets)*** and analyzing them using the machine learning model.
- If the model's confidence in detecting a potential MITM attack exceeds ***the pre-defined threshold (0.9 by default),*** an alert message will be displayed in the log text box, providing details about the suspicious packet.

# Important Notes

- The current implementation uses placeholder functions for feature extraction and model training. You'll need to replace these with your own logic and training data for effective MITM detection.
- Adjust the confidence threshold (alert_threshold) in the source code to suit your desired level of sensitivity. Lower thresholds may generate more alerts, while higher thresholds might miss some attacks.

# Disclaimer

- This is a basic framework for a MITM detection tool and in development. Additional development will be implemented for robust attack detection and assertiveness in production environments.

# Future Enhancements

- [ ] feature engineering techniques to extract meaningful information from network packets.
- [ ] Train the machine learning model with a comprehensive dataset of labeled network traffic (MITM attacks and normal traffic).

DoS Alarm System
The DoS Alarm System is a Python-based network monitoring tool that detects potential Denial-of-Service (DoS) attacks by monitoring network traffic for abnormal SYN and UDP packet rates. In addition, the system uses anomaly detection with K-Means clustering to identify unusual traffic patterns.

Warning:
This tool is intended for educational purposes and authorized network monitoring only. Ensure you have proper permission before running this tool on any network.

Table of Contents
Features
Requirements
Installation
Usage
Configuration
Performance Metrics
Code Overview
Disclaimer
Features
Real-Time Packet Monitoring:
Sniffs network packets on a user-selected interface.

Threshold-Based Detection:
Raises alerts if the number of SYN or UDP packets within a time window exceeds defined thresholds.

Anomaly Detection:
Uses K-Means clustering to analyze traffic patterns and detect anomalies.

Performance Metrics Logging:
Logs metrics such as true positives, false positives, false negatives, and detection times into a performance metrics file.

User-Friendly Interface Selection:
Displays available network interfaces with friendly names and allows the user to select one.

Requirements
Python 3.6+
Scapy
psutil
scikit-learn
numpy
You can install the required packages using pip:

bash
Copy
pip install scapy psutil scikit-learn numpy
Installation
Clone the Repository:

bash
Copy
git clone https://github.com/dromech/ddos_alarm.git
cd ddos_alarm
Install Dependencies:

bash
Copy
pip install -r requirements.txt
If you don't have a requirements.txt, you can install the dependencies manually as shown in the Requirements section.

Usage
Run the Script:

bash
Copy
python dos_alarm_system.py
Select a Network Interface:
Upon starting, the tool will list all available network interfaces with friendly names. Input the number corresponding to the interface you wish to monitor.

Monitor Traffic:
The system will begin capturing packets and will alert you if it detects:

A high rate of SYN packets (potential SYN flood attack)
A high rate of UDP packets
Anomalous traffic patterns based on historical data
Stopping the Tool:
Use Ctrl+C to gracefully stop the tool. Upon shutdown, the system logs cumulative performance metrics to performance_metrics.txt.

Configuration
You can adjust various parameters directly in the script:

Packet Thresholds:

THRESHOLD_SYN: Number of SYN packets per window to trigger an alert.
THRESHOLD_UDP: Number of UDP packets per window to trigger an alert.
Time Window:

WINDOW_SIZE: The duration (in seconds) of the monitoring window.
Anomaly Detection:

ANOMALY_THRESHOLD: The ratio threshold used in the K-Means clustering anomaly detection.
Performance Metrics File:

METRICS_FILE: Name of the file where performance metrics are logged.
Performance Metrics
The system tracks and logs the following metrics:

True Positives:
Number of correctly detected DoS events.

False Positives:
Number of alerts raised when no actual DoS event occurred.

False Negatives:
Number of DoS events that were missed.

Detection Times:
Time taken to detect each event.

Metrics are logged at the end of each time window in the performance_metrics.txt file.

Code Overview
Packet Sniffing:
Uses Scapy’s sniff function to capture IP packets on the selected network interface.

Processing Packets:
Each packet is analyzed in process_packet(). The script increments counters for SYN and UDP packets, prints alerts when thresholds are exceeded, and stores data for anomaly detection.

Anomaly Detection:
The detect_anomaly() function employs K-Means clustering to compare traffic patterns against historical data.

Interface Selection:
Functions get_friendly_names(), list_interfaces_with_names(), and select_interface() provide a user-friendly mechanism for selecting the correct network interface.

Threading:
Packet sniffing runs in a separate thread to facilitate graceful shutdowns.

Disclaimer
This software is provided for educational purposes only.
Unauthorized use of this tool on networks that you do not own or have explicit permission to monitor may be illegal. The author is not responsible for any misuse or damages caused by this software.
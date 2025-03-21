Created by Liam Calder

DoS Alarm System:  
The DoS Alarm System is a Python-based network monitoring tool designed to detect potential Denial-of-Service (DoS) attacks by monitoring network traffic for abnormal SYN and UDP packet rates. The tool also leverages anomaly detection with K-Means clustering to identify unusual traffic patterns.

Warning:  
This tool is intended for educational purposes and authorized network monitoring only. Ensure you have proper permission before running this tool on any network.

Current Features:  
Threshold-Based Detection:  
Raises alerts if the number of SYN or UDP packets within a given time window exceeds defined thresholds.

Anomaly Detection:  
Uses A multi-stage detection system with both volume-based checks and pattern-based anomaly detection.  
* Auto-calibrating parameters based on network traffic patterns  
* Training mode to establish baseline traffic before detection  
* Consecutive anomaly tracking to reduce false positives  
* 3-sigma rule for establishing reliable anomaly boundaries  
* JSON-based persistent storage of traffic patterns across system restarts

Performance Metrics Logging:  
Logs metrics such into a performance metrics file (performance_metrics.txt).

User-Friendly Interface Selection:  
Displays available network interfaces with friendly names and allows the user to select one for monitoring.

Packet Sniffing & Processing:  
Captures IP packets using Scapy’s sniff function and processes each packet to update counters and store data for anomaly detection.

Threading:  
Runs packet sniffing in a separate thread to facilitate graceful shutdown using Ctrl+C.

Modular Detection Switching:  
Encapsulate threshold-based detection and anomaly detection in separate modules to allow for controlled comparisons.

Installation:  
Clone the repository:  
bash  
Copy  
git clone [<repository_url>](https://github.com/dromech/ddos_alarm)  
Install dependencies:  
bash  
Copy  
pip install -r requirements.txt  
Usage  
Run the script:  
bash  
Copy  
python alarm.py  

Usage  
Run the script:  
bash  
python alarm.py

Select a Network Interface: 
Upon starting, the tool will list all available network interfaces with friendly names. Input the number corresponding to the interface you wish to monitor.

Monitor Traffic:  
The system will begin capturing packets and alert you if it detects:

A high rate of SYN packets (potential SYN flood attack)  
A high rate of UDP packets  
Anomalous traffic patterns based on historical data  

Stop the Tool:  
Use Ctrl+C to gracefully stop the tool. Upon shutdown, performance metrics are logged to a timestamped metrics file.

Configuration:  
Adjust various parameters directly in the script:  

Packet Thresholds:  
THRESHOLD_SYN: Number of SYN packets per window to trigger an alert.
THRESHOLD_UDP: Number of UDP packets per window to trigger an alert.

Time Window:  
WINDOW_SIZE: The duration (in seconds) of the monitoring window.

Anomaly Detection:  
anomaly_threshold: Number of consecutive anomalous windows required to trigger an alert (default: 3)  
distance_threshold: Auto-calculated based on traffic statistics with minimum threshold protection

Code Overview:  
Packet Sniffing:  
Utilizes Scapy’s sniff function to capture IP packets on the selected network interface.

Processing Packets:  
Each packet is analyzed in process_packet(), where counters for SYN and UDP packets are incremented, alerts are printed when thresholds are exceeded, and data is stored for anomaly detection.

Interface Selection:  
Functions get_friendly_names(), list_interfaces_with_names(), and select_interface() provide a user-friendly mechanism for choosing the correct network interface.

Threading:  
Packet sniffing is performed in a separate thread to facilitate a graceful shutdown.

Disclaimer:  
This software is provided for educational purposes only. Unauthorized use of this tool on networks that you do not own or have explicit permission to monitor may be illegal. The author is not responsible for any misuse or damages caused by this software.
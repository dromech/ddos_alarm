Created by Liam Calder

DoS Alarm System:  
The DoS Alarm System is a Python-based network monitoring tool designed to detect potential Denial-of-Service (DoS) attacks by monitoring network traffic for abnormal SYN and UDP packet rates. The tool also leverages anomaly detection with K-Means clustering to identify unusual traffic patterns.

Warning:  
This tool is intended for educational purposes and authorized network monitoring only. Ensure you have proper permission before running this tool on any network.

Current Features:  
Threshold-Based Detection:  
Raises alerts if the number of SYN or UDP packets within a given time window exceeds defined thresholds.

Anomaly Detection:  
Uses K-Means clustering to analyze traffic patterns and detect anomalies based on historical data.

Performance Metrics Logging:  
Logs metrics such as true positives, false positives, false negatives, and detection times into a performance metrics file (performance_metrics.txt).

User-Friendly Interface Selection:  
Displays available network interfaces with friendly names and allows the user to select one for monitoring.

Packet Sniffing & Processing:  
Captures IP packets using Scapy’s sniff function and processes each packet to update counters and store data for anomaly detection.

Threading:  
Runs packet sniffing in a separate thread to facilitate graceful shutdown using Ctrl+C.

Planned Enhancements:  
Modular Detection Switching:  

Implement configuration options or command-line arguments to switch between detection methods.
Encapsulate threshold-based detection and anomaly detection in separate modules to allow for controlled comparisons.
Enhanced Anomaly Detection:  

Further tune K-Means parameters for better performance.
Explore additional models such as autoencoders.
Expand feature extraction to include additional traffic characteristics (e.g., packet sizes, inter-arrival times).

Improved Performance Metrics:  

Log additional details such as CPU and memory usage, and more precise timestamps for each event.
Refine logic to accurately capture false positives and false negatives within each monitoring window.

Advanced Alerting Mechanisms:  

Extend alerting beyond console output by integrating email notifications via SMTP and possibly SMS alerts.
Implement rate-limiting to prevent alert flooding during prolonged attacks.

DoS Attack Simulation Module:  

Develop a module to simulate various DoS attacks (e.g., TCP SYN Flood, UDP Flood, Slowloris) for controlled testing of the detection methods.
Allow configuration of simulation parameters to validate the system under different attack scenarios.

Comprehensive Documentation & Reporting:  

Update documentation with detailed installation instructions, usage guidelines, and configuration options.
Prepare a final report that includes a comparative analysis of detection methods and performance metrics.

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

Select a Network Interface:  
Upon starting, the tool will list all available network interfaces with friendly names. Input the number corresponding to the interface you wish to monitor.

Monitor Traffic:  
The system will begin capturing packets and alert you if it detects:

A high rate of SYN packets (potential SYN flood attack)  
A high rate of UDP packets  
Anomalous traffic patterns based on historical data  

Stop the Tool:  
Use Ctrl+C to gracefully stop the tool. Upon shutdown, cumulative performance metrics are logged to performance_metrics.txt.

Configuration:  
Adjust various parameters directly in the script:  

Packet Thresholds:  
THRESHOLD_SYN: Number of SYN packets per window to trigger an alert.
THRESHOLD_UDP: Number of UDP packets per window to trigger an alert.

Time Window:  
WINDOW_SIZE: The duration (in seconds) of the monitoring window.

Anomaly Detection:  
ANOMALY_THRESHOLD: The ratio threshold used in the K-Means clustering anomaly detection.

Performance Metrics File:  
METRICS_FILE: The filename for logging performance metrics.  
Performance Metrics  

The system tracks and logs the following metrics in performance_metrics.txt:  

True Positives:  
Number of correctly detected DoS events.

False Positives:  
Number of alerts raised when no actual DoS event occurred.

False Negatives:  
Number of DoS events that were missed.

Detection Times:  
The time taken to detect each event.

Metrics are logged at the end of each monitoring window.

Code Overview:  
Packet Sniffing:  
Utilizes Scapy’s sniff function to capture IP packets on the selected network interface.

Processing Packets:  
Each packet is analyzed in process_packet(), where counters for SYN and UDP packets are incremented, alerts are printed when thresholds are exceeded, and data is stored for anomaly detection.

Anomaly Detection:  
The detect_anomaly() function employs K-Means clustering to compare current traffic patterns against historical data.

Interface Selection:  
Functions get_friendly_names(), list_interfaces_with_names(), and select_interface() provide a user-friendly mechanism for choosing the correct network interface.

Threading:  
Packet sniffing is performed in a separate thread to facilitate a graceful shutdown.

Disclaimer:  
This software is provided for educational purposes only. Unauthorized use of this tool on networks that you do not own or have explicit permission to monitor may be illegal. The author is not responsible for any misuse or damages caused by this software.
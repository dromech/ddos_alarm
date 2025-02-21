import psutil
from scapy.all import sniff, TCP, UDP, IP, get_if_list
from collections import defaultdict
import time
from sklearn.cluster import KMeans
import numpy as np
import sys
import threading

# Liam Calder

# TO DO ---------------------------------------------------
"""
- Add modular switching functionality to select between detection methods. (done)
    - Create a configuration option or command-line argument to choose between: (done)
        - Threshold-based detection.
        - Anomaly detection.
    - Encapsulate each detection method in its own function or class. (done so far)

- Enhance anomaly detection:
    - Tune KMeans parameters (e.g., number of clusters, initialization settings).
    - Implement an additional anomaly detection model (such as an autoencoder).
    - Expand feature extraction to include additional traffic characteristics (e.g., packet sizes, inter-arrival times).

- Improve performance metric logging:
    - Log additional details such as CPU and memory usage during detection.
    - Record detailed timestamps for alerts. (done)
    - Accurately log counts of false positives and false negatives.
    - Refine metric reset logic for each time window.

- Upgrade alerting mechanisms:
    - Integrate email notifications (maybe using SMTP).
    - Implement SMS or other messaging service alerts.
    - Add rate-limiting to avoid alert flooding during prolonged attacks.

- Develop a simulation module for DoS attacks:
    - Implement simulations for TCP SYN Flood, UDP Flood, and Slowloris attacks. (have basic SYN Flood and UDP Flood) (may need improvment)
    - Allow configuration of simulation parameters to test detection methods under various conditions.
    - Automate attack simulations to generate comprehensive performance data.

- Update documentation:
    - Document all new functions and classes.
    - Update the README with installation instructions, usage guidelines, and configuration options. (done)
    - Prepare a final report detailing the comparative analysis of detection methods and performance metrics.
"""
# TO DO ---------------------------------------------------

# Configuration
THRESHOLD_SYN = 100  # SYN packets per window to trigger alert
THRESHOLD_UDP = 200  # UDP packets per window to trigger alert
WINDOW_SIZE = 10     # Time window in seconds
ANOMALY_THRESHOLD = 0.1  # Threshold for anomaly detection ratio

# Performance Metrics File
METRICS_FILE = 'performance_metrics.txt'

# Globals for Threshold-Based Detection
packet_counts = defaultdict(int)
start_time = time.time()

# Globals for Anomaly Detection
traffic_history = []

# Metrics Counters (Cumulative)
metrics_total = {
    'true_positives': 0,
    'false_positives': 0,
    'false_negatives': 0,
    'detection_times': [],
    'window_pps': [],
    'attack_durations': [],
    'attack_pps': [],  
    'attack_sources': []
}

# Flag to control sniffing
stop_sniffing = False
window_start_time = time.time()

# Global variables for enhanced threshold attack tracking
# Separate state for SYN and UDP floods
attack_state_syn = {"active": False, "start_time": None, "sources": set()}
attack_state_udp = {"active": False, "start_time": None, "sources": set()}

def send_alert(subject, body):
    """Print alert to console."""
    print(f"\n=== ALERT ===\n{subject}\n{body}\n==============\n")

def log_metrics():
    """Append the current window's metrics to the performance metrics file."""
    with open(METRICS_FILE, 'a') as f:
        f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"True Positives (Window): {metrics_total['true_positives']}\n")
        f.write(f"False Positives (Window): {metrics_total['false_positives']}\n")
        f.write(f"False Negatives (Window): {metrics_total['false_negatives']}\n")
        if metrics_total['detection_times']:
            avg_time = sum(metrics_total['detection_times']) / len(metrics_total['detection_times'])
        else:
            avg_time = 0
        f.write(f"Average Detection Time (Window): {avg_time:.2f} seconds\n")
        f.write("-----\n")

# --- Detector Classes ---

class ThresholdDetector:
    """Handles threshold-based detection by counting packets."""
    def __init__(self, syn_threshold, udp_threshold):
        self.syn_threshold = syn_threshold
        self.udp_threshold = udp_threshold
        self.packet_counts = defaultdict(int)
        self.source_ips = set()  # Collect source IP addresses
    
    def update(self, packet):
        if packet.haslayer(IP):
            self.source_ips.add(packet[IP].src)
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            if tcp_layer.flags == 'S':  # SYN flag
                self.packet_counts['SYN'] += 1
        if packet.haslayer(UDP):
            self.packet_counts['UDP'] += 1
    
    def detect(self):
        alerts = []
        if self.packet_counts['SYN'] > self.syn_threshold:
            alerts.append(f"High SYN packet rate: {self.packet_counts['SYN']} packets in {WINDOW_SIZE} seconds")
        if self.packet_counts['UDP'] > self.udp_threshold:
            alerts.append(f"High UDP packet rate: {self.packet_counts['UDP']} packets in {WINDOW_SIZE} seconds")
        return alerts
    
    def reset(self):
        self.packet_counts.clear()
        self.source_ips.clear()

class AnomalyDetector:
    """Handles anomaly detection using KMeans clustering on traffic history."""
    def __init__(self, anomaly_threshold):
        self.anomaly_threshold = anomaly_threshold
        self.history = []  # Each element is [SYN_count, UDP_count]
    
    def update(self, current_counts):
        self.history.append([current_counts.get('SYN', 0), current_counts.get('UDP', 0)])
    
    def detect(self):
        if len(self.history) < 2:
            return False
        try:
            kmeans = KMeans(n_clusters=2, random_state=0)
            features = np.array(self.history)
            kmeans.fit(features)
            labels = kmeans.labels_
            counts = np.bincount(labels)
            dominant_cluster = np.argmax(counts)
            minority_cluster = 1 - dominant_cluster
            if counts[minority_cluster] / counts[dominant_cluster] < self.anomaly_threshold:
                return True
        except Exception as e:
            print(f"Anomaly detection error: {e}")
        return False
    
    def reset(self):
        self.history = []

# --- Interface Helper Functions ---

def get_friendly_names():
    """Map NPF GUIDs to friendly interface names using psutil."""
    # Get list of network interfaces from Scapy
    scapy_interfaces = get_if_list()
    
    # Get list of network interfaces from psutil
    psutil_interfaces = psutil.net_if_addrs()
    psutil_names = list(psutil_interfaces.keys())
    
    # Create a mapping based on the order (may not always be accurate)
    interface_map = {}
    for i, iface in enumerate(scapy_interfaces):
        if i < len(psutil_names):
            interface_map[iface] = psutil_names[i]
        else:
            interface_map[iface] = "Unknown"
    
    return interface_map

def list_interfaces_with_names():
    """List available network interfaces with friendly names."""
    interface_map = get_friendly_names()
    print("\nAvailable Network Interfaces:")
    for idx, iface in enumerate(get_if_list()):
        friendly_name = interface_map.get(iface, "Unknown")
        print(f"{idx}: {iface} ({friendly_name})")

def select_interface():
    """Prompt user to select a network interface."""
    list_interfaces_with_names()
    try:
        iface_index = int(input("\nSelect the interface to monitor (enter the number): "))
        interfaces = get_if_list()
        if iface_index < 0 or iface_index >= len(interfaces):
            print("Invalid interface number. Exiting.")
            sys.exit(1)
    except ValueError:
        print("Invalid input. Please enter a valid number.")
        sys.exit(1)
    selected_iface = interfaces[iface_index]
    friendly_name = get_friendly_names().get(selected_iface, "Unknown")
    print(f"\nMonitoring interface: {selected_iface} ({friendly_name})\n")
    return selected_iface

# --- Packet Processing ---

def process_packet(packet, detection_method, thresh_detector, anomaly_detector):
    """Process each captured packet and run the chosen detection method at the end of a window."""
    global window_start_time, metrics_total, attack_state_syn, attack_state_udp
    current_time = time.time()
    elapsed_time = current_time - window_start_time

    # Update both detectors with the incoming packet
    thresh_detector.update(packet)
    anomaly_detector.update(thresh_detector.packet_counts)

    # If the window has elapsed, perform detection
    if elapsed_time > WINDOW_SIZE:
        detection_start = time.time()
        if detection_method == 'threshold':
            # Separate threshold checks for SYN and UDP
            syn_count = thresh_detector.packet_counts.get('SYN', 0)
            udp_count = thresh_detector.packet_counts.get('UDP', 0)
            
            # Handle SYN Flood detection
            if syn_count > THRESHOLD_SYN:
                if not attack_state_syn["active"]:
                    attack_state_syn["active"] = True
                    attack_state_syn["start_time"] = current_time
                    attack_state_syn["sources"] = set(thresh_detector.source_ips)
                    send_alert("DoS Alert: SYN Flood Detected",
                               f"Attack started at {time.strftime('%H:%M:%S', time.localtime(current_time))}.\n"
                               f"Source(s): {', '.join(attack_state_syn['sources'])}")
                else:
                    attack_state_syn["sources"].update(thresh_detector.source_ips)
            else:
                if attack_state_syn["active"]:
                    attack_end_time = current_time
                    duration = attack_end_time - attack_state_syn["start_time"]
                    send_alert("DoS Alert: SYN Flood Ended",
                               f"Attack ended at {time.strftime('%H:%M:%S', time.localtime(attack_end_time))}.\n"
                               f"Duration: {duration:.2f} seconds.\n"
                               f"Source(s): {', '.join(attack_state_syn['sources'])}")
                    metrics_total['attack_durations'].append(duration)
                    metrics_total['attack_sources'].append(list(attack_state_syn["sources"]))
                    attack_state_syn["active"] = False
                    attack_state_syn["start_time"] = None
                    attack_state_syn["sources"] = set()
            
            # Handle UDP Flood detection
            if udp_count > THRESHOLD_UDP:
                if not attack_state_udp["active"]:
                    attack_state_udp["active"] = True
                    attack_state_udp["start_time"] = current_time
                    attack_state_udp["sources"] = set(thresh_detector.source_ips)
                    send_alert("DoS Alert: UDP Flood Detected",
                               f"Attack started at {time.strftime('%H:%M:%S', time.localtime(current_time))}.\n"
                               f"Source(s): {', '.join(attack_state_udp['sources'])}")
                else:
                    attack_state_udp["sources"].update(thresh_detector.source_ips)
            else:
                if attack_state_udp["active"]:
                    attack_end_time = current_time
                    duration = attack_end_time - attack_state_udp["start_time"]
                    send_alert("DoS Alert: UDP Flood Ended",
                               f"Attack ended at {time.strftime('%H:%M:%S', time.localtime(attack_end_time))}.\n"
                               f"Duration: {duration:.2f} seconds.\n"
                               f"Source(s): {', '.join(attack_state_udp['sources'])}")
                    metrics_total['attack_durations'].append(duration)
                    metrics_total['attack_sources'].append(list(attack_state_udp["sources"]))
                    attack_state_udp["active"] = False
                    attack_state_udp["start_time"] = None
                    attack_state_udp["sources"] = set()
            
            if syn_count > THRESHOLD_SYN or udp_count > THRESHOLD_UDP:
                metrics_total['true_positives'] += 1

        elif detection_method == 'anomaly':
            if anomaly_detector.detect():
                send_alert("DoS Alert: Anomalous Traffic Detected",
                           f"Anomalous traffic pattern detected in the last {WINDOW_SIZE} seconds.")
                metrics_total['true_positives'] += 1

        detection_time = time.time() - detection_start
        metrics_total['detection_times'].append(detection_time)
        log_metrics()

        # Reset detectors and update the window start time for the next window
        thresh_detector.reset()
        anomaly_detector.reset()
        window_start_time = current_time

def packet_callback(packet, detection_method, thresh_detector, anomaly_detector):
    process_packet(packet, detection_method, thresh_detector, anomaly_detector)

def start_sniffing(interface, detection_method):
    """Start sniffing packets on the specified interface with the selected detection method."""
    print("Starting packet sniffing...\n")
    thresh_detector = ThresholdDetector(THRESHOLD_SYN, THRESHOLD_UDP)
    anomaly_detector = AnomalyDetector(ANOMALY_THRESHOLD)
    sniff(iface=interface,
          filter="ip",
          prn=lambda pkt: packet_callback(pkt, detection_method, thresh_detector, anomaly_detector),
          store=False,
          stop_filter=lambda x: stop_sniffing)

# --- Main Function with Interactive Prompts ---

def main():
    print("Welcome to the DoS Alarm System!")
    
    # Ask user which network interface to monitor.
    interface = select_interface()
    
    # Ask user for the detection method.
    detection_method = input("Select detection method ('threshold' or 'anomaly'): ").strip().lower()
    if detection_method not in ["threshold", "anomaly"]:
        print("Invalid detection method. Defaulting to 'threshold'.")
        detection_method = "threshold"
    
    # Ask user for duration (in seconds)
    time_limit_input = input("Enter duration to monitor in seconds (leave blank for continuous monitoring): ").strip()
    time_limit = None
    if time_limit_input:
        try:
            time_limit = int(time_limit_input)
        except ValueError:
            print("Invalid input. Running continuously.")
            time_limit = None

    print(f"\nMonitoring on {interface} using {detection_method} detection method.")
    if time_limit:
        print(f"Monitoring for {time_limit} seconds.\n")
    else:
        print("Monitoring continuously until you press Ctrl+C.\n")
    
    # Initialize performance metrics file
    with open(METRICS_FILE, 'w') as f:
        f.write("DoS Alarm System Performance Metrics\n")
        f.write("====================================\n\n")
    
    # Start sniffing in a separate thread to allow graceful shutdown
    sniff_thread = threading.Thread(target=start_sniffing, args=(interface, detection_method))
    sniff_thread.start()
    
    # If a time limit is provided, start a timer to stop sniffing after the given duration.
    if time_limit is not None:
        def timer_stop():
            global stop_sniffing
            time.sleep(time_limit)
            print("\nTime limit reached. Stopping DoS Alarm System...")
            stop_sniffing = True
        timer_thread = threading.Thread(target=timer_stop)
        timer_thread.start()
    
    try:
        while sniff_thread.is_alive():
            sniff_thread.join(timeout=1)
    except KeyboardInterrupt:
        print("\nCtrl+C detected. Stopping DoS Alarm System...")
        global stop_sniffing
        stop_sniffing = True
        sniff_thread.join()
    
    # Final logging and display of metrics
    log_metrics()
    print("\n=== Cumulative Performance Metrics ===")
    print(f"True Positives: {metrics_total['true_positives']}")
    print(f"False Positives: {metrics_total['false_positives']}")
    print(f"False Negatives: {metrics_total['false_negatives']}")
    if metrics_total['detection_times']:
        avg_time = sum(metrics_total['detection_times']) / len(metrics_total['detection_times'])
    else:
        avg_time = 0
    print(f"Average Detection Time: {avg_time:.2f} seconds")
    print("======================================")
    print(f"Performance metrics have been logged to {METRICS_FILE}")
    sys.exit(0)

if __name__ == "__main__":
    main()
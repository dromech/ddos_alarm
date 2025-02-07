import psutil
from scapy.all import sniff, TCP, UDP, get_if_list
from collections import defaultdict
import time
from sklearn.cluster import KMeans
import numpy as np
import sys
import threading

# TO DO ---------------------------------------------------
"""
- Add modular switching functionality to select between detection methods.
    - Create a configuration option or command-line argument to choose between:
        - Threshold-based detection.
        - Anomaly detection.
    - Encapsulate each detection method in its own function or class.

- Enhance anomaly detection:
    - Tune KMeans parameters (e.g., number of clusters, initialization settings).
    - Implement an additional anomaly detection model (such as an autoencoder).
    - Expand feature extraction to include additional traffic characteristics (e.g., packet sizes, inter-arrival times).

- Improve performance metric logging:
    - Log additional details such as CPU and memory usage during detection.
    - Record detailed timestamps for alerts.
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
    - Update the README with installation instructions, usage guidelines, and configuration options.
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
    'detection_times': []
}

# Flag to control sniffing
stop_sniffing = False

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
            average_detection_time = sum(metrics_total['detection_times']) / len(metrics_total['detection_times'])
        else:
            average_detection_time = 0
        f.write(f"Average Detection Time (Window): {average_detection_time:.2f} seconds\n")
        f.write("-----\n")
    # Note: Do not reset metrics_total to keep cumulative counts

def detect_anomaly(features):
    """Detect anomalies using K-Means clustering."""
    if len(features) < 2:
        return False
    try:
        kmeans = KMeans(n_clusters=2, random_state=0)
        kmeans.fit(features)
        labels = kmeans.labels_
        counts = np.bincount(labels)
        dominant_cluster = np.argmax(counts)
        minority_cluster = 1 - dominant_cluster
        # If minority cluster is significantly smaller, consider it as anomaly
        if counts[minority_cluster] / counts[dominant_cluster] < ANOMALY_THRESHOLD:
            return True
        return False
    except Exception as e:
        print(f"Anomaly detection error: {e}")
        return False

def process_packet(packet):
    """Process each captured packet."""
    global start_time

    current_time = time.time()
    elapsed_time = current_time - start_time

    # Reset per-window packet counts and history if window has passed
    if elapsed_time > WINDOW_SIZE:
        packet_counts.clear()
        start_time = current_time
        traffic_history.clear()
        log_metrics()

    # Count SYN packets
    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        if tcp_layer.flags == 'S':  # SYN flag
            packet_counts['SYN'] += 1
            print(f"[{time.strftime('%H:%M:%S')}] SYN packet detected. Count: {packet_counts['SYN']}")

    # Count UDP packets
    if packet.haslayer(UDP):
        packet_counts['UDP'] += 1
        print(f"[{time.strftime('%H:%M:%S')}] UDP packet detected. Count: {packet_counts['UDP']}")

    # Collect features for anomaly detection
    traffic_history.append([packet_counts['SYN'], packet_counts['UDP']])

    # Threshold-Based Detection
    if elapsed_time <= WINDOW_SIZE:
        detection_start_time = time.time()
        if packet_counts['SYN'] > THRESHOLD_SYN:
            subject = "DoS Alert: High SYN Packet Rate"
            body = f"Detected {packet_counts['SYN']} SYN packets in the last {WINDOW_SIZE} seconds."
            send_alert(subject, body)
            metrics_total['true_positives'] += 1  # Cumulative count
            packet_counts['SYN'] = 0  # Reset after alert
            detection_time = time.time() - detection_start_time
            metrics_total['detection_times'].append(detection_time)

        if packet_counts['UDP'] > THRESHOLD_UDP:
            subject = "DoS Alert: High UDP Packet Rate"
            body = f"Detected {packet_counts['UDP']} UDP packets in the last {WINDOW_SIZE} seconds."
            send_alert(subject, body)
            metrics_total['true_positives'] += 1  # Cumulative count
            packet_counts['UDP'] = 0  # Reset after alert
            detection_time = time.time() - detection_start_time
            metrics_total['detection_times'].append(detection_time)

    # Anomaly Detection every window
    if elapsed_time > WINDOW_SIZE and len(traffic_history) > 0:
        is_anomaly = detect_anomaly(traffic_history)
        if is_anomaly:
            subject = "DoS Alert: Anomalous Traffic Pattern Detected"
            body = f"Anomalous traffic pattern detected based on historical data in the last {WINDOW_SIZE} seconds."
            send_alert(subject, body)
            metrics_total['true_positives'] += 1  # Cumulative count
            detection_time = time.time() - detection_start_time
            metrics_total['detection_times'].append(detection_time)
        traffic_history.clear()

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
        print("Invalid input. Please enter a number corresponding to the interface.")
        sys.exit(1)
    selected_iface = interfaces[iface_index]
    friendly_name = get_friendly_names().get(selected_iface, "Unknown")
    print(f"\nMonitoring interface: {selected_iface} ({friendly_name})\n")
    return selected_iface

def start_sniffing(interface):
    """Start sniffing packets on the specified interface."""
    print("Starting packet sniffing...\n")
    sniff(iface=interface, filter="ip", prn=process_packet, store=False, stop_filter=lambda x: stop_sniffing)

def main():
    """Main function to start the DoS Alarm System."""
    print("Starting DoS Alarm System...")
    # Initialize performance metrics file
    with open(METRICS_FILE, 'w') as f:
        f.write("DoS Alarm System Performance Metrics\n")
        f.write("====================================\n\n")
    
    # Select network interface
    interface = select_interface()
    
    # Start sniffing in a separate thread to allow graceful shutdown
    sniff_thread = threading.Thread(target=start_sniffing, args=(interface,))
    sniff_thread.start()
    
    try:
        while sniff_thread.is_alive():
            sniff_thread.join(timeout=1)
    except KeyboardInterrupt:
        print("\nStopping DoS Alarm System...")
        global stop_sniffing
        stop_sniffing = True
        sniff_thread.join()
        # Log final metrics
        log_metrics()
        # Print cumulative metrics to console
        print("\n=== Cumulative Performance Metrics ===")
        print(f"True Positives: {metrics_total['true_positives']}")
        print(f"False Positives: {metrics_total['false_positives']}")
        print(f"False Negatives: {metrics_total['false_negatives']}")
        if metrics_total['detection_times']:
            average_detection_time = sum(metrics_total['detection_times']) / len(metrics_total['detection_times'])
        else:
            average_detection_time = 0
        print(f"Average Detection Time: {average_detection_time:.2f} seconds")
        print("======================================")
        print(f"Performance metrics have been logged to {METRICS_FILE}")
        sys.exit(0)

if __name__ == "__main__":
    main()
import psutil
from scapy.all import sniff, TCP, UDP, IP, get_if_list
from collections import defaultdict
import time
from sklearn.cluster import KMeans
import numpy as np
import sys
import threading
import os
import json
from datetime import datetime

# Liam Calder

# TO DO ---------------------------------------------------
"""
- Add modular switching functionality to select between detection methods. (done)
    - Create a configuration option or command-line argument to choose between: (done)
        - Threshold-based detection.
        - Anomaly detection.
    - Encapsulate each detection method in its own function or class. (done so far)

- Enhance anomaly detection:
    - Tune KMeans parameters (e.g., number of clusters, initialization settings). (done)
    - Implement an additional anomaly detection model (such as an autoencoder). (maybe not)
    - Expand feature extraction to include additional traffic characteristics (e.g., packet sizes, inter-arrival times). (maybe not)

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
    - Implement simulations for TCP SYN Flood, UDP Flood, and maybe Slowloris attacks. (have basic SYN Flood and UDP Flood) (may need improvment)
    - Allow configuration of simulation parameters to test detection methods under various conditions.
    - Automate attack simulations to generate comprehensive performance data.

- Update documentation:
    - Document all new functions and classes.
    - Update the README with installation instructions, usage guidelines, and configuration options. (done)
    - Prepare a final report detailing the comparative analysis of detection methods and performance metrics.
"""
# TO DO ---------------------------------------------------

THRESHOLD_SYN = 100  # Default fallback
THRESHOLD_UDP = 200  # Default fallback
WINDOW_SIZE = 10     # Default fallback (seconds)
current_metrics_file = None  # Will be set by initialize_metrics_session

stop_sniffing = False
window_start_time = time.time()

packet_counts = defaultdict(int)
start_time = time.time()

traffic_history = []

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

attack_state_syn = {"active": False, "start_time": None, "sources": set(), "peak_syn": 0, "peak_udp": 0}
attack_state_udp = {"active": False, "start_time": None, "sources": set(), "peak_syn": 0, "peak_udp": 0}
attack_state_anomaly = {"active": False, "start_time": None, "sources": set(), "peak_syn": 0, "peak_udp": 0}


def send_alert(subject, body):
    print(f"\n=== ALERT ===\n{subject}\n{body}\n==============\n")


def get_metrics_filename():
    # Create metrics directory if it doesn't exist
    metrics_dir = "metrics"
    if not os.path.exists(metrics_dir):
        os.makedirs(metrics_dir)
    
    # Generate timestamp for filename
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    # Create filename with timestamp
    filename = os.path.join(metrics_dir, f"performance_metrics_{timestamp}.txt")
    
    return filename
      
def log_attack(attack_type, start_time=None, end_time=None, sources=None, extra_info=None, detection_method=None):
    # Use the current session's metrics file
    global current_metrics_file
    
    with open(current_metrics_file, 'a') as f:
        now_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        f.write(f"Log Entry Time: {now_str}\n")
        
        if start_time is not None:
            start_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))
            f.write(f"Start Time: {start_str}\n")
        
        if end_time is not None and start_time is not None:
            end_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_time))
            duration = end_time - start_time
            f.write(f"End Time: {end_str}\n")
            f.write(f"Duration: {duration:.2f} seconds\n")

        if detection_method is not None:
            f.write(f"Detection Method: {detection_method}\n")
        
        if sources:
            if isinstance(sources, set):
                sources = list(sources)
            f.write(f"Sources: {', '.join(sources)}\n")
        
        if extra_info:
            f.write(f"Details: {extra_info}\n")
        
        f.write("----------------------------------------------------\n\n")

# Function to initialize metrics file with session information
def initialize_metrics_session():
    global current_metrics_file
    metrics_file = get_metrics_filename()
    
    with open(metrics_file, 'w') as f:
        f.write("DoS Alarm System Performance Metrics\n")
        f.write("====================================\n")
        f.write(f"Session Start: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        # Add system info
        f.write(f"System Information:\n")
        # We could add more system information here
        try:
            import platform
            f.write(f"  OS: {platform.system()} {platform.release()}\n")
            f.write(f"  Python: {platform.python_version()}\n")
        except ImportError:
            pass
        f.write("====================================\n\n")

    current_metrics_file = metrics_file
    return metrics_file

def save_traffic_data(interface, data):
    """Save traffic history data to a JSON file."""
    folder = "traffic_data"
    if not os.path.exists(folder):
        os.makedirs(folder)
    
    # Clean up interface name for filename - replace invalid characters
    safe_interface = interface.replace('\\', '_').replace('/', '_').replace(':', '_')
    filename = os.path.join(folder, f"traffic_history_{safe_interface}.json")
    
    with open(filename, "w") as f:
        json.dump(data, f)

def load_traffic_data(interface):
    """Load traffic history data from a JSON file."""
    folder = "traffic_data"
    if not os.path.exists(folder):
        os.makedirs(folder)
    
    # Clean up interface name for filename - replace invalid characters
    safe_interface = interface.replace('\\', '_').replace('/', '_').replace(':', '_')
    filename = os.path.join(folder, f"traffic_history_{safe_interface}.json")
    
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def append_traffic_data(interface, syn_count, udp_count):
    """Append new traffic data to the existing file."""
    data = load_traffic_data(interface)
    data.append([syn_count, udp_count])
    save_traffic_data(interface, data)


class ThresholdDetector:
    def __init__(self, syn_threshold, udp_threshold):
        self.syn_threshold = syn_threshold
        self.udp_threshold = udp_threshold
        self.packet_counts = defaultdict(int)
        self.source_ips = set()
    
    def update(self, packet):
        if packet.haslayer(IP):
            self.source_ips.add(packet[IP].src)
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            if tcp_layer.flags == 'S':  # SYN flag
                self.packet_counts['SYN'] += 1
        if packet.haslayer(UDP):
            self.packet_counts['UDP'] += 1
    
    def reset(self):
        self.packet_counts.clear()
        self.source_ips.clear()


class AnomalyDetector:
    """Anomaly detection using KMeans with auto-calibrated parameters."""
    
    def __init__(self, interface):
        self.interface = interface
        # Load history from persistent storage
        self.history = load_traffic_data(interface)
        print(f"Loaded {len(self.history)} historical traffic data points for {interface}")
        
        # Flag to indicate if we're in training mode
        self.training_mode = len(self.history) < 10
        
        # Store historical maximums to prevent false positives during quiet periods
        self.historical_max_syn = 0
        self.historical_max_udp = 0
        if len(self.history) > 0:
            self.historical_max_syn = max([point[0] for point in self.history])
            self.historical_max_udp = max([point[1] for point in self.history])
            print(f"Historical max values - SYN: {self.historical_max_syn}, UDP: {self.historical_max_udp}")
        
        # Auto-determine parameters based on data
        self.calibrate_parameters()
        
        # Keep track of current window counts for display during training
        self.current_syn = 0
        self.current_udp = 0
        
        if self.training_mode:
            print(f"Training mode active - collecting baseline data ({len(self.history)}/10 windows)")
        else:
            print("Anomaly detection active")
    
    def calibrate_parameters(self):
        """Calculate appropriate n_clusters and distance_threshold from data."""
        if len(self.history) < 5:  # Need some minimum data
            self.n_clusters = 1
            self.distance_threshold = 10.0  # Default fallback
            return
            
        # Convert to numpy array for calculations
        X = np.array(self.history)
        
        # Determine number of clusters using silhouette method or simple heuristic
        if len(self.history) > 30:
            # Use a heuristic based on data size
            self.n_clusters = min(5, max(1, len(self.history) // 20))
        else:
            self.n_clusters = 1  # Default for small datasets
        
        # Fit K-means
        kmeans = KMeans(n_clusters=self.n_clusters, random_state=0)
        labels = kmeans.fit_predict(X)
        
        # Calculate distances to centroids for all points
        distances = []
        for i, point in enumerate(X):
            centroid = kmeans.cluster_centers_[labels[i]]
            dist = np.linalg.norm(point - centroid)
            distances.append(dist)
        
        # Set threshold based on distribution of distances (e.g., mean + 2*std for better sensitivity)
        mean_dist = np.mean(distances)
        std_dist = np.std(distances)
        # More sensitive detection (2 std instead of 3)
        self.distance_threshold = mean_dist + 2 * std_dist  
        
        print(f"Auto-calibrated parameters: n_clusters={self.n_clusters}, distance_threshold={self.distance_threshold:.2f}")
    
    def update_counts(self, packet):
        """Track SYN and UDP packets for the current window"""
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            if tcp_layer.flags == 'S':  # SYN flag
                self.current_syn += 1
        if packet.haslayer(UDP):
            self.current_udp += 1
        
        # Display current counts during training
        if self.training_mode and (self.current_syn + self.current_udp) % 10 == 0:  # Show every 10 packets
            print(f"Training window counts - SYN: {self.current_syn}, UDP: {self.current_udp}")
    
    def update(self, syn_count, udp_count):
        # Reset current window counts
        self.current_syn = 0
        self.current_udp = 0
        
        # Check if we're still in training mode
        if self.training_mode:
            self.history.append([syn_count, udp_count])
            # Save to persistent storage after each update
            append_traffic_data(self.interface, syn_count, udp_count)
            print(f"Training: Window {len(self.history)}/10 - SYN={syn_count}, UDP={udp_count}")
            
            # Exit training mode if we have enough data
            if len(self.history) >= 10:
                self.training_mode = False
                self.calibrate_parameters()
                print("Training complete - anomaly detection now active")
            return False, None  # No anomaly detection during training
        
        # Check if this data point is an anomaly BEFORE adding it to history
        is_anomaly, anomaly_info = self.is_anomaly(syn_count, udp_count)
        
        # Only add non-anomalous data to the history
        if not is_anomaly:
            # Update historical maximums for non-anomalous traffic
            if syn_count > self.historical_max_syn:
                self.historical_max_syn = syn_count
            if udp_count > self.historical_max_udp:
                self.historical_max_udp = udp_count
                
            # Add to history and save
            self.history.append([syn_count, udp_count])
            append_traffic_data(self.interface, syn_count, udp_count)
            
            # Limit history size to prevent memory issues
            if len(self.history) > 100:
                # Keep first 20% (oldest) and last 80% (newest) to maintain perspective
                history_length = len(self.history)
                keep_historical = int(history_length * 0.2)
                keep_recent = history_length - int(history_length * 0.2)
                self.history = self.history[:keep_historical] + self.history[-keep_recent:]
                
                # Update storage after trimming
                save_traffic_data(self.interface, self.history)
        else:
            print(f"Anomaly detected - NOT adding to baseline: SYN={syn_count}, UDP={udp_count}")
        
        # Recalibrate periodically (every 20 points instead of 10)
        if len(self.history) % 20 == 0 and not is_anomaly:
            self.calibrate_parameters()
            
        return is_anomaly, anomaly_info
    
    def is_anomaly(self, syn_count, udp_count):
        """Check if the given counts represent an anomaly"""
        # First check: is traffic significantly above historical maximums?
        # Allow for up to 40% above historical maximum without triggering (more sensitive)
        traffic_ratio = max(
            syn_count / max(1, self.historical_max_syn),
            udp_count / max(1, self.historical_max_udp)
        )
        
        # Print traffic statistics for debugging
        print(f"Traffic stats - SYN: {syn_count}, UDP: {udp_count}, " 
              f"Historical max - SYN: {self.historical_max_syn}, UDP: {self.historical_max_udp}")
        print(f"Traffic ratio: {traffic_ratio:.2f}")
        
        # Use a more sensitive threshold for high traffic
        if traffic_ratio > 1.4:  # 40% above historical instead of 50%
            anomaly_info = {
                "reason": "High traffic volume",
                "details": f"Traffic {int(traffic_ratio*100-100)}% above historical maximum"
            }
            return True, anomaly_info
        
        if len(self.history) < self.n_clusters:
            return False, None
        
        # Get the point we're testing
        test_point = np.array([[syn_count, udp_count]])
        
        # Fit KMeans on existing history
        X = np.array(self.history)
        kmeans = KMeans(n_clusters=self.n_clusters, random_state=0)
        kmeans.fit(X)
        
        # Find closest centroid for the new point
        new_label = kmeans.predict(test_point)[0]
        centroid = kmeans.cluster_centers_[new_label]
        
        # Calculate distance to closest centroid
        distance = np.linalg.norm(test_point - centroid)
        
        print(f"Distance to nearest centroid: {distance:.2f}, Threshold: {self.distance_threshold:.2f}")
        
        is_anomaly = distance > self.distance_threshold
        
        if is_anomaly:
            anomaly_info = {
                "reason": "Abnormal traffic pattern",
                "details": f"Distance {distance:.2f} > threshold {self.distance_threshold:.2f}"
            }
            print(f"ANOMALY DETECTED - distance {distance:.2f} > threshold {self.distance_threshold:.2f}")
            return True, anomaly_info
        
        return False, None


def get_friendly_names():
    scapy_interfaces = get_if_list()
    psutil_interfaces = psutil.net_if_addrs()
    psutil_names = list(psutil_interfaces.keys())
    
    interface_map = {}
    for i, iface in enumerate(scapy_interfaces):
        if i < len(psutil_names):
            interface_map[iface] = psutil_names[i]
        else:
            interface_map[iface] = "Unknown"
    return interface_map


def list_interfaces_with_names():
    interface_map = get_friendly_names()
    print("\nAvailable Network Interfaces:")
    for idx, iface in enumerate(get_if_list()):
        friendly_name = interface_map.get(iface, "Unknown")
        print(f"{idx}: {iface} ({friendly_name})")


def select_interface():
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


def process_packet(packet, detection_method, thresh_detector, anomaly_detector):
    global window_start_time, metrics_total, attack_state_syn, attack_state_udp, attack_state_anomaly, WINDOW_SIZE
    
    current_time = time.time()
    elapsed_time = current_time - window_start_time

    # Always update threshold detector each packet
    thresh_detector.update(packet)
    
    # Also update anomaly detector's packet counter if using anomaly detection
    if detection_method == 'anomaly' and anomaly_detector:
        anomaly_detector.update_counts(packet)

    if elapsed_time > WINDOW_SIZE:
        detection_start = time.time()
        
        syn_count = thresh_detector.packet_counts.get('SYN', 0)
        udp_count = thresh_detector.packet_counts.get('UDP', 0)
        
        if detection_method == 'threshold':
            # Threshold detection logic (unchanged)
            if syn_count > thresh_detector.syn_threshold:
                if not attack_state_syn["active"]:
                    attack_state_syn["active"] = True
                    attack_state_syn["start_time"] = current_time
                    attack_state_syn["sources"] = set(thresh_detector.source_ips)
                    attack_state_syn["peak_syn"] = syn_count
                    attack_state_syn["peak_udp"] = udp_count
                    send_alert("DoS Alert: SYN Flood Detected",
                               f"Attack started at {time.strftime('%H:%M:%S', time.localtime(current_time))}.\n"
                               f"Source(s): {', '.join(attack_state_syn['sources'])}")
                else:
                    if syn_count > attack_state_syn["peak_syn"]:
                        attack_state_syn["peak_syn"] = syn_count
                    if udp_count > attack_state_syn["peak_udp"]:
                        attack_state_syn["peak_udp"] = udp_count
                    attack_state_syn["sources"].update(thresh_detector.source_ips)
            else:
                if attack_state_syn["active"]:
                    attack_end_time = current_time
                    duration = attack_end_time - attack_state_syn["start_time"]
                    send_alert("DoS Alert: SYN Flood Ended",
                               f"Attack ended at {time.strftime('%H:%M:%S', time.localtime(attack_end_time))}.\n"
                               f"Duration: {duration:.2f} seconds.\n"
                               f"Source(s): {', '.join(attack_state_syn['sources'])}")
                    log_attack(attack_type="SYN Flood",
                               start_time=attack_state_syn["start_time"],
                               end_time=attack_end_time,
                               sources=attack_state_syn["sources"],
                               extra_info=(f"Peak SYN: {attack_state_syn['peak_syn']}, "f"Peak UDP: {attack_state_syn['peak_udp']}"),
                               detection_method="threshold")
                    attack_state_syn["active"] = False
                    attack_state_syn["start_time"] = None
                    attack_state_syn["sources"] = set()
                    attack_state_syn["peak_syn"] = 0
                    attack_state_syn["peak_udp"] = 0

            if udp_count > thresh_detector.udp_threshold:
                if not attack_state_udp["active"]:
                    attack_state_udp["active"] = True
                    attack_state_udp["start_time"] = current_time
                    attack_state_udp["sources"] = set(thresh_detector.source_ips)
                    attack_state_udp["peak_syn"] = syn_count
                    attack_state_udp["peak_udp"] = udp_count
                    send_alert("DoS Alert: UDP Flood Detected",
                               f"Attack started at {time.strftime('%H:%M:%S', time.localtime(current_time))}.\n"
                               f"Source(s): {', '.join(attack_state_udp['sources'])}")
                else:
                    if syn_count > attack_state_udp["peak_syn"]:
                        attack_state_udp["peak_syn"] = syn_count
                    if udp_count > attack_state_udp["peak_udp"]:
                        attack_state_udp["peak_udp"] = udp_count
                    attack_state_udp["sources"].update(thresh_detector.source_ips)
            else:
                if attack_state_udp["active"]:
                    attack_end_time = current_time
                    duration = attack_end_time - attack_state_udp["start_time"]
                    send_alert("DoS Alert: UDP Flood Ended",
                               f"Attack ended at {time.strftime('%H:%M:%S', time.localtime(attack_end_time))}.\n"
                               f"Duration: {duration:.2f} seconds.\n"
                               f"Source(s): {', '.join(attack_state_udp['sources'])}")
                    log_attack(attack_type="UDP Flood",
                               start_time=attack_state_udp["start_time"],
                               end_time=attack_end_time,
                               sources=attack_state_udp["sources"],
                               extra_info=(f"Peak SYN: {attack_state_udp['peak_syn']}, "f"Peak UDP: {attack_state_udp['peak_udp']}"),
                               detection_method="threshold")
                    attack_state_udp["active"] = False
                    attack_state_udp["start_time"] = None
                    attack_state_udp["sources"] = set()
                    attack_state_udp["peak_syn"] = 0
                    attack_state_udp["peak_udp"] = 0

        elif detection_method == 'anomaly' and anomaly_detector:
            # Update anomaly detector once per window and check for anomalies
            is_anomaly, anomaly_info = anomaly_detector.update(syn_count, udp_count)
            
            # Only try to detect anomalies if not in training mode
            if not anomaly_detector.training_mode:
                # Then check if the point is anomalous
                if is_anomaly:
                    # If not active, start a new "anomaly" attack
                    if not attack_state_anomaly["active"]:
                        attack_state_anomaly["active"] = True
                        attack_state_anomaly["start_time"] = current_time
                        attack_state_anomaly["sources"] = set(thresh_detector.source_ips)
                        attack_state_anomaly["peak_syn"] = syn_count
                        attack_state_anomaly["peak_udp"] = udp_count
                        
                        # Get detailed alert message based on anomaly info
                        alert_detail = ""
                        if anomaly_info and "reason" in anomaly_info:
                            alert_detail = f"\nReason: {anomaly_info['reason']}\n"
                            if "details" in anomaly_info:
                                alert_detail += f"Details: {anomaly_info['details']}\n"
                        
                        send_alert("DoS Alert: Anomalous Traffic Detected",
                                f"Anomalous traffic in last {WINDOW_SIZE} seconds.\n"
                                f"SYN: {syn_count}, UDP: {udp_count}{alert_detail}"
                                f"Source(s): {', '.join(thresh_detector.source_ips)}")
                    else:
                        # Ongoing anomaly; update peaks & sources
                        if syn_count > attack_state_anomaly["peak_syn"]:
                            attack_state_anomaly["peak_syn"] = syn_count
                        if udp_count > attack_state_anomaly["peak_udp"]:
                            attack_state_anomaly["peak_udp"] = udp_count
                        attack_state_anomaly["sources"].update(thresh_detector.source_ips)
                else:
                    # If we had an anomaly ongoing, end it
                    if attack_state_anomaly["active"]:
                        attack_end_time = current_time
                        duration = attack_end_time - attack_state_anomaly["start_time"]
                        send_alert(
                            "DoS Alert: Anomaly Ended",
                            f"Attack ended at {time.strftime('%H:%M:%S', time.localtime(attack_end_time))}.\n"
                            f"Duration: {duration:.2f} seconds.\n"
                            f"Source(s): {', '.join(attack_state_anomaly['sources'])}"
                        )
                        log_attack(
                            attack_type="Anomaly",
                            start_time=attack_state_anomaly["start_time"],
                            end_time=attack_end_time,
                            sources=attack_state_anomaly["sources"],
                            extra_info=(
                                f"Peak SYN: {attack_state_anomaly['peak_syn']}, "
                                f"Peak UDP: {attack_state_anomaly['peak_udp']}"
                            ),
                            detection_method="anomaly"
                        )
                        # Reset anomaly attack state
                        attack_state_anomaly["active"] = False
                        attack_state_anomaly["start_time"] = None
                        attack_state_anomaly["sources"] = set()
                        attack_state_anomaly["peak_syn"] = 0
                        attack_state_anomaly["peak_udp"] = 0

        # Reset threshold detector each window, but NOT the anomaly detector's history
        thresh_detector.reset()
        window_start_time = current_time


def packet_callback(packet, detection_method, thresh_detector, anomaly_detector):
    process_packet(packet, detection_method, thresh_detector, anomaly_detector)


def start_sniffing(interface, detection_method, syn_thr, udp_thr):
    print("Starting packet sniffing...\n")
    
    # Create detectors based on user's inputs
    if detection_method == 'threshold':
        thresh_detector = ThresholdDetector(syn_threshold=syn_thr,
                                            udp_threshold=udp_thr)
        anomaly_detector = None  # Not used
    else:  # anomaly
        # We'll still create a threshold detector for packet counting
        # but with a large threshold so it doesn't do real detection
        thresh_detector = ThresholdDetector(999999, 999999)
        anomaly_detector = AnomalyDetector(interface=interface)
    
    sniff(iface=interface,
          filter="ip",
          prn=lambda pkt: packet_callback(pkt, detection_method, thresh_detector, anomaly_detector),
          store=False,
          stop_filter=lambda x: stop_sniffing,
          promisc=True)


# Utility to measure traffic for x seconds, to recommend thresholds
def measure_traffic_sample(interface, sample_time=30):
    """Sniff for 'sample_time' seconds, return average packets/second for SYN and UDP."""
    local_counts = defaultdict(int)

    def sample_callback(pkt):
        if pkt.haslayer(TCP):
            tcp_layer = pkt.getlayer(TCP)
            if tcp_layer.flags == 'S':
                local_counts['SYN'] += 1
        if pkt.haslayer(UDP):
            local_counts['UDP'] += 1
    
    print(f"\nMeasuring traffic on {interface} for {sample_time} seconds to recommend thresholds...")
    t0 = time.time()
    sniff(iface=interface, store=False, prn=sample_callback,
          stop_filter=lambda x: (time.time() - t0) > sample_time)
    
    # Average packets per second
    syn_rate = local_counts['SYN'] / float(sample_time)
    udp_rate = local_counts['UDP'] / float(sample_time)
    return syn_rate, udp_rate


def main():
    global stop_sniffing
    global WINDOW_SIZE

    print("Welcome to the DoS Alarm System!")
    
    # 1) Select interface
    interface = select_interface()
    
    # 2) Ask user for the detection method
    detection_method = input("Select detection method ('threshold' or 'anomaly'): ").strip().lower()
    if detection_method not in ["threshold", "anomaly"]:
        print("Invalid detection method. Defaulting to 'threshold'.")
        detection_method = "threshold"

    # 3) Ask user for the time window size
    try:
        w_size_input = input("Enter window size in seconds (default 10): ").strip()
        if w_size_input:
            WINDOW_SIZE = int(w_size_input)
        else:
            WINDOW_SIZE = 10
    except ValueError:
        print("Invalid window size. Defaulting to 10 seconds.")
        WINDOW_SIZE = 10
    
    # 4) Based on detection method, ask for relevant parameters
    syn_thr = THRESHOLD_SYN  # default
    udp_thr = THRESHOLD_UDP  # default
    n_clust = 2
    dist_thr = 10.0
    max_hist = 50
    
    if detection_method == "threshold":
        # Ask user if they want an auto recommendation
        auto_recommend = input("Would you like an auto-recommended threshold based on a short traffic sample? (y/n): ").strip().lower()
        if auto_recommend == 'y':
            # measure a short sample
            test_time = input("How long (in seconds) would you like to monitor the traffic to form a sample?: ").strip()
            if test_time:
                test_time_length = int(test_time)
            else:
                test_time_length = 30
            syn_rate, udp_rate = measure_traffic_sample(interface, test_time_length)
            # For example, set thresholds as 3 times average pps * window size
            recommended_syn = int((1 + syn_rate) * WINDOW_SIZE * 3)
            recommended_udp = int((1 + udp_rate) * WINDOW_SIZE * 3)
            print(f"Recommended SYN threshold ~ {recommended_syn}, UDP threshold ~ {recommended_udp}")
            
            try:
                user_syn = input(f"Enter desired SYN threshold (default {recommended_syn}): ").strip()
                user_udp = input(f"Enter desired UDP threshold (default {recommended_udp}): ").strip()
                syn_thr = int(user_syn) if user_syn else recommended_syn
                udp_thr = int(user_udp) if user_udp else recommended_udp
            except ValueError:
                # If invalid input, fall back
                syn_thr = recommended_syn
                udp_thr = recommended_udp
                print("Invalid input. Using recommended thresholds.")
        else:
            # Let them input their own
            try:
                s_input = input(f"Enter custom SYN threshold (default {THRESHOLD_SYN}): ").strip()
                u_input = input(f"Enter custom UDP threshold (default {THRESHOLD_UDP}): ").strip()
                if s_input:
                    syn_thr = int(s_input)
                if u_input:
                    udp_thr = int(u_input)
            except ValueError:
                print("Invalid threshold input. Using defaults.")

    if detection_method == "anomaly":
        # Check if we have sufficient historical data
        existing_data = load_traffic_data(interface)
        if len(existing_data) < 10:  # Need minimum data points
            print(f"Insufficient traffic data found ({len(existing_data)} points). Taking a sample...")
            sample_duration = int(input("Enter sample duration in seconds (default 60): ").strip() or 60)
            print(f"Taking a {sample_duration} second traffic sample...")
            
            # Collect baseline sample
            sample_data = existing_data.copy()  # Start with any existing data
            
            def baseline_callback(pkt):
                nonlocal syn_count, udp_count
                if pkt.haslayer(TCP):
                    tcp_layer = pkt.getlayer(TCP)
                    if tcp_layer.flags == 'S':
                        syn_count += 1
                if pkt.haslayer(UDP):
                    udp_count += 1
            
            # Collect several windows of data
            for i in range(int(sample_duration / WINDOW_SIZE)):
                syn_count, udp_count = 0, 0
                t0 = time.time()
                sniff(iface=interface, store=False, prn=baseline_callback,
                     stop_filter=lambda x: (time.time() - t0) > WINDOW_SIZE)
                sample_data.append([syn_count, udp_count])
                print(f"Window {i + 1}: SYN={syn_count}, UDP={udp_count}")
            
            # Save the collected baseline
            save_traffic_data(interface, sample_data)
            print(f"Baseline traffic data collected and saved ({len(sample_data)} windows)")
        else:
            print(f"Found existing traffic data with {len(existing_data)} data points")
            reset_data = input("Would you like to reset the traffic baseline and start fresh? (y/n): ").strip().lower()
            if reset_data == 'y':
                # Reset the traffic data
                save_traffic_data(interface, [])
                print("Traffic baseline reset. System will start in training mode.")

    # 5) Ask user for duration (in seconds)
    time_limit_input = input("Enter duration to monitor in seconds (leave blank for continuous monitoring): ").strip()
    time_limit = None
    if time_limit_input:
        try:
            time_limit = int(time_limit_input)
        except ValueError:
            print("Invalid input. Running continuously.")
            time_limit = None

    print(f"\nMonitoring on {interface} using {detection_method} detection method with window size = {WINDOW_SIZE}s.")
    if detection_method == "threshold":
        print(f"Using SYN threshold = {syn_thr}  |  UDP threshold = {udp_thr}")
    else:
        print(f"Using anomaly detection with more conservative thresholds (3-sigma)")
    
    if time_limit:
        print(f"Monitoring for {time_limit} seconds.\n")
    else:
        print("Monitoring continuously until you press Ctrl+C.\n")
    
    # Initialize performance metrics session
    metrics_file = initialize_metrics_session()
    print(f"Logging performance metrics to: {metrics_file}")
    
    # Start sniffing in a separate thread
    sniff_thread = threading.Thread(
        target=start_sniffing,
        args=(interface, detection_method, syn_thr, udp_thr)
    )
    sniff_thread.start()
    
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
        stop_sniffing = True
        sniff_thread.join()
    
    sys.exit(0)


if __name__ == "__main__":
    main()
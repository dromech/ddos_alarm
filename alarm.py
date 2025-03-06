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
METRICS_FILE = 'performance_metrics.txt'

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


def send_alert(subject, body):
    print(f"\n=== ALERT ===\n{subject}\n{body}\n==============\n")

# Old logging function (can be deleted)
def log_metrics():
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
      

# New loggin function
def log_attack(attack_type, start_time=None, end_time=None, sources=None, extra_info=None):
    with open(METRICS_FILE, 'a') as f:
        now_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        f.write(f"Log Entry Time: {now_str}\n")
        f.write(f"Attack Type: {attack_type}\n")
        
        if start_time is not None:
            start_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))
            f.write(f"Start Time: {start_str}\n")
        
        if end_time is not None and start_time is not None:
            end_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_time))
            duration = end_time - start_time
            f.write(f"End Time: {end_str}\n")
            f.write(f"Duration: {duration:.2f} seconds\n")
        
        if sources:
            if isinstance(sources, set):
                sources = list(sources)
            f.write(f"Sources: {', '.join(sources)}\n")
        
        if extra_info:
            f.write(f"Details: {extra_info}\n")
        
        f.write("----------------------------------------------------\n\n")


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
    """Anomaly detection using KMeans and distance to centroid."""
    
    def __init__(self, n_clusters=1, distance_threshold=10.0, max_history=50):
        self.n_clusters = n_clusters
        self.distance_threshold = distance_threshold
        self.max_history = max_history
        self.history = []  # store [syn_count, udp_count] per window
    
    def update(self, syn_count, udp_count):
        self.history.append([syn_count, udp_count])
        if len(self.history) > self.max_history:
            self.history.pop(0)
    
    def detect(self):
        if len(self.history) < self.n_clusters:
            return False
        
        X = np.array(self.history)
        kmeans = KMeans(n_clusters=self.n_clusters, random_state=0)
        labels = kmeans.fit_predict(X)
        
        # newest data point
        new_point = X[-1]
        new_point_label = labels[-1]
        
        centroid = kmeans.cluster_centers_[new_point_label]
        distance = np.linalg.norm(new_point - centroid)
        
        return distance > self.distance_threshold
    
    def remove_last(self):
        if self.history:
            self.history.pop()


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
    global window_start_time, metrics_total, attack_state_syn, attack_state_udp, WINDOW_SIZE
    
    current_time = time.time()
    elapsed_time = current_time - window_start_time

    # Always update threshold detector each packet
    thresh_detector.update(packet)

    if elapsed_time > WINDOW_SIZE:
        detection_start = time.time()
        
        syn_count = thresh_detector.packet_counts.get('SYN', 0)
        udp_count = thresh_detector.packet_counts.get('UDP', 0)
        
        if detection_method == 'threshold':
            # Threshold detection logic 
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
                               start_time=attack_state_udp["start_time"],
                               end_time=attack_end_time,
                               sources=attack_state_udp["sources"],
                               extra_info=(f"Peak SYN: {attack_state_syn['peak_syn']}, "f"Peak UDP: {attack_state_syn['peak_udp']}"))
                    # metrics_total['attack_durations'].append(duration)
                    # metrics_total['attack_sources'].append(list(attack_state_syn["sources"]))
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
                    attack_state_syn["peak_syn"] = syn_count
                    attack_state_syn["peak_udp"] = udp_count
                    send_alert("DoS Alert: UDP Flood Detected",
                               f"Attack started at {time.strftime('%H:%M:%S', time.localtime(current_time))}.\n"
                               f"Source(s): {', '.join(attack_state_udp['sources'])}")
                else:
                    if syn_count > attack_state_syn["peak_syn"]:
                        attack_state_syn["peak_syn"] = syn_count
                    if udp_count > attack_state_syn["peak_udp"]:
                        attack_state_syn["peak_udp"] = udp_count
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
                               extra_info=(f"Peak SYN: {attack_state_syn['peak_syn']}, "f"Peak UDP: {attack_state_syn['peak_udp']}"))
                    # metrics_total['attack_durations'].append(duration)
                    # metrics_total['attack_sources'].append(list(attack_state_udp["sources"]))
                    attack_state_udp["active"] = False
                    attack_state_udp["start_time"] = None
                    attack_state_udp["sources"] = set()
                    attack_state_syn["peak_syn"] = 0
                    attack_state_syn["peak_udp"] = 0

            # if (syn_count > thresh_detector.syn_threshold) or (udp_count > thresh_detector.udp_threshold):
            #     metrics_total['true_positives'] += 1

        if detection_method == 'anomaly':
            # Update anomaly detector once per window
            anomaly_detector.update(syn_count, udp_count)
            # Then check if the newest point is anomalous
            if anomaly_detector.detect():
                anomaly_detector.remove_last() # Remove the anomaly traffic to avoid it becoming base
                send_alert("DoS Alert: Anomalous Traffic Detected",
                           f"Anomalous traffic in last {WINDOW_SIZE} seconds.")
                log_attack(attack_type="Anomaly Detected",
                           extra_info=f"SYN={syn_count}, UDP={udp_count}")
                # metrics_total['true_positives'] += 1
        
        detection_time = time.time() - detection_start
        # metrics_total['detection_times'].append(detection_time)
        # log_metrics()

        # Reset threshold each window, but NOT the anomaly detector
        thresh_detector.reset()
        window_start_time = current_time


def packet_callback(packet, detection_method, thresh_detector, anomaly_detector):
    process_packet(packet, detection_method, thresh_detector, anomaly_detector)


def start_sniffing(interface, detection_method, syn_thr, udp_thr, n_clust, dist_thr, max_hist):
    print("Starting packet sniffing...\n")
    
    # Create detectors based on user’s inputs
    if detection_method == 'threshold':
        thresh_detector = ThresholdDetector(syn_threshold=syn_thr,
                                            udp_threshold=udp_thr)
        anomaly_detector = None  # Not used
    else:  # anomaly
        # We'll still create a threshold detector for packet counting
        # but with a large threshold so it doesn't do real detection
        thresh_detector = ThresholdDetector(999999, 999999)
        anomaly_detector = AnomalyDetector(n_clusters=n_clust,
                                           distance_threshold=dist_thr,
                                           max_history=max_hist)
    
    sniff(iface=interface,
          filter="ip",
          prn=lambda pkt: packet_callback(pkt, detection_method, thresh_detector, anomaly_detector),
          store=False,
          stop_filter=lambda x: stop_sniffing)


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

    else:
        # anomaly detection: ask for n_clusters, distance_threshold, max_history
        try:
            n_clust = int(input("Enter number of KMeans clusters (default 1): ").strip() or 1)
            dist_thr = float(input("Enter distance threshold (default 10.0): ").strip() or 10.0)
            max_hist = int(input("Enter max history (number of windows to keep) (default 50): ").strip() or 50)
        except ValueError:
            print("Invalid input. Using defaults for anomaly parameters.")

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
        print(f"Using n_clusters={n_clust}, distance_threshold={dist_thr}, max_history={max_hist}")
    
    if time_limit:
        print(f"Monitoring for {time_limit} seconds.\n")
    else:
        print("Monitoring continuously until you press Ctrl+C.\n")
    
    # Initialize performance metrics file
    with open(METRICS_FILE, 'w') as f:
        f.write("DoS Alarm System Performance Metrics\n")
        f.write("====================================\n\n")
    
    # Start sniffing in a separate thread
    sniff_thread = threading.Thread(
        target=start_sniffing,
        args=(interface, detection_method, syn_thr, udp_thr, n_clust, dist_thr, max_hist)
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
    
    # Final logging and display
    # log_metrics()
    # print("\n=== Cumulative Performance Metrics ===")
    # print(f"True Positives: {metrics_total['true_positives']}")
    # print(f"False Positives: {metrics_total['false_positives']}")
    # print(f"False Negatives: {metrics_total['false_negatives']}")
    # if metrics_total['detection_times']:
    #     avg_time = sum(metrics_total['detection_times']) / len(metrics_total['detection_times'])
    # else:
    #     avg_time = 0
    # print(f"Average Detection Time: {avg_time:.2f} seconds")
    # print("======================================")
    # print(f"Performance metrics have been logged to {METRICS_FILE}")
    sys.exit(0)


if __name__ == "__main__":
    main()
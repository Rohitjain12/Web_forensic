from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time
import logging

# Constants
REQUEST_THRESHOLD = 100  # Max number of packets from the same IP in a given time period
TIME_WINDOW = 3  # Time window in seconds to measure traffic
IN_OUT_RATIO_THRESHOLD = 0.5  # Threshold for incoming vs outgoing requests ratio

# Dictionaries to store IP packet counts for incoming and outgoing traffic
incoming_packet_counts = defaultdict(int)
outgoing_packet_counts = defaultdict(int)

# Set up logging
logging.basicConfig(filename='dos_attack_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

def analyze_packet(packet):
    if IP in packet and TCP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        
        # Check if it's an incoming or outgoing packet
        if packet[IP].dst == "your_server_ip":  # Replace with your server IP
            # Incoming packet
            incoming_packet_counts[source_ip] += 1
        else:
            # Outgoing packet
            outgoing_packet_counts[destination_ip] += 1

def detect_dos():
    while True:
        time.sleep(TIME_WINDOW)
        
        for ip in incoming_packet_counts.keys() | outgoing_packet_counts.keys():
            incoming_count = incoming_packet_counts[ip]
            outgoing_count = outgoing_packet_counts[ip]
            
            # Check for potential DoS attack based on request ratio and thresholds
            if outgoing_count > incoming_count and outgoing_count > REQUEST_THRESHOLD:
                ratio = incoming_count / outgoing_count if outgoing_count != 0 else 0
                if ratio < IN_OUT_RATIO_THRESHOLD:
                    alert_message = f"[ALERT] Possible DoS attack detected from IP: {ip}"
                    packet_data_message = f"Incoming packets: {incoming_count}, Outgoing packets: {outgoing_count}"
                    
                    # Log the alert and packet data
                    logging.info(alert_message)
                    logging.info(packet_data_message)
                    print(alert_message)
                    print(packet_data_message)

        # Reset counts for the next time window
        incoming_packet_counts.clear()
        outgoing_packet_counts.clear()

if __name__ == "__main__":
    print("Starting network analysis...")

    # Start a separate thread to sniff packets
    sniff(prn=analyze_packet, filter="tcp", store=0, iface="wlp1s0", count=0)
    
    # Run DoS detection in the main thread
    detect_dos()

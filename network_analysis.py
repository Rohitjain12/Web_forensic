from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time
import logging
import threading  # Import threading for parallel execution

# Constants
REQUEST_THRESHOLD = 30  # Adjusted threshold for demonstration
TIME_WINDOW = 3  # Time window in seconds to measure traffic
IN_OUT_RATIO_THRESHOLD = 0.3  # Threshold for incoming vs outgoing requests ratio

# Dictionaries to store IP packet counts for incoming and outgoing traffic
incoming_packet_counts = defaultdict(int)
outgoing_packet_counts = defaultdict(int)

# Set up logging
logging.basicConfig(filename='logs/dos_attack_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

def is_ongoing_connection_packet(tcp_flags):
    """
    Determine if the TCP packet is part of an ongoing connection.
    We avoid counting SYN, SYN-ACK, and ACK packets used during the connection setup.
    """
    # Only count packets that are not SYN, SYN-ACK, or single ACK packets for initial handshake
    return 'S' not in tcp_flags and tcp_flags != 'A'

def analyze_packet(packet):
    if IP in packet and TCP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        tcp_layer = packet[TCP]
        
        # Check if it's an incoming packet directed to the server IP
        if destination_ip == "172.20.0.2":  # Replace with your server IP
            # Only count packets that are connection attempts (SYN packets)
            if tcp_layer.flags == 'S':  # SYN packet (initial request)
                incoming_packet_counts[source_ip] += 1
                log_message = f"Incoming connection attempt from {source_ip}, total: {incoming_packet_counts[source_ip]}"
                #print(log_message)
                logging.info(log_message)
        else:
            # Outgoing packet: Count only if it's part of an ongoing connection
            if is_ongoing_connection_packet(tcp_layer.flags):
                outgoing_packet_counts[destination_ip] += 1
                log_message = f"Outgoing packet to {destination_ip} (ongoing connection), total: {outgoing_packet_counts[destination_ip]}"
                #print(log_message)
                logging.info(log_message)

def detect_dos():
    logging.info("Starting DoS detection loop...")
    while True:
        time.sleep(TIME_WINDOW)
        
        # Only process if there is traffic to analyze
        if incoming_packet_counts or outgoing_packet_counts:
            for ip in incoming_packet_counts.keys() | outgoing_packet_counts.keys():
                log_message = f"Analyzing IP: {ip}"
                print(log_message)
                logging.info(log_message)

                incoming_count = incoming_packet_counts[ip]
                outgoing_count = outgoing_packet_counts[ip]
                
                # Log packet counts for each IP
                log_packet_counts = f"Incoming packets for {ip}: {incoming_count}, Outgoing packets for {ip}: {outgoing_count}"
                print(log_packet_counts)
                logging.info(log_packet_counts)
                
                # Check for potential DoS attack based on request ratio and thresholds
                if outgoing_count > REQUEST_THRESHOLD and (incoming_count == 0 or (incoming_count / outgoing_count < IN_OUT_RATIO_THRESHOLD)):
                    alert_message = f"[ALERT] Possible DoS attack detected from IP: {ip}"
                    packet_data_message = f"Incoming packets: {incoming_count}, Outgoing packets: {outgoing_count}"
                    
                    # Log the alert and packet data
                    logging.info(alert_message)
                    logging.info(packet_data_message)
                    print(alert_message)
                    print(packet_data_message)
        else:
            no_data_message = "No packet data to process."
            print(no_data_message)
            logging.info(no_data_message)
        
        # Reset counts for the next time window
        incoming_packet_counts.clear()
        outgoing_packet_counts.clear()
        logging.info("Packet counts reset for the next time window.")

if __name__ == "__main__":
    startup_message = "Starting network analysis..."
    print(startup_message)
    logging.info(startup_message)

    # Start a separate thread to sniff packets
    sniff_thread = threading.Thread(target=lambda: sniff(prn=analyze_packet, filter="tcp", store=0, iface="eth0", count=0))
    sniff_thread.start()
    logging.info("Packet sniffing started...")

    # Run DoS detection in the main thread
    detect_dos()

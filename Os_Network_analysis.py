import threading
import time
import logging
import psutil
from scapy.all import sniff, IP, TCP
from collections import defaultdict

# Constants for system monitoring
CPU_THRESHOLD = 85
MEMORY_THRESHOLD = 85
DISK_THRESHOLD = 90
NETWORK_THRESHOLD = 10 * 1024 * 1024
WHITELISTED_APPS = ["python", "chrome", "explorer", "systemd", "bash"]

# Constants for network analysis
REQUEST_THRESHOLD = 100
TIME_WINDOW = 3
IN_OUT_RATIO_THRESHOLD = 0.5
INCOMING_PACKET_COUNTS = defaultdict(int)
OUTGOING_PACKET_COUNTS = defaultdict(int)

# Logging setup
logging.basicConfig(filename='os_network_analysis_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

# Global variables for system monitoring
previous_sent = psutil.net_io_counters().bytes_sent
previous_recv = psutil.net_io_counters().bytes_recv

# System Monitoring Functions
def check_cpu_usage():
    cpu_usage = psutil.cpu_percent(interval=1)
    if cpu_usage > CPU_THRESHOLD:
        alert_message = f"[ALERT] High CPU usage detected: {cpu_usage}%"
        logging.info(alert_message)
        print(alert_message)

def check_memory_usage():
    memory_info = psutil.virtual_memory()
    if memory_info.percent > MEMORY_THRESHOLD:
        alert_message = f"[ALERT] High Memory usage detected: {memory_info.percent}%"
        logging.info(alert_message)
        print(alert_message)

def check_disk_usage():
    disk_info = psutil.disk_usage('/')
    if disk_info.percent > DISK_THRESHOLD:
        alert_message = f"[ALERT] High Disk usage detected: {disk_info.percent}%"
        logging.info(alert_message)
        print(alert_message)

def check_network_usage():
    global previous_sent, previous_recv
    net_io = psutil.net_io_counters()
    bytes_sent_per_sec = net_io.bytes_sent - previous_sent
    bytes_recv_per_sec = net_io.bytes_recv - previous_recv
    previous_sent = net_io.bytes_sent
    previous_recv = net_io.bytes_recv
    mb_recv_per_sec = bytes_recv_per_sec / (1024 * 1024)
    if mb_recv_per_sec > (NETWORK_THRESHOLD / (1024 * 1024)):
        alert_message = f"[ALERT] High Network traffic detected: {mb_recv_per_sec:.2f} MB/s"
        logging.info(alert_message)
        print(alert_message)

def check_running_processes():
    non_whitelisted_processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            process_name = proc.info['name'].lower()
            if process_name not in WHITELISTED_APPS:
                non_whitelisted_processes.append(process_name)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    if non_whitelisted_processes:
        alert_message = f"[ALERT] Non-whitelisted applications detected: {', '.join(non_whitelisted_processes)}"
        logging.info(alert_message)
        print(alert_message)

def monitor_system(interval=5):
    while True:
        print("-" * 40)
        check_cpu_usage()
        check_memory_usage()
        check_disk_usage()
        check_network_usage()
        check_running_processes()
        time.sleep(interval)

# Network Analysis Functions
def analyze_packet(packet):
    if IP in packet and TCP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        if packet[IP].dst == "your_server_ip":  # Replace with your server IP
            INCOMING_PACKET_COUNTS[source_ip] += 1
        else:
            OUTGOING_PACKET_COUNTS[destination_ip] += 1

def detect_dos():
    while True:
        time.sleep(TIME_WINDOW)
        for ip in INCOMING_PACKET_COUNTS.keys() | OUTGOING_PACKET_COUNTS.keys():
            incoming_count = INCOMING_PACKET_COUNTS[ip]
            outgoing_count = OUTGOING_PACKET_COUNTS[ip]
            if outgoing_count > incoming_count and outgoing_count > REQUEST_THRESHOLD:
                ratio = incoming_count / outgoing_count if outgoing_count != 0 else 0
                if ratio < IN_OUT_RATIO_THRESHOLD:
                    alert_message = f"[ALERT] Possible DoS attack detected from IP: {ip}"
                    packet_data_message = f"Incoming packets: {incoming_count}, Outgoing packets: {outgoing_count}"
                    logging.info(alert_message)
                    logging.info(packet_data_message)
                    print(alert_message)
                    print(packet_data_message)
        INCOMING_PACKET_COUNTS.clear()
        OUTGOING_PACKET_COUNTS.clear()

def sniff_packets():
    sniff(prn=analyze_packet, filter="tcp", store=0, iface="wlp1s0", count=0)

# Main Function
if __name__ == "__main__":
    print("Starting OS and Network analysis...")

    # Create threads for system monitoring and network analysis
    system_thread = threading.Thread(target=monitor_system, args=(5,))
    network_thread = threading.Thread(target=sniff_packets)
    dos_detection_thread = threading.Thread(target=detect_dos)

    # Start the threads
    system_thread.start()
    network_thread.start()
    dos_detection_thread.start()

    # Wait for threads to complete
    system_thread.join()
    network_thread.join()
    dos_detection_thread.join()

import psutil
import time
import logging

# Thresholds for detecting potential DoS attacks
CPU_THRESHOLD = 85  # CPU usage percentage considered as abnormal
MEMORY_THRESHOLD = 85  # Memory usage percentage considered as abnormal
DISK_THRESHOLD = 90  # Disk usage percentage considered as abnormal
NETWORK_THRESHOLD = 10 * 1024 * 1024  # 10 MB per second (adjust based on your typical traffic)

# Store previous network stats for comparison
previous_sent = psutil.net_io_counters().bytes_sent
previous_recv = psutil.net_io_counters().bytes_recv

# Whitelisted applications (process names)
WHITELISTED_APPS = ["python", "chrome", "explorer", "systemd", "bash"]  # Add more as needed

# Set up logging
logging.basicConfig(filename='system_monitor_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

def check_cpu_usage():
    """Check if CPU usage is above the threshold."""
    cpu_usage = psutil.cpu_percent(interval=1)
    if cpu_usage > CPU_THRESHOLD:
        alert_message = f"[ALERT] High CPU usage detected: {cpu_usage}%"
        logging.info(alert_message)
        print(alert_message)
        return True
    return False

def check_memory_usage():
    """Check if memory usage is above the threshold."""
    memory_info = psutil.virtual_memory()
    if memory_info.percent > MEMORY_THRESHOLD:
        alert_message = f"[ALERT] High Memory usage detected: {memory_info.percent}%"
        logging.info(alert_message)
        print(alert_message)
        return True
    return False

def check_disk_usage():
    """Check if disk usage is above the threshold."""
    disk_info = psutil.disk_usage('/')
    if disk_info.percent > DISK_THRESHOLD:
        alert_message = f"[ALERT] High Disk usage detected: {disk_info.percent}%"
        logging.info(alert_message)
        print(alert_message)
        return True
    return False

def check_network_usage():
    """Check if network traffic is above the threshold."""
    global previous_sent, previous_recv
    net_io = psutil.net_io_counters()
    
    # Calculate data sent/received in the last interval (bytes per second)
    bytes_sent_per_sec = net_io.bytes_sent - previous_sent
    bytes_recv_per_sec = net_io.bytes_recv - previous_recv
    
    previous_sent = net_io.bytes_sent
    previous_recv = net_io.bytes_recv
    
    # Convert to MB
    mb_sent_per_sec = bytes_sent_per_sec / (1024 * 1024)
    mb_recv_per_sec = bytes_recv_per_sec / (1024 * 1024)
    
    if mb_recv_per_sec > (NETWORK_THRESHOLD / (1024 * 1024)):
        alert_message = f"[ALERT] High Network traffic detected: {mb_recv_per_sec:.2f} MB/s"
        logging.info(alert_message)
        print(alert_message)
        return True
    return False

def check_running_processes():
    """Check currently running processes and detect non-whitelisted applications."""
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
        return True
    return False

def monitor_system(interval=5):
    """Monitor system resources in real-time and detect abnormal behavior."""
    try:
        while True:
            print("-" * 40)
            cpu_alert = check_cpu_usage()
            memory_alert = check_memory_usage()
            disk_alert = check_disk_usage()
            network_alert = check_network_usage()
            process_alert = check_running_processes()
            
            if cpu_alert or memory_alert or disk_alert or network_alert or process_alert:
                warning_message = "[WARNING] Potential issue detected! Possible DoS attack or unauthorized application running."
                logging.warning(warning_message)
                print(warning_message)
            else:
                print("System is operating normally.")
            
            time.sleep(interval)
    except KeyboardInterrupt:
        print("Monitoring stopped.")

if __name__ == "__main__":
    monitor_interval = 5  # Set the interval for monitoring (in seconds)
    print("Starting system resource and process monitoring for DoS detection...")
    monitor_system(interval=monitor_interval)

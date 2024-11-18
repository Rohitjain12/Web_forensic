import psutil
import time
import logging
import os

# Thresholds for detecting potential DoS attacks
CPU_THRESHOLD = 85  # CPU usage percentage considered as abnormal
MEMORY_THRESHOLD = 85  # Memory usage percentage considered as abnormal
DISK_THRESHOLD = 90  # Disk usage percentage considered as abnormal
NETWORK_THRESHOLD = 10 * 1024 * 1024  # 10 MB per second (adjust based on your typical traffic)

# Store previous network stats for comparison
previous_sent = psutil.net_io_counters().bytes_sent
previous_recv = psutil.net_io_counters().bytes_recv

# Whitelisted applications (dynamically determined at startup)
WHITELISTED_APPS = []

# Set up logging
logging.basicConfig(filename='logs/system_monitor_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

# Logging for non-whitelisted processes
non_whitelisted_log = logging.getLogger('non_whitelisted_processes')
non_whitelisted_log.setLevel(logging.INFO)
file_handler = logging.FileHandler('non_whitelisted_log.txt')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
non_whitelisted_log.addHandler(file_handler)

import psutil


def initialize_whitelist():
    """Initialize the whitelist based on currently running processes at startup."""
    global WHITELISTED_APPS
    current_processes = psutil.process_iter(attrs=['pid', 'name', 'cmdline'])
    WHITELISTED_APPS = ["/bin/sh ./start.sh", "/bin/sh", "/usr/local/bin/python", "/app/app.py"]

    logging.info("Initializing whitelist based on currently running processes...")
    
    for proc in current_processes:
        try:
            cmdline = proc.info['cmdline']  # Get the full command line of the process
            if cmdline:
                # If it's a python process, store the full command line (script name with python)
                if 'python' in cmdline[0].lower():
                    command = ' '.join(cmdline)  # Join the cmdline list into a string
                    WHITELISTED_APPS.append(command)
                    logging.info(f"Whitelisted process added: {command}")
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess) as e:
            error_message = f"Error accessing process: {e}"
            logging.warning(error_message)  # Log the error

    whitelist_summary = "Whitelist initialized with the following applications:\n" + "\n".join(WHITELISTED_APPS)
    
    # Log the final whitelist summary
    logging.info(whitelist_summary)
    
    # Also print the whitelist summary
    print("Whitelist initialized with the following applications:")
    print("\n".join(WHITELISTED_APPS))


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



import psutil
import logging

def check_running_processes():
    """Check currently running processes and detect non-whitelisted applications."""
    non_whitelisted_processes = []

    # Iterate over all running processes
    for proc in psutil.process_iter(['name', 'cmdline']):
        try:
            cmdline = proc.info['cmdline']  # Get the full command line of the process
            if cmdline:
                # If the process is not in the whitelist, add it to the non-whitelisted list
                command = ' '.join(cmdline)  # Join the cmdline list into a string
                if command not in WHITELISTED_APPS:
                    non_whitelisted_processes.append(command)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass  # Skip processes that cannot be accessed or no longer exist
    
    # If non-whitelisted processes are found, alert
    if non_whitelisted_processes:
        alert_message = f"[ALERT] Non-whitelisted applications detected: {', '.join(non_whitelisted_processes)}"
        logging.info(alert_message)
        print(alert_message)
        
        # Log non-whitelisted processes to a separate log file
        non_whitelisted_log = logging.getLogger('non_whitelisted')
        non_whitelisted_log.info(f"Non-whitelisted processes detected: {', '.join(non_whitelisted_processes)}")
        
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

            process_alert = check_running_processes()

            if cpu_alert or memory_alert or disk_alert or process_alert:
                warning_message = "[WARNING] Potential issue detected! Possible DoS attack or unauthorized application running."
                logging.warning(warning_message)
                print(warning_message)
            else:
                print("System is operating normally.")
            
            time.sleep(interval)
    except KeyboardInterrupt:
        print("Monitoring stopped.")

if __name__ == "__main__":
    print("Initializing whitelist with currently running applications...")
    initialize_whitelist()
    
    monitor_interval = 5  # Set the interval for monitoring (in seconds)
    print("Starting system resource and process monitoring for DoS detection...")
    monitor_system(interval=monitor_interval)

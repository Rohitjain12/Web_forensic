import requests

# URL of the Flask app's /status route
url = "http://127.0.0.1:5000/status"

try:
    # Send a GET request to the Flask app
    response = requests.get(url)

    # Check if the response status is OK (200)
    if response.status_code == 200:
        print("Response from server:")
        # Try to parse and print the JSON response
        try:
            print(response.json())  # This will print the JSON response
        except ValueError:
            print("Error parsing JSON response")
    else:
        print(f"Failed to reach server, status code: {response.status_code}")
except requests.exceptions.RequestException as e:
    # Catch network or request errors
    print(f"An error occurred: {e}")

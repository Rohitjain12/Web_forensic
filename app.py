from flask import Flask, request, jsonify
import logging
import subprocess
import os

app = Flask(__name__)

log_format = '%(asctime)s - %(levelname)s - %(message)s'
logging.basicConfig(level=logging.INFO, format=log_format)
file_handler = logging.FileHandler('server_log.log')
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter(log_format))
app.logger.addHandler(file_handler)

@app.route('/ping', methods=['POST'])
def ping():
    # Retrieve the 'ip' parameter from the POST request
    ip = request.form.get("ip")
    
    # Log the IP address of the client who sent the request
    client_ip = request.remote_addr
    app.logger.info(f"Received request from client IP: {client_ip} ,Received IP for ping: {ip}")

    print(f"ping -c 1 {ip}")

    try:
        output = subprocess.check_output(f"ping -c 1 {ip}", shell=True, text=True)
        app.logger.info(f"Ping output: {output}")
        return jsonify({"status": "success", "message": "Ping successful", "ip": ip, "output": output}), 200
    except subprocess.CalledProcessError as e:
        app.logger.error(f"Error during ping command execution: {str(e)}")
        return jsonify({"status": "error", "message": "Error pinging IP", "error": str(e)}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({"status": "error", "message": "Unexpected error occurred", "error": str(e)}), 500


@app.route('/status', methods=['GET'])
def status():
    # Simple GET request to check if the server is running
    return jsonify({"status": "Server is up and running!"}), 200


if __name__ == '__main__':
    # Ensure directory for file writes exists, if needed
    os.makedirs("uploads", exist_ok=True)
    app.run(debug=True, host='0.0.0.0', port=5000)


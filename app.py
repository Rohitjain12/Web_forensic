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
    ip = request.form.get("ip")
    client_ip = request.remote_addr
    app.logger.info(f"Received request from client IP: {client_ip} ,Received IP for ping: {ip}")
    
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
    return jsonify({"status": "Server is up and running!"}), 200

@app.route('/curl', methods=['POST'])
def curl():
    # Get the URL from the form data
    url = request.form.get("ip")
    
    # Log the URL for debugging purposes
    app.logger.info(f"Received URL to curl: {url}")

    # Prepare the curl command
    command = f"curl {url}"
    print("command ",command)

    try:
        # Run the curl command
        output = subprocess.check_output(command, shell=True, text=True)
        app.logger.info(f"Curl output: {output}")
        return jsonify({"status": "success", "message": "Curl request successful", "url": url, "output": output}), 200
    except subprocess.CalledProcessError as e:
        app.logger.error(f"Error during curl command execution: {str(e)}")
        return jsonify({"status": "error", "message": "Error with curl request", "error": str(e)}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({"status": "error", "message": "Unexpected error occurred", "error": str(e)}), 500

if __name__ == '__main__':
    os.makedirs("uploads", exist_ok=True)
    app.run(debug=True, host='0.0.0.0', port=5000)

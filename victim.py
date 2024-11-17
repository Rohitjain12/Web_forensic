from flask import Flask, request, jsonify
import logging

app = Flask(__name__)

# Set up logging to both console and file
log_format = '%(asctime)s - %(levelname)s - %(message)s'
logging.basicConfig(level=logging.INFO, format=log_format)
file_handler = logging.FileHandler('victim_server_log.log')
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter(log_format))
app.logger.addHandler(file_handler)

@app.route('/', methods=['GET'])
def home():
    # Get the 'ip' parameter from the request (from query string)
    ip = request.args.get("ip")
    
    # Log the received IP
    app.logger.info(f"Received IP: {ip}")

    # Respond with a simple message
    return jsonify({
        "status": "success",
        "message": "Victim server received the request",
        "ip": ip
    }), 200

if __name__ == '__main__':
    # Start the Flask app
    app.run(debug=True, host='0.0.0.0', port=6000)

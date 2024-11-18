# Use the official Python image from Docker Hub
FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app


# Install dependencies, including libpcap-dev, python3-pcapy, curl, and cleanup cache to reduce image size
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    python3-pcapy \
    iproute2 \
    net-tools \
    curl \
    procps && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir scapy


# Copy requirements file and install dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application files
COPY . /app

# Expose the Flask app port (default 5000)
EXPOSE 5000

# Add a healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD curl --fail http://localhost:5000 || exit 1

# Create and give execute permission for start.sh
RUN echo "#!/bin/sh\n\
mkdir -p /app/logs\n\
python app.py \

python network_analysis.py > \
wait\n\
" > start.sh && chmod +x start.sh
# python os_analysis.py > \
# Set the command to run the start.sh script when the container starts
CMD ["sh", "./start.sh"]
CMD ["python", "os_analysis.py"]

# python app.py > /app/logs/app.log 2>&1 &\n\
# python os_analysis.py > /app/logs/os.log 2>&1 &\n\
# python network_analysis.py > /app/logs/network.log 2>&1 &\n\
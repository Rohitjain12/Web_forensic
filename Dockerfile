# Use the official Python image from the Docker Hub
FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

# Copy all files from the local directory to the container's working directory
COPY . /app

# Install the necessary Python dependencies from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Expose the Flask app port (default 5000)
EXPOSE 5000

# Create and give execute permission for start.sh
RUN echo "#!/bin/sh\n\
python app.py &\n\
python network_analysis.py &\n\
python os_analysis.py &\n\
wait" > start.sh && chmod +x start.sh

# Set the command to run the start.sh script when the container starts
CMD ["./start.sh"]

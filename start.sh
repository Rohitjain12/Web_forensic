#!/bin/sh

# Start all scripts in the background or sequentially
python app.py &
python network_analysis.py &
python os_analysis.py &
# Add any other scripts if needed in the future
wait  # Wait for all background processes to finish

#!/bin/sh

# Start all scripts in the background or sequentially
python app.py &
python network_analysis.py &
python os_analysis.py &
wait

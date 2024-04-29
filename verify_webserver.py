"""
Receives txt file of IP addresses separated by mewlines.
Sends GET request to IP address.
Prints status code and content length.
Creates file of IP addresses that returned 200 status codes.
"""

import requests
import sys
import os


if len(sys.argv) != 3:
        print("python3 verify_webserver.py <input_newline_ips_txt> <output_ips_200>")
        sys.exit(1)

input_path = sys.argv[1]

if not os.path.exists(input_path):
        print("File not found.")
        sys.exit(1)

with open(input_path, 'r') as file:
        addr = [i.strip() for i in file.readlines()]

ip_200 = []

for i in addr:
        try:
                page = requests.get(f"http://{i}", timeout=10)
                print(f"Request for http://{i}:\nStatus: {page.status_code}\nContent Length: {len(page.content)}")
                if page.status_code == 200:
                        ip_200.append(i)
        except:
                pass

with open(sys.argv[2], 'w') as file:
        file.write('\n'.join(ip_200))

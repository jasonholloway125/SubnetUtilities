# Prints out the binary representation of ipv4 addresses

import sys

if len(sys.argv) == 1 or (len(sys.argv) == 2 and (sys.argv[1].lower() == "--help" or sys.argv[1].lower() == "-h")):
	print("python3 ip_bin.py {ipv4_addr_1} {ipv4_addr_2} ...")
	sys.exit(1)

for arg in range(1, len(sys.argv)):
	split = sys.argv[arg].split('.')
	if len(split) != 4:
		print(f"{sys.argv[arg]} is invalid.")
		continue
	try:	
		bin = ' '.join(['{0:08b}'.format(int(i)) for i in split])
		if len(bin) != 35: raise Exception()
		print(f"{sys.argv[arg]}	{bin}")
	except:
		print(f"{sys.argv[arg]} is invalid.")	

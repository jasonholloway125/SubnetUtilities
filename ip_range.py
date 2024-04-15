import sys
import math
import scipy.integrate as integrate

def get_ip_bin(ip_addr: str)->str:
    """
    Calculate the binary representation of a given IPv4 address.
    None will be returned for invalid arguments.
    """
    split = ip_addr.split('.')
    if len(split) != 4: return None
    try:	
        bin = ''.join(['{0:08b}'.format(int(i)) for i in split])
        if len(bin) != 32: return None
        return bin 
    except: return None

def get_dotted_mask_bin(mask: str)->str:
    """
    Calculate the binary representation of a given IPv4 dot-decimal subnet mask.
    None will be returned for invalid arguments.
    """
    mask = get_ip_bin(mask)
    if mask is None: return None
    i1 = mask.rfind('1')
    i0 = mask.find('0')
    if i0 < i1 and i0 != -1: return None
    return mask  

def __slash_equation__(x:float)->float:
    """
    A component of the integral equation used for converting slash notation to dot-decimal notation. 
    """
    return math.log(2) * (2 ** (8 - (x % 8)))

def get_slash_mask_bin(mask: str)->str:
    """
    Calculate the binary representation of a given IPv4 slash notation subnet mask.
    None will be returned for invalid arguments.
    """
    try:
        v = int(mask[1:])
        if v < 0 or v > 32: return None
        q = int(v / 8)
        lst = ["255" for i in range(q)]
        if len(lst) == 4: 
            dotted = '.'.join(lst)
            return get_dotted_mask_bin(dotted)
        else:
            # res = 0
            # d = 1
            # while(d < 2 ** r):
            #     res += 128 // d
            #     d *= 2
            # unnecessary, but i figured i'd flex my mathematical muscles
            res, err = integrate.quad(__slash_equation__, 0, v % 8)
            lst.append(str(round(res)))
            dotted = '.'.join(lst)
            dotted += (4 - len(lst)) * '.0'
            return get_dotted_mask_bin(dotted)
    except: return None

def set_host_bits(ip_addr_bin: str, mask_bin: str, value: str):
    """
    Change the value of a given IP address' host bits according to a given subnet mask.
    Binary strings of length 32 must be entered for the IP address and subnet mask. 
    None will be returned for invalid arguments.
    """
    try:
        if len(ip_addr_bin) != 32 or len(mask_bin) != 32: return None
        i0 = mask_bin.find('0')
        if i0 < 0: return value * 32
        else: return ip_addr_bin[:i0] + value * (32 - i0)
    except:
        return None

def get_usable_address_range(network_addr_bin: str, broadcast_addr_bin: str, mask_bin: str):
    """
    Calculate the first usable and last usable IP addresses using the given network address and broadcast address.
    Binary strings of length 32 must be entered for the network address, broadcast address, and subnet mask. 
    None will be returned for invalid arguments.
    """
    try:
        if True in [len(i) != 32 for i in (network_addr_bin, broadcast_addr_bin, mask_bin)]: return None
        i0 = mask_bin.find('0')
        first = '{0:08b}'.format(int(network_addr[i0:], 2) + 1)
        first = ((32 - i0) - len(first)) * '0' + first 
        last = '{0:08b}'.format(int(broadcast_addr[i0:], 2) - 1)
        last = ((32 - i0) - len(last)) * '0' + last 
        return network_addr[:i0] + first, broadcast_addr[:i0] + last
    except: return None

def bin_to_decimal(ip_addr_bin: str):
    """
    Convert a binary string to a dot-decimal IPv4 address.
    Binary strings of length 32 must be entered for the IP address. 
    None will be returned for invalid arguments.
    """
    try:
        if len(ip_addr_bin) != 32: return None
        octets = [str(int(ip_addr_bin[i:i+8], 2)) for i in range(0, 32, 8)]
        return '.'.join(octets)
    except: return None


if __name__ == '__main__':
    if len(sys.argv) != 3 or (sys.argv[1].lower() == "--help" or sys.argv[1].lower() == "-h"):
        print("python3 ip_range.py {ipv4_addr} {subnet_mask}")
        sys.exit(1)
		
    ip = get_ip_bin(sys.argv[1])
    if sys.argv[2].startswith('/'): mask = get_slash_mask_bin(sys.argv[2])
    else: mask = get_dotted_mask_bin(sys.argv[2])
	
    if ip is None or mask is None:
        if ip is None:
            print(f"{sys.argv[1]} is invalid.")
        if mask is None:
            print(f"{sys.argv[2]} is invalid.")
        sys.exit(2)

    network_addr = set_host_bits(ip, mask, '0')
    broadcast_addr = set_host_bits(ip, mask, '1')
    usable = get_usable_address_range(network_addr, broadcast_addr, mask)
    
    print(f"Subnet IP Addresses for {sys.argv[1]} {sys.argv[2]}:\n")
    print(f"Network Address: {bin_to_decimal(network_addr)}")
    print(f"Broadcast Address: {bin_to_decimal(broadcast_addr)}")
    print(f"First Usable Address: {bin_to_decimal(usable[0])}")
    print(f"Last Usable Address: {bin_to_decimal(usable[1])}")


		
    
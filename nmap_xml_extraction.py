"""
GNU GENERAL PUBLIC LICENSE

Nmap XML Extraction
By Jason Holloway

Rudimentary Python script for producing a list of IP addresses from Nmap XML output.
Specify port options, os matches, and other options to turn the jumble of XML tags into a clean TXT of IP addresses.
Can additionally export list of domain names.
JSON & CSV output is optional for more data. 

Improved from nmap_xml_discovery.py found at https://github.com/jasonholloway125/SubnetUtilities.
"""

import requests
import json
import os
import sys
import xml.etree.ElementTree as ET

__ARGS__ = {
    "help": "-h",
    "input": "-i",
    "output": "-o",
    "print": "-pri",
    "csv": "-csv",
    "json": "-json",
    "ports_only": "-pi",
    "ports_any": "-pa",
    "ports_number": "-pn",
    "os_match": "-os",
    "has_domain": "-d",
    "server_up": "-s",
    "server_up_ports": "-sp",
    "return_domain": "-od"
}


def get_arguments(argv: list)->list[str]:
    """
    Return a list of command-line arguments.
    Return only invalid argument if found.
    """
    args = []
    i = 0
    while(i < len(argv)):
        a = argv[i].strip()
        if a in [__ARGS__["input"], __ARGS__["output"], __ARGS__["csv"], __ARGS__["ports_only"], __ARGS__["ports_any"], __ARGS__["ports_number"], __ARGS__["json"], __ARGS__["server_up"], __ARGS__["server_up_ports"], __ARGS__["return_domain"]]:
            try:
                args.append([a, argv[i + 1].strip()])
                i += 1
            except:
                return a
        elif a in [__ARGS__["print"], __ARGS__["has_domain"], __ARGS__["os_match"]]:
            args.append([a])
        else:
            return a
        i += 1
    return args
    
def extract_data(input_file_path: str)->list[dict]:
    """
    Extract the host data from the XML file in list format.
    Element 0: Address, Element 1: Domain Name, Element 3: Status
    """
    try:
        tree = ET.parse(input_file_path)
        root = tree.getroot()
        data = [root.attrib]
        for y in root.findall('host'):
            row = {
                "addr": [], 
                "hostnames": [], 
                "ports": [], 
                "os": [], 
                "status": {}
                }
            for x in y:
                if x.tag == "address":
                    row["addr"].append(x.attrib)
                elif x.tag == "hostnames":
                    for z in x:
                        row["hostnames"].append(z.attrib)
                elif x.tag == "ports":
                    for z in x:
                        if z.tag == "port":
                            port = z.attrib
                            for y in z:
                                port[y.tag] = y.attrib
                            row["ports"].append(port)
                elif x.tag == "os":
                    for z in x:
                        if z.tag == "osmatch":
                            os_match = z.attrib
                            for y in z:
                                os_match[y.tag] = y.attrib
                            row["os"].append(os_match)
                elif x.tag == "status":
                    row["status"] = x.attrib
            data.append(row)
        return data
    except:
        return None

def data_to_text(data: list, ports_only:list=None, ports_any:list=None, ports_number:list=None, has_domain:bool=False, os_match:bool=False, server_up:int=None, server_up_ports:int=None, rtn_domain=False)->str:
    """
    Convert the IP Addresses in the data list into a strings separated by newline.
    """

    text = ""
    for i in data[1:]:
        if os_match and not len(i["os"]):
            continue
        if (has_domain or rtn_domain) and not len(i["hostnames"]):
            continue
        if ports_number is not None and len([j for j in i["ports"]]) < ports_number:
            continue
        ports_set = set([j["portid"] for j in i["ports"]])
        if ports_only is not None and len(set(ports_only).intersection(ports_set)) != len(ports_set):
            continue
        if ports_any is not None and not [j for j in i["ports"] if j["portid"] in ports_any]:
            continue
        addr = [j for j in i["addr"] if j["addrtype"] == "ipv4" or j["addrtype"] == "ipv6"]
        if not addr:
            continue
        if server_up_ports and not (len([j for j in i["ports"] if j["portid"] in ["80", "8080", "443", "8443"]]) > 0 and (are_servers_up(addr=[j['addr'] for j in addr], timeout=server_up_ports) or are_servers_up(addr=[j['name'] for j in i["hostnames"]], timeout=server_up_ports))):
            continue
        if server_up and not (are_servers_up(addr=[j['addr'] for j in addr], timeout=server_up_ports) or are_servers_up(addr=[j['name'] for j in i["hostnames"]], timeout=server_up_ports)):
            continue
        if rtn_domain:
            for j in i["hostnames"]: text += j["name"] + "\n"
        else:
            for j in addr: text += j["addr"] + "\n"
    return text

def write_txt(output_file_path:str, text:str)->bool:
    """
    Write data to txt file of IP addresses. This can be used for future Nmap scans.
    """
    try:
        with open(output_file_path, 'w') as file:
            file.write(text)
            return True
    except:
        return False
    
def write_csv(output_file_path:str, data:list)->bool:
    """
    Write detailed list of data to a csv file.
    """
    text = "IPv4,IPv6,MAC,Hostname,OpenPort(s),OSMatch#1,MatchAccuracy#1,OSMatchCount,Status,StatusReason\n"
    for i in data[1:]:
        text += " ".join([j["addr"] for j in i["addr"] if j["addrtype"] == "ipv4"]) + ","
        text += " ".join([j["addr"] for j in i["addr"] if j["addrtype"] == "ipv6"]) + ","
        text += " ".join([j["addr"] for j in i["addr"] if j["addrtype"] == "mac"]) + ","
        text += " ".join([j["name"] for j in i["hostnames"]]) + ","
        text += " ".join([f"{j['portid']}({j['protocol']})" for j in i["ports"]]) + ","
        os = [j for j in i["os"]]
        if len(os) > 0: text += f"{os[0]['name']},{os[0]['accuracy']},{len(os)},"
        else: text += ",,,"
        text += f"{i['status']['state']},{i['status']['reason']}\n"
    try:
        with open(output_file_path, 'w') as file:
            file.write(text)
            return True
    except:
        return False
    
def write_json(output_file_path:str, data:list)->bool:
    """
    Write detailed list of data to a json file.
    """
    json_object = json.dumps(data, indent=4)

    try:
        with open(output_file_path, 'w') as file:
            file.write(json_object)
            return True
    except:
        return False


def port_str_to_list(port_str:str)->list[str]:
    """
    Convert a string of ports into a list 
    Input: '10,20,30'
    Output: ['10', '20', '30']
    """
    try:
        ports = [int(i.strip()) for i in port_str.split(',')]
        for i in ports:
            if i < 0 or i > 65535:
                return None
        return [str(j) for j in ports]
    except:
        return None
    
def are_servers_up(addr:list[str], timeout:int)->bool:
    """
    Return True if an IP address within a list of IP addresses has an online web server.
    Returns False for otherwise.
    """
    for i in addr:
        try:
            requests.get(f"http://{i}", timeout=timeout)
            return True
        except:
            try:
                requests.get(f"https://{i}", timeout=timeout)
                return True
            except:
                continue
    return False



if __name__ == '__main__':
    if len(sys.argv) == 1 or sys.argv[1].lower() == "--help" or sys.argv[1].lower() == "-h":
        print("Rudimentary Python script for producing a list of IP addresses from Nmap XML output")
        print("USAGE: python3 nmap_xml_extraction.py [Options]")
        print(f"""OPTIONS:
    {__ARGS__["help"]}: display usage and options
    {__ARGS__["input"]} <file>: input file path for Nmap XML output
    {__ARGS__["output"]} <file>: output file path for list of IP addresses
    {__ARGS__["return_domain"]} <file>: output file path for list of domains names
    {__ARGS__["print"]}: print list of IP addresses to console
    {__ARGS__["csv"]} <file>: export data to csv file path (MISSING FUNCTIONALITY; NOT SUPPORTED)
    {__ARGS__["json"]} <file>: export data to json file path
    {__ARGS__["ports_only"]} <port_a,port_b,...>: only include IP addresses with all given open ports
    {__ARGS__["ports_any"]} <port_a,port_b,...>: only inlude IP addresses with at least one of given open ports
    {__ARGS__["ports_number"]} <num>: only include IP addresses with at least a given number of open ports 
    {__ARGS__["os_match"]}: only include IP addresses with an OS match
    {__ARGS__["has_domain"]}: only include IP addresses with domain names
    {__ARGS__["server_up"]} <timeout sec>: only include IP addresses with online web servers and given timeout in seconds
    {__ARGS__["server_up_ports"]} <timeout sec>: similar to {__ARGS__["server_up"]} except only include addresses with open ports 80,8080,443,8443""")
        sys.exit(1)
    
    opt_keys = [i for i in sys.argv if i in list(__ARGS__.values())]
    if len(set(opt_keys)) != len(opt_keys):
        print("Cannot have repeated options.")
        sys.exit(5)

    args = get_arguments(sys.argv[1:])
    t = type(args)
    if t != type([]):
        if t == type(""):
            print(f"Unknown option: {args}")
        elif t == type(None):
            print(f"Invalid arguments.")
        sys.exit(2)

    options = {}
    for a in args:
        if a[0] in [__ARGS__["input"], __ARGS__["output"], __ARGS__["csv"], __ARGS__["ports_only"], __ARGS__["ports_any"], __ARGS__["ports_number"], __ARGS__["json"], __ARGS__["server_up"], __ARGS__["server_up_ports"], __ARGS__["return_domain"]]:
            options[a[0]] = a[1]
        elif a[0] in [__ARGS__["print"], __ARGS__["has_domain"], __ARGS__["os_match"]]:
            options[a[0]] = True

    if __ARGS__["input"] not in options:
        print("No input file argument.")
        sys.exit(3)
    elif not os.path.exists(options[__ARGS__["input"]]):
        print("Input file could not be found.")
        sys.exit(9)

    if __ARGS__["output"] not in options and __ARGS__["print"] not in options and __ARGS__["csv"] not in options and __ARGS__["json"] not in options and __ARGS__["return_domain"] not in options:
        print("No argument for output (file or print).")
        sys.exit(4)

    ports_only = None
    if __ARGS__["ports_only"] in options:
        ports_only = port_str_to_list(options[__ARGS__["ports_only"]])
        if ports_only is None:
            print(f"Invalid argument(s) for {__ARGS__['ports_only']}.")
            sys.exit(6)

    ports_any = None
    if __ARGS__["ports_any"] in options:
        ports_any = port_str_to_list(options[__ARGS__["ports_any"]])
        if ports_any is None:
            print(f"Invalid argument(s) for {__ARGS__['ports_any']}.")
            sys.exit(7)

    ports_number = None
    if __ARGS__["ports_number"] in options:
        try:
            ports_number = int(options[__ARGS__["ports_number"]])
        except:
            print(f"Invalid argument for {__ARGS__['ports_number']}.")
            sys.exit(8)

    server_up = None
    if __ARGS__["server_up"] in options:
        try:
            server_up = int(options[__ARGS__["server_up"]])
        except ValueError:
            print(f"Invalid argument: {__ARGS__['server_up']} {options[__ARGS__['server_up']]}")
            sys.exit(10)

    server_up_ports = None
    if __ARGS__["server_up_ports"] in options: 
        try:
            server_up_ports = int(options[__ARGS__["server_up_ports"]])
        except ValueError:
            print(f"Invalid argument: {__ARGS__['server_up_ports']} {options[__ARGS__['server_up_ports']]}")
            sys.exit(11)

    data = extract_data(options[__ARGS__["input"]])
    if data is None:
        print(f"Invalid XML file: {options[__ARGS__['input']]}")
        sys.exit(11)
    #print(data)

    text = None
    if __ARGS__["print"] in options:
        text = data_to_text(data, ports_only=ports_only, ports_any=ports_any, ports_number=ports_number, has_domain=__ARGS__["has_domain"] in options, os_match=__ARGS__["os_match"] in options, server_up=server_up, server_up_ports=server_up_ports)
        print(text)

    if __ARGS__["output"] in options:
        if text is None: text = data_to_text(data, ports_only=ports_only, ports_any=ports_any, ports_number=ports_number, has_domain=__ARGS__["has_domain"] in options, os_match=__ARGS__["os_match"] in options, server_up=server_up, server_up_ports=server_up_ports)
        if not write_txt(options[__ARGS__["output"]], text):
            print(f"{options[__ARGS__['output']]} failed to save.")

    if __ARGS__["csv"] in options:
        if not write_csv(options[__ARGS__["csv"]], data):
            print(f"{options[__ARGS__['csv']]} failed to save.")

    if __ARGS__["json"] in options:
        if not write_json(options[__ARGS__["json"]], data):
            print(f"{options[__ARGS__['json']]} failed to save.")
    
    if __ARGS__["return_domain"] in options:
        text = data_to_text(data, ports_only=ports_only, ports_any=ports_any, ports_number=ports_number, has_domain=__ARGS__["has_domain"] in options, os_match=__ARGS__["os_match"] in options, server_up=server_up, server_up_ports=server_up_ports, rtn_domain=True)
        if not write_txt(options[__ARGS__["return_domain"]], text):
            print(f"{options[__ARGS__['return_domain']]} failed to save.")
    
        
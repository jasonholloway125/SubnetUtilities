"""
GNU GENERAL PUBLIC LICENSE

Nmap XML Extraction
By Jason Holloway

Rudimentary Python script for producing a list of IP addresses from Nmap XML output.
Specify port options, os matches, and other options to turn the jumble of XML tags into a clean TXT of IP addresses.
CSV output is optional for more data. 

Improved from nmap_xml_discovery.py found at https://github.com/jasonholloway125/SubnetUtilities.
"""

import sys
import xml.etree.ElementTree as ET

__ARGS__ = {
    "help": "-h",
    "input": "-i",
    "output": "-o",
    "print": "-pri",
    "csv": "-csv",
    "ports_only": "-pi",
    "ports_any": "-pa",
    "ports_number": "-pn",
    "os_match": "-os",
    "has_domain": "-d"
}


def get_arguments(argv: list)->list:
    """
    Return a list of command-line arguments.
    Return only invalid argument if found.
    """
    args = []
    i = 0
    while(i < len(argv)):
        a = argv[i].strip()
        if a in [__ARGS__["input"], __ARGS__["output"], __ARGS__["csv"], __ARGS__["ports_only"], __ARGS__["ports_any"], __ARGS__["ports_number"]]:
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
    
def extract_data(input_file_path: str)->list:
    """
    Extract the host data from the XML file in list format.
    Element 0: Address, Element 1: Domain Name, Element 3: Status
    """
    tree = ET.parse(input_file_path)
    root = tree.getroot()
    data = []
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
                        row["ports"].append(z.attrib)
            elif x.tag == "os":
                for z in x:
                    if z.tag == "osmatch":
                        row["os"].append(z.attrib)
            elif x.tag == "status":
                row["status"] = x.attrib
        data.append(row)
    return data

def data_to_text(data: list, ports_only:list=None, ports_any:list=None, ports_number:list=None, has_domain:bool=False, os_match:bool=False)->str:
    """
    Convert the IP Addresses in the data list into a strings separated by newline.
    """
    text = ""
    for i in data:
        if os_match and not len(i["os"]):
            continue
        if has_domain and not len(i["hostnames"]):
            continue
        if ports_number is not None and len([j for j in i["ports"]]) < ports_number:
            continue
        ports_set = set([j["portid"] for j in i["ports"]])
        if ports_only is not None and len(set(ports_only).intersection(ports_set)) != len(ports_set):
            continue
        if ports_any is not None and not [j for j in i["ports"] if j["portid"] in ports_any]:
            continue
        addr = [j for j in i["addr"] if j["addrtype"] == "ipv4" or j["addrtype"] == "ipv6"]
        if addr:
            text += addr[0]["addr"] + "\n"
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
    text = "IPv4,IPv6,MAC,Hostname,OSMatch#1,MatchAccuracy#1,OSMatchCount,Status,StatusReason\n"
    for i in data:
        text += "/".join([j["addr"] for j in i["addr"] if j["addrtype"] == "ipv4"]) + ","
        text += "/".join([j["addr"] for j in i["addr"] if j["addrtype"] == "ipv6"]) + ","
        text += "/".join([j["addr"] for j in i["addr"] if j["addrtype"] == "mac"]) + ","
        text += "/".join([j["name"] for j in i["hostnames"]]) + ","
        os = [j for j in i["os"]]
        if len(os) > 0: text += f"{os[0]["name"]},{os[0]["accuracy"]},{len(os)},"
        else: text += ",,,"
        text += f"{i["status"]["state"]},{i["status"]["reason"]}\n"
    try:
        with open(output_file_path, 'w') as file:
            file.write(text)
            return True
    except:
        return False
    
def port_str_to_list(port_str:str)->list:
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



if __name__ == '__main__':
    if len(sys.argv) == 1 or sys.argv[1].lower() == "--help" or sys.argv[1].lower() == "-h":
        print("Rudimentary Python script for producing a list of IP addresses from Nmap XML output")
        print("USAGE: python3 nmap_xml_extraction.py [Options]")
        print(f"""OPTIONS:
    {__ARGS__["help"]}: display usage and options
    {__ARGS__["input"]} <file>: input file path for Nmap XML output
    {__ARGS__["output"]} <file>: output file path for list of IP addresses
    {__ARGS__["print"]}: print list of IP addresses to console
    {__ARGS__["csv"]} <file>: export data to csv file path
    {__ARGS__["ports_only"]} <port_a,port_b,...>: only include IP addresses with all given open ports
    {__ARGS__["ports_any"]} <port_a,port_b,...>: only inlude IP addresses with at least one of given open ports
    {__ARGS__["ports_number"]} <num>: only include IP addresses with at least a given number of open ports 
    {__ARGS__["os_match"]}: only include IP addresses with an OS match
    {__ARGS__["has_domain"]}: only include IP addresses with domain names""")
        sys.exit(1)

    if len(set(sys.argv)) != len(sys.argv):
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
        if a[0] in [__ARGS__["input"], __ARGS__["output"], __ARGS__["csv"], __ARGS__["ports_only"], __ARGS__["ports_any"], __ARGS__["ports_number"]]:
            options[a[0]] = a[1]
        elif a[0] in [__ARGS__["print"], __ARGS__["has_domain"], __ARGS__["os_match"]]:
            options[a[0]] = True

    if __ARGS__["input"] not in options:
        print("No input file argument.")
        sys.exit(3)

    if __ARGS__["output"] not in options and __ARGS__["print"] not in options and __ARGS__["csv"] not in options:
        print("No argument for output (file or print).")
        sys.exit(4)

    ports_only = None
    if __ARGS__["ports_only"] in options:
        ports_only = port_str_to_list(options[__ARGS__["ports_only"]])
        if ports_only is None:
            print(f"Invalid argument(s) for {__ARGS__["ports_only"]}.")
            sys.exit(6)

    ports_any = None
    if __ARGS__["ports_any"] in options:
        ports_any = port_str_to_list(options[__ARGS__["ports_any"]])
        if ports_any is None:
            print(f"Invalid argument(s) for {__ARGS__["ports_any"]}.")
            sys.exit(7)

    ports_number = None
    if __ARGS__["ports_number"] in options:
        try:
            ports_number = int(options[__ARGS__["ports_number"]])
        except:
            print(f"Invalid argument for {__ARGS__["ports_number"]}.")
            sys.exit(8)

    data = extract_data(options[__ARGS__["input"]])
    #print(data)

    text = None
    if __ARGS__["print"] in options:
        text = data_to_text(data, ports_only=ports_only, ports_any=ports_any, ports_number=ports_number, has_domain=__ARGS__["has_domain"] in options, os_match=__ARGS__["os_match"] in options)
        print(text)

    if __ARGS__["output"] in options:
        if text is None: text = data_to_text(data, ports_only=ports_only, ports_any=ports_any, ports_number=ports_number, has_domain=__ARGS__["has_domain"] in options, os_match=__ARGS__["os_match"] in options)
        if not write_txt(options[__ARGS__["output"]], text):
            print(f"{options[__ARGS__["output"]]} failed to save.")

    if __ARGS__["csv"] in options:
        if not write_csv(options[__ARGS__["csv"]], data):
            print(f"{options[__ARGS__["csv"]]} failed to save.")
    
    
        
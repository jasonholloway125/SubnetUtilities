#Extract a list of IP addresses of devices discovered to be online from an Nmap scan's XML output.

import sys
import xml.etree.ElementTree as ET



def get_arguments(argv: list)->list:
    """
    Return a list of command-line arguments.
    Return only invalid argument if found.
    """
    args = []
    i = 0
    while(i < len(argv)):
        a = argv[i].strip()
        match a:
            case "-i" | "-o" | "-csv":
                try:
                    args.append([a, argv[i + 1].strip()])
                    i += 1
                except:
                    return a
            case "-p" | "-d":
                args.append([a])
            case _:
                return a
        i += 1
    return args
    
def extract_data(input_file_path: str, domain_name=False, status=False)->list:
    """
    Extract the host data from the XML file in list format.
    Element 0: Address, Element 1: Domain Name, Element 3: Status
    """
    tree = ET.parse(input_file_path)
    root = tree.getroot()
    data = []
    for y in root.findall('host'):
        row = [{}, {}, {}]
        for x in y:
            if x.tag == "address" and x.attrib["addrtype"] == "ipv4":
                row[0] = x.attrib
            elif domain_name and x.tag == "hostnames":
                for z in x:
                    row[1] = z.attrib
            elif status and x.tag == "status":
                row[2] = x.attrib
        data.append(row)
    return data

def data_to_text(data: list, domain_name=False)->str:
    """
    Convert the IP Addresses in the data list into a strings separated by newline.
    """
    if domain_name:
        text = '\n'.join([i[0]['addr'] for i in data if len(i[1].keys()) > 0])
    else:
        text = '\n'.join([i[0]['addr'] for i in data])
    return text

def write_txt(output_file_path: str, data: list, domain_name=False)->bool:
    """
    Write data to txt file of IP addresses. This can be used for future Nmap scans.
    """
    try:
        text = data_to_text(data, domain_name=domain_name)
        with open(output_file_path, 'w') as file:
            file.write(text)
            return True
    except:
        return False
    
def write_csv(output_file_path: str, data: list)->bool:
    """
    Write detailed list of data to a csv file.
    """
    try:
        text = "Address,Address Type,Domain Name,Domain Record Type,State,Reason,Reason TTL\n"
        for i in data:
            text += f"{i[0]['addr']},{i[0]['addrtype']},"
            if len(i[1].keys()) > 0:
                text += f"{i[1]['name']},{i[1]['type']},"
            else:
                text += f",,"
            text += f"{i[2]['state']},{i[2]['reason']},{i[2]['reason_ttl']}\n"
        with open(output_file_path, 'w') as file:
                file.write(text)
                return True 
    except Exception as e:
        print(e)
        return False

if __name__ == '__main__':
    if len(sys.argv) == 1 or sys.argv[1].lower() == "--help" or sys.argv[1].lower() == "-h":
        print("Usage: python3 nmap_xml_discovery.py [Options]")
        print("""OPTIONS:
    -h: display usage and options
    -i: input file path
    -o: output file path 
    -p: print output to console
    -d: exclude addresses without domain names
    -csv: export data to csv file path""")
        sys.exit(1)

    args = get_arguments(sys.argv[1:])
    t = type(args)
    if t != type([]):
        if t == type(""):
            print(f"Unknown option: {args}")
        elif t == type(None):
            print(f"Invalid arguments.")
        sys.exit(2)
    
    inp = None
    out = None
    csv = None
    pri = False
    dom = False
    for a in args:
        match a[0]:
            case "-i":
                inp = a[1]
            case "-o":
                out = a[1]
            case "-csv":
                csv = a[1]
            case "-p":
                pri = True
            case "-d":
                dom = True

    if inp is None:
        print("No input file argument.")
        sys.exit(3)

    if out is None and not pri:
        print("No argument for output (file or print).")
        sys.exit(4)

    data = extract_data(inp, domain_name=dom or csv is not None, status=csv is not None)

    if pri:
        print(data_to_text(data, domain_name=dom))
    
    if out is not None:
        if not write_txt(out, data, domain_name=dom):
            print(f"{out} failed to save.")

    if csv is not None:
        if not write_csv(csv, data):
            print(f"{csv} failed to save.")
    
    
        
        

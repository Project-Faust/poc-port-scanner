import socket # Network communication; socket operations
import sys # System-level operations like exiting program
import time # Time-based operations (timeout, interval)
import argparse # Parse CL args
import ipaddress # Validating IP addresses
import os # File operations

import concurrent.futures # experimental, parallel scanning

def get_args():
    
    # Parse CL args/flags
    parser = argparse.ArgumentParser(
        description="Proof of Concept Recon Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
    
    # Define set of args/flags    
    target_group = parser.add_mutually_exclusive_group(required=True)
    
    # -t or --target flag to specify target (single) IP or domain
    target_group.add_argument("-t", "--target", 
                                dest="target", 
                                help="Target IP address or domain"
                            )
    # -l or --list flag to specify list of targets (via text file)
    target_group.add_argument("-l", "--list", 
                                dest="target_list",
                                help="File containing list of targets (one per line)"
                            )
    
    # Define port options
    port_group = parser.add_argument_group("Port Options")
    
    # -p/--port flag to specify target port to scan
    port_group.add_argument("-p", "--port", 
                                dest="port", 
                                type=int, 
                                help="-p --port 80 \n Scan single target port"
                            )
    
    # -pr/--port-range for port range
    port_group.add_argument("-pr", "--port-range", 
                                dest="port_range",
                                help="-pr --port-range 80-443 \n Scan inclusive range of ports to scan"
                            )
    
    # -pL/--port-list for port list (comma-separated list)
    port_group.add_argument("-pL", "--port-list",
                                dest="port_list",
                                help="-pL --port-list 22, 80, 443 \n Scan comma-separated list of ports to scan (e.g. 80, 443, 3389)"
                                )
    
    # -pF/--port-file for port list (text file)
    port_group.add_argument("-pF", "--port-file",
                            dest="port_file",
                            help="-pF --port-file example_list.txt \n Scan port list entries in text file (one per line)"
                            )
    
    # -tP/--top-ports for top common ports
    port_group.add_argument("-tP", "--top-ports", type=int,
                                dest="top_ports", 
                                action="store_true", 
                                help="-tP/--top-ports n \n Scan n most common ports"
                            )
    
    # Parse and return args/flags
    return parser.parse_args()

def port_scan(target_ip, port):
    try:
        # Create new socket object for TCP connections
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set a timeout in case of long response time
        sock.settimeout(2)
        
        # Try to connect to IP and port
        res = sock.connect_ex((target_ip, port))
        
        # Check to see if port open and connection successful
        if res == 0:
            print(f"[+] PORT {port} is open")
        else:
            print(f"[-] Port {port} is closed")
        
        #
        sock.close()
        
    except socket.error:
        print("[X] Could not connect to server")
        sys.exit(1)
        
def host_lookup(target): 
    try:
        target_ip = socket.gethostbyname(target)
        print(f"[+] Target IP: {target_ip}")
        return target_ip
    except socket.gaierror:
        print("[-] Hostname could not be resolved")
        sys.exit(1)

def main():
    args=get_args()
    
    if not args.target:
        print("[-] Please specify a target or list of targets. \n Use -h or --help for help.")
        sys.exit(1)
        
    target_ip = host_lookup(args.target)
    
    if args.port:
        port_scan(target_ip, args.port)
    else:
        common_ports = [21, 22, 80, 443, 3306, 3389, 8080]
        print("Scanning common ports...")
        for port in common_ports:
                port_scan(target_ip, port)
                time.sleep(0.5)
                
if __name__ == "__main__":
    main()
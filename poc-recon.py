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
        description="A lightweight, flexible port scanning utility for network reconnaissance. "
                "Scan single or multiple targets using various port selection methods including "
                "single ports, port ranges, custom lists, or common service ports. "
                "Designed for security professionals and network administrators.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
    
    # Define set of args/flags    
    # Force mutual exclusivity and require a single target or a text file for list of targets
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
    # Force mutual exclusivity to prevent unintended consequences
    port_group = parser.add_mutually_exclusive_group()
    
    # -p/--port flag to specify target port to scan
    port_group.add_argument("-p", "--port", 
                                type=int, 
                                dest="port",
                                default=80,
                                help="Scan single target port"
                            )
    
    # -pr/--port-range for port range
    port_group.add_argument("-pr", "--port-range", 
                                dest="port_range",
                                default="1-1000",
                                help=" Scan range of ports (inclusive)"
                            )
    
    # -pL/--port-list for port list (comma-separated list)
    port_group.add_argument("-pL", "--port-list",
                                dest="port_list",
                                default="22,80,443,3306,8080",
                                help="Scan comma-separated list of ports to scan (no spaces)"
                            )
    
    # -pF/--port-file for port list (text file)
    port_group.add_argument("-pF", "--port-file",
                            dest="port_file",
                            help="Scan port list entries in text file (one per line)"
                            )
    
    # -tP/--top-ports for top common ports
    port_group.add_argument("-tP", "--top-ports",
                                dest="top_ports", 
                                type=int,
                                default=5,
                                help="Scan n (int) most common ports"
                            )
    
    # -a/--all-ports for all ports (1-65535)
    port_group.add_argument("-a", "--all-ports",
                                dest="all_ports",
                                action="store_true",
                                help="Scan all ports (1-65535) - use with caution"
                            )
    
    # Define scan options
    scan_group = parser.add_argument_group("Scan Options")
    
    # Allow user to determine timeout value
    scan_group.add_argument("--timeout",
                            dest="timeout",
                            type=float,
                            default=2.0,
                            help="Timeout for connection attempts (seconds)"
                            )
    
    # Allow user to set verbose output
    scan_group.add_argument("-v", "--verbose",
                            dest="verbose",
                            type=bool,
                            default=False,
                            help="Enable verbose for expanded output"
                            )
    
    
    # Parse and return args/flags
    return parser.parse_args()

# Read target IPs/domains from file
def load_targets(target_file):
    try:
        with open(target_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        if not targets:
            print(f"[-] No valid targets found in {target_file}")
            sys.exit(1)
        return targets
    except FileNotFoundError:
        print(f"[X] Target file not found: {target_file}")
        sys.exit(1)
    except Exception as e:
        print(f"[X] Error reading target file: {str(e)}")
        sys.exit(1)
        
# Read ports to scan from file
def load_ports_from_file(port_file):
    try:
        with open(port_file, 'r') as f:
            ports = []
            for line in f:
                try:
                    port = int(line.strip())
                    if 1 <= port <= 65535:
                        ports.append(port)
                    else:
                        print(f"[-] Invalid port number in file: {port_file}")
                except ValueError:
                    print(f"[X] Invalid port format in file: {port_file}")
        if not ports:
            print(f"[-] No valid ports in file: {port_file}")
            sys.exit(1)
        return ports
    except FileNotFoundError:
        print(f"[X] Port file not found: {port_file}")
        sys.exit(1)
    except Exception as e:
        print(f"[X] Error reading port file: {str(e)}")
        sys.exit(1)

def port_scan(target_ip, port, timeout=2.0, verbose=False):
    try:
        # Create new socket object for TCP connections
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set a timeout in case of long response time
        sock.settimeout(timeout)
        
        # Try to connect to IP and port
        res = sock.connect_ex((target_ip, port))
        
        # Close connection to prevent excess traffic
        sock.close()
        
        # Check to see if port open and connection successful
        if res == 0:
            print(f"[+] PORT {port} is open on {target_ip}")
            return True
        else:
            # Only show closed ports if -v / --verbose
            if verbose:
                print(f"[-] Port {port} is closed")
            return False
        
    except socket.error as e:
        print(f"[X] Error scanning {target_ip}:{port} - {str(e)}")
        sys.exit(1)
        
def host_lookup(target): 
    try:
        target_ip = socket.gethostbyname(target)
        print(f"[*] Target IP: {target_ip}")
        return target_ip
    # Catch getaddrinfo() error but let program continue to any subsequent targets
    except socket.gaierror:
        print("[X] Hostname could not be resolved")
        return None

def main():
    args=get_args()
    common_ports = [21, 22, 80, 443, 3306, 3389, 8080]
    timeout = args.timeout
    
    # Check to see if target exists (as string or txt file)
    if args.target:
        targets = [args.target]
    elif args.target_list:
        targets = load_targets(args.target_list)
    else:
        # Should be covered by required=True in target_group, but just in case
        print("[-] Please specify a target or list of targets. \n Use -h or --help for help.")
        sys.exit(1)

    for target in targets:        
        target_ip = host_lookup(target)
        
        if target_ip is None:
            print(f"[X] Skipping {target}. Failed hostname lookup.")
            continue
        
        print(f"\n Starting scan on {target} ({target_ip})")
        
        # if -p / --port
        if args.port is not None:
            ports = [args.port]
            
        # if -pR / --port-range
        elif args.port_range is not None:
            try:
                start, end = map(int, args.port_range.split('-'))
                ports = list(range(start, end + 1))
            except ValueError:
                print(f"[X] Invalid port range format: {args.port_range}")
                sys.exit(1)
                
        # if -pL / --port-list
        elif args.port_list is not None:
            try:
                ports = [int(port.strip()) for port in args.port_list.split(',')]

            except ValueError:
                print(f"[X] Invalid port list format: {args.port_list}")
                sys.exit(1)
                
        # if -pF / --port-file
        elif args.port_file is not None:
            ports = load_ports_from_file(args.port_file)
            
        # if -tp / --top-ports
        elif args.top_ports is not None:
            ports = common_ports[:min(args.top_ports, len(common_ports))]
            
        # if -a / --all-ports
        elif args.all_ports:
            ports = list(range(1, 65536))
            
        # if no port flag
        else:
            print("[*] No port option specified. \n Scanning common ports...")
            for port in common_ports:
                    port_scan(target_ip, port)
                    time.sleep(0.5)
                    
        # After ports are parsed and assigned as list
        for port in ports:
            port_scan(target_ip, port, timeout=timeout)
            time.sleep(0.5)
if __name__ == "__main__":
    main()
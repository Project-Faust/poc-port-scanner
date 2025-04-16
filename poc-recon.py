import socket # Network communication; socket operations
import sys # System-level operations like exiting program
import time # Time-based operations (timeout, interval)
import argparse # Parse CL args

def get_args():
    # Parse CL args/flags
    parser = argparse.ArgumentParser(description="Proof of Concept Recon Tool")
    
    # Define set of args/flags    
    # -t or --target flag to specify target IP or domain
    parser.add_argument("-t", "--target", dest="target", help="Target IP address or domain")
    
    # -p or --port flag to specify target port to scan
    parser.add_argument("-p", "--port", dest="port", type=int, help="Target port")
    
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
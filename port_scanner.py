import socket
import threading
from queue import Queue
import logging
import argparse
from tqdm import tqdm
import time
import csv

def is_valid_ip(host):
    """Validate if the provided host is a valid IP address or hostname."""
    try:
        socket.gethostbyname(host)
        return True
    except socket.gaierror:
        return False

def is_valid_port(port):
    """Validate if the port is a valid integer between 1 and 65535."""
    try:
        port = int(port)
        return 1 <= port <= 65535
    except ValueError:
        return False

def save_results(target, open_ports):
    """Save scan results to a CSV file."""
    with open(f"scan_results_{target}.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Port", "Service"])
        writer.writerows(open_ports)

def port_scanner(target_host, start_port, end_port, num_threads=100, verbose=False):
    """
    Scans a range of ports on a target host to identify open ports and their services.
    
    Args:
        target_host (str): The target hostname or IP address (e.g., 'localhost', '127.0.0.1').
        start_port (int): The starting port number (1–65535).
        end_port (int): The ending port number (1–65535).
        num_threads (int): Number of threads for concurrent scanning (default: 100).
        verbose (bool): Enable verbose output (default: False).
    
    Returns:
        list: A sorted list of tuples containing open ports and their associated services.
    """
    # Set up logging to a file
    logging.basicConfig(filename='port_scan.log', level=logging.INFO, 
                        format='%(asctime)s - %(message)s')
    logging.info(f"Starting scan on {target_host} ports {start_port}-{end_port}")
    
    # Validate inputs
    if not is_valid_ip(target_host):
        print(f"Error: '{target_host}' is not a valid host.")
        logging.error(f"Invalid host: {target_host}")
        return []
    if not (is_valid_port(start_port) and is_valid_port(end_port)):
        print("Error: Ports must be integers between 1 and 65535.")
        logging.error(f"Invalid port range: {start_port}-{end_port}")
        return []
    if start_port > end_port:
        print("Error: Start port must be less than or equal to end port.")
        logging.error(f"Invalid port range: start_port {start_port} > end_port {end_port}")
        return []

    open_ports = []
    port_queue = Queue()
    lock = threading.Lock()

    def scan_port():
        """Worker function to scan a single port and identify its service."""
        while True:
            port = port_queue.get()
            if verbose:
                print(f"Scanning port {port}...")
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_host, port))
                with lock:
                    if result == 0:
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = "unknown"
                        open_ports.append((port, service))
                        logging.info(f"Port {port} ({service}) open on {target_host}")
                sock.close()
            except socket.error:
                pass
            port_queue.task_done()

    # Fill the queue with ports to scan
    total_ports = end_port - start_port + 1
    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    # Start worker threads
    threads = []
    for _ in range(min(num_threads, total_ports)):
        t = threading.Thread(target=scan_port)
        t.daemon = True
        t.start()
        threads.append(t)

    # Show progress bar
    with tqdm(total=total_ports, desc="Scanning ports") as pbar:
        while not port_queue.empty():
            pbar.n = total_ports - port_queue.qsize()
            pbar.refresh()
            time.sleep(0.1)
        pbar.n = total_ports
        pbar.refresh()
    port_queue.join()

    logging.info(f"Scan completed on {target_host}")
    return sorted(open_ports)

def main():
    """Parse command-line arguments and run the port scanner."""
    parser = argparse.ArgumentParser(description="Simple Port Scanner")
    parser.add_argument("-t", "--target", required=True, 
                        help="Target host (e.g., 'localhost' or '127.0.0.1')")
    parser.add_argument("-s", "--start", type=int, required=True, 
                        help="Starting port")
    parser.add_argument("-e", "--end", type=int, required=True, 
                        help="Ending port")
    parser.add_argument("-n", "--threads", type=int, default=100, 
                        help="Number of threads (default: 100)")
    parser.add_argument("-v", "--verbose", action="store_true", 
                        help="Enable verbose output")
    args = parser.parse_args()

    open_ports_found = port_scanner(args.target, args.start, args.end, args.threads, args.verbose)
    if open_ports_found:
        print(f"Open ports on {args.target}:")
        for port, service in open_ports_found:
            print(f"Port {port}: {service}")
        save_results(args.target, open_ports_found)
        print(f"Results saved to scan_results_{args.target}.csv")
    else:
        print(f"No open ports found on {args.target} in the specified range.")

if __name__ == "__main__":
    main()
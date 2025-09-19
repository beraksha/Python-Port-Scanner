# Python-Port-Scanner
A Python-based port scanner to identify open ports and their services on a target host. Built to learn network programming and cybersecurity concepts.

## Features
- Scans ports using multithreading for speed.
- Detects services (e.g., HTTP, SSH) on open ports.
- Supports command-line arguments and verbose mode.
- Logs results to a file and saves output as CSV.
- Displays a progress bar during scanning.

## Installation
```bash
pip install -r requirements.txt
```

## Usage
Run the scanner with command-line arguments:
```bash
python port_scanner.py -t <target> -s <start_port> -e <end_port> [-n <threads>] [-v]
```

## Example
```bash
python port_scanner.py -t 127.0.0.1 -s 1 -e 1000
```
### Example Output:
```bash
Scanning ports: 100%|██████████| 1000/1000 [00:09<00:00, 111.11it/s]
Open ports on 127.0.0.1:
Port 135: epmap
Port 445: microsoft-ds
Port 902: unknown
Port 912: unknown
Results saved to scan_results_127.0.0.1.csv
```

## Options
- `-t, --target`: Target host (e.g., localhost, 127.0.0.1).
- `-s, --start`: Starting port number (1–65535).
- `-e, --end`: Ending port number (1–65535).
- `-n, --threads`: Number of threads (default: 100).
- `-v, --verbose`: Enable verbose output to show each port being scanned.

## Requirements
- Python 3.x
- `tqdm` (for progress bar)

### Install dependencies:
```
pip install tqdm
```

## Files
- `port_scanner.py`: Main script.
- `requirements.txt`: Lists dependencies (tqdm).
- `port_scan.log`: Logs scan start, open ports, and completion.
- `scan_results_<target>.csv`: CSV file with open ports and services.

## Example CSV Output
For the above scan, `scan_results_127.0.0.1.csv` contains:
```
Port,Service
135,epmap
445,microsoft-ds
902,unknown
912,unknown
```

## Disclaimer
Only scan hosts you have explicit permission to scan. Unauthorized port scanning may be illegal in many jurisdictions.

---

Built by [beraksha](https://github.com/beraksha) as part of a cybersecurity learning journey. Feedback and contributions welcome!

#Automated NMAP Syn + OS Fingerprint Network Scanner

`scanner.py` is a python-written CLI tool that performs a SYN scan and OS detection on an entered IP range using Nmap, then parses the results into both CSV and HTML reports.

## Prerequisites

- **Python 3.8+**
- **Nmap** installed and available in your system PATH for Windows. This can be verified with a new CLI instance and typing `nmap --version`. The script is designed to scan for a nmap path using Shutil and if not found will default to the program files default directory. https://nmap.org/download.html
- Python dependencies:
```bash
pip install -r requirements.txt

## Installation Steps

- Clone the repository:
git clone https://github.com/bhodge02/network-scanner.git
pip install -r requirements.txt

## Usage

python scanner.py --range <IP_RANGE> [--output <File_Name>]

--range (required): IP range to scan, e.g., 192.168.1.0/24
--output (optional, default scan_report): File name for the output file in both .csv and .html format.

## Example

python scanner.py --range 10.0.0.0/24 --output network_scan


import argparse
import nmap
import pandas as pd
import os
import shutil


NMAP_EXE = shutil.which("nmap")
if not NMAP_EXE:
    default = r"C:\Program Files\Nmap\nmap.ece"
    if os.path.isfile(default):
        NMAP_EXE = default
    else:
        print("Error: nmap.exe not found in system path. Please ensure NMAP is installed in your PATH.")
        exit(1)

def run_scan(ip_range):
    nm = nmap.PortScanner(nmap_search_path=[NMAP_EXE])
    print(f"Scanning {ip_range}...")
    nm.scan(hosts=ip_range, arguments='-sS -O')
    return nm


def parse_results(nm):
    records = []
    for host in nm.all_hosts():
        host_info = {
            "IP": host,
            "Hostname": nm[host].hostname(),
            "State": nm[host].state(),
            "OS": nm[host]['osmatch'][0]['name'] if nm[host].get('osmatch') else 'Unknown'            
        }
        
        ports = []
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                port_info = nm[host][proto][port]
                ports.append(f"{port}/{proto} ({port_info['state']})")
            host_info['Ports'] = ", ".join(ports)
            records.append(host_info)
    return records

def save_reports(records, base_name):
    df = pd.DataFrame(records)
    csv_file = f"{base_name}.csv"
    html_file = f"{base_name}.html"
    df.to_csv(csv_file, index=False)
    df.to_html(html_file, index=False)
    print(f"Reports saved: {csv_file}, {html_file}")

def main():
    parser = argparse.ArgumentParser(description='Automated SYN + OS Fingerprint Scanner')
    parser.add_argument('--range', required=True, help='IP range to scan e.g. 192.168.1.0/24')
    parser.add_argument('--output', default='scan_report', help='Base name for output files')
    args = parser.parse_args()

    nm = run_scan(args.range)
    records = parse_results(nm)
    save_reports(records, args.output)

if __name__ == '__main__':
    main()
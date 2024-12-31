import subprocess
import nmap
import subprocess

def scan_network_with_nmap(network_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=network_range, arguments='-sn')  # -sn for ping scan to find active devices
    devices = []
    
    for host in nm.all_hosts():
        device_name = nm[host].hostname() if nm[host].hostname() else "Unknown"
        devices.append((host, device_name, nm[host]['addresses'].get('mac', 'Unknown')))
    
    return devices

def scan_network_with_nbtscan(network_range):
    command = f'nbtscan {network_range}'
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    output = process.communicate()[0].decode('utf-8').splitlines()
    
    devices = []
    for line in output:
        if line.strip() and not line.startswith("Doing NBT name scan"):
            parts = line.split()
            if len(parts) >= 4:
                ip_address = parts[0]
                device_name = parts[1] if parts[1] != "<unknown>" else "Unknown"
                mac_address = parts[-1]
                devices.append((ip_address, device_name, mac_address))
    
    return devices




def get_network_interfaces():
    try:
        result = subprocess.run(['nmcli', 'device', 'status'], capture_output=True, text=True, check=True)
        output = result.stdout
        print("Network Interfaces and Status:")
        print(output)
    except Exception as e:
        print(f"Error detecting network interfaces: {e}")

get_network_interfaces()


def combine_scan_results(nmap_devices, nbtscan_devices):
    combined_results = {}
    
    # Add nmap results to the dictionary
    for ip, name, mac in nmap_devices:
        combined_results[ip] = {'Device Name': name, 'MAC Address': mac}
    
    # Update with nbtscan results
    for ip, name, mac in nbtscan_devices:
        if ip in combined_results:
            if combined_results[ip]['Device Name'] == "Unknown":
                combined_results[ip]['Device Name'] = name  # Update with nbtscan name if unknown
            combined_results[ip]['MAC Address'] = mac  # Update MAC address if nbtscan provides it
        else:
            combined_results[ip] = {'Device Name': name, 'MAC Address': mac}

    return combined_results

# Replace with your network range
#network_range = '192.168.0.0/24'
network_range = '192.168.1.0/24'

# Perform scans using bo
# th nmap and nbtscan
nmap_results = scan_network_with_nmap(network_range)
nbtscan_results = scan_network_with_nbtscan(network_range)

# Combine the results from both scans
final_results = combine_scan_results(nmap_results, nbtscan_results)

# Display the combined results
print("Combined Scan Results (IP, Device Name, MAC Address):")
for ip, details in final_results.items():
    print(f"IP Address: {ip} - Device Name: {details['Device Name']} - MAC Address: {details['MAC Address']}")

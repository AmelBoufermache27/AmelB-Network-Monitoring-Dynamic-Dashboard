import subprocess
from scapy.all import sniff, IP, TCP, UDP
import datetime
import time
import psutil
import socket
import statistics
import pandas as pd

# Target for testing latency, jitter, and packet loss
TARGET_IP = "8.8.8.8"
PING_COUNT = 5  # Number of pings to send for latency and jitter measurement

# Cache to store resolved hostnames
hostname_cache = {}

# Function to resolve IP to hostname with caching
def resolve_hostname(ip_address):
    if ip_address in hostname_cache:
        return hostname_cache[ip_address]

    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
    except (socket.herror, socket.gaierror):
        hostname = ip_address  # Fallback to IP if resolution fails

    hostname_cache[ip_address] = hostname
    return hostname

# Function to measure latency and packet loss
def measure_latency_packet_loss():
    latencies = []
    lost_packets = 0

    for _ in range(PING_COUNT):
        try:
            response = subprocess.run(
                ['ping', '-c', '1', '-W', '1', TARGET_IP],
                capture_output=True, text=True
            )
            if 'time=' in response.stdout:
                latency = float(response.stdout.split('time=')[1].split(' ')[0])
                latencies.append(latency)  # Store latency in ms
            else:
                lost_packets += 1  # Count lost packets if no response
        except Exception as e:
            print(f"Error during ping: {e}")
            lost_packets += 1  # Consider as lost packet

        time.sleep(0.2)  # Short delay between pings

    average_latency = sum(latencies) / len(latencies) if latencies else None
    packet_loss_percentage = (lost_packets / PING_COUNT) * 100
    return average_latency, packet_loss_percentage, latencies

# Function to calculate jitter based on latencies
def calculate_jitter(latencies):
    return statistics.stdev(latencies) if len(latencies) > 1 else 0.0

# Unified function to collect network metrics, including packet sniffing
def collect_network_data(duration, interface='wlp2s0'):
    network_data = []
    start_time = time.time()
    end_time = start_time + duration

    net_io_counters_initial = psutil.net_io_counters()
    previous_bytes_sent = net_io_counters_initial.bytes_sent
    previous_bytes_recv = net_io_counters_initial.bytes_recv

    while time.time() < end_time:
        # Calculate bandwidth, throughput, latency, jitter, and packet loss
        net_io_counters = psutil.net_io_counters()
        bytes_sent = net_io_counters.bytes_sent
        bytes_recv = net_io_counters.bytes_recv
        bandwidth_utilization = ((bytes_sent - previous_bytes_sent) + (bytes_recv - previous_bytes_recv)) * 8 / (1024 * 1024)  # Mbps
        throughput = (bytes_recv + bytes_sent) * 8 / (1024 * 1024)  # Total throughput in Mbps

        latency, packet_loss, latencies = measure_latency_packet_loss()
        jitter = calculate_jitter(latencies)

        previous_bytes_sent = bytes_sent
        previous_bytes_recv = bytes_recv

        # Sniff network packets using Scapy
        packets = sniff(iface=interface, timeout=1)

        # Process each captured packet
        for packet in packets:
            if IP in packet:
                # Extract packet details
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto

                # Resolve hostnames
                src_host = resolve_hostname(src_ip)
                dst_host = resolve_hostname(dst_ip)

                # Extract ports if the packet is TCP or UDP
                src_port = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else None)
                dst_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None)

                packet_size = len(packet)  # Packet size in bytes

                # Append all parameters into a single record
                network_data.append({
                    'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'bytes_sent': bytes_sent,
                    'bytes_recv': bytes_recv,
                    'latency (ms)': latency,
                    'jitter (ms)': jitter,
                    'packet_loss (%)': packet_loss,
                    'throughput (Mbps)': throughput,
                    'bandwidth_utilization (Mbps)': bandwidth_utilization,
                    'src_ip': src_ip,
                    'src_host': src_host,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_host': dst_host,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'packet_size': packet_size
                })

        time.sleep(1)  # Collect data every second

    return network_data

# Function to save collected data to a CSV file
def save_data_to_csv(data, filename):
    df = pd.DataFrame(data)
    df.to_csv(filename, index=False)
    print(f"Data saved to {filename}")

# Main function to initiate network monitoring
def main():
    interface = 'wlp2s0'  # Replace with your actual network interface
    data_collection_duration = 4000  # Duration in seconds for data collection

    print(f"Starting network monitoring on interface: {interface} for {data_collection_duration} seconds...")

    # Collect network data
    network_data = collect_network_data(data_collection_duration, interface)

    # Save collected data to CSV
    network_csv_file = f'network_data_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    save_data_to_csv(network_data, network_csv_file)

    print("Monitoring complete. Data saved.")
#hydra -l aimal -P /home/aimal/rockyou.txt 192.168.0.57 -t 4 -s <port_number> ssh

if __name__ == '__main__':
    main()

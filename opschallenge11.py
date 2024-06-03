from scapy.all import *


def scan_port(ip, port):
    # Create a SYN packet
    syn_packet = IP(dst=ip)/TCP(dport=port, flags='S')
    response = sr1(syn_packet, timeout=1, verbose=0)

    if response:
        # Check for SYN-ACK response
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            # Send a RST packet to close the open connection
            rst_packet = IP(dst=ip)/TCP(dport=port, flags='R')
            send(rst_packet, verbose=0)
            print(f"Port {port} is open.")
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
            print(f"Port {port} is closed.")
    else:
        print(f"Port {port} is filtered and silently dropped.")

if __name__ == "__main__":
    # Define the target IP
    ip = str("scanme.nmap.org")  # Replace with the target IP address

    # Define the port range
    start_port = 80
    end_port = 90

    # Scan each port in the specified range
    for port in range(start_port, end_port + 1):
        scan_port(ip, port)

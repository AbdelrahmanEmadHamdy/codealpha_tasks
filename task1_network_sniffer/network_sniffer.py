import socket
import struct

# Create a raw socket and bind it to the public interface
sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
sniffer.bind((" 192.168.1.30", 0))  # Replace with your local IP

# Include the IP headers in the capture
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Enable promiscuous mode (Windows-specific)
sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

try:
    print("Sniffing... Press Ctrl+C to stop.")
    while True:
        raw_data, addr = sniffer.recvfrom(65535)
        ip_header = raw_data[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        ttl = iph[5]
        protocol = iph[6]
        src_addr = socket.inet_ntoa(iph[8])
        dest_addr = socket.inet_ntoa(iph[9])

        print(f"IP Packet - From: {src_addr} To: {dest_addr} | Protocol: {protocol}")

except KeyboardInterrupt:
    # Turn off promiscuous mode
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    print("\nStopped sniffing.")
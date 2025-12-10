import socket
import struct
import textwrap
import sys


# --- HELPER FUNCTIONS ---

def get_mac_addr(bytes_addr):
    """
    Converts a byte array into a human-readable MAC address string (AA:BB:CC...).
    """
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


def get_ip_addr(bytes_addr):
    """
    Converts a byte array into a human-readable IP address string (192.168.1.1).
    """
    return '.'.join(map(str, bytes_addr))


def format_multi_line(prefix, string, size=80):
    """
    Formats binary data to be printable.
    Tries to decode as UTF-8; falls back to Hex dump if non-printable characters exist.
    """
    size -= len(prefix)
    if isinstance(string, bytes):
        try:
            # Try to print as clean ASCII text
            return prefix + string.decode('utf-8', errors='ignore')
        except:
            # Fallback to Hex representation
            string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
            if size % 2:
                size -= 1
            return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
    return prefix + str(string)


# --- PARSING FUNCTIONS ---

def ethernet_frame(data):
    """
    Unpacks the Ethernet Frame (Layer 2).
    Returns: Destination MAC, Source MAC, Protocol, Payload.
    """
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


def ipv4_packet(data):
    """
    Unpacks the IPv4 Header (Layer 3).
    Extracts Version, Header Length, TTL, Protocol, Source/Target IPs.
    """
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, get_ip_addr(src), get_ip_addr(target), data[header_length:]


def tcp_segment(data):
    """
    Unpacks the TCP Segment (Layer 4).
    Extracts Source Port, Destination Port, and Payload based on Data Offset.
    """
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dest_port, data[offset:]


# --- MAIN EXECUTION ---

def main():
    try:
        # Create a Raw Socket to listen for all protocols (ETH_P_ALL = 3)
        # Note: This requires root/sudo privileges on Linux.
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        print("[*] Sniffer Started! Listening for HTTP traffic (Port 80)...")

    except PermissionError:
        print("[!] Error: Root privileges required. Please run with 'sudo'.")
        sys.exit(1)

    while True:
        try:
            raw_data, addr = conn.recvfrom(65535)

            # Layer 2: Ethernet Frame
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

            # IPv4 Protocol ID: 8
            if eth_proto == 8:
                # Layer 3: IP Packet
                version, header_length, ttl, proto, src, target, data = ipv4_packet(data)

                # TCP Protocol ID: 6
                if proto == 6:
                    # Layer 4: TCP Segment
                    src_port, dest_port, data = tcp_segment(data)

                    # Filter: Capture only HTTP traffic (Port 80)
                    if src_port == 80 or dest_port == 80:
                        # Show only packets containing data payload
                        if len(data) > 0:
                            print(f'\n[HTTP Captured] {src}:{src_port} -> {target}:{dest_port}')
                            print(format_multi_line('\t ', data))

        except KeyboardInterrupt:
            print("\n[*] Sniffer stopped by user.")
            break


if __name__ == "__main__":
    main()
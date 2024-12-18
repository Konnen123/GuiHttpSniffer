import socket
import struct

FILTER_IP = None
FILTER_METHOD = None
MAX_PACKET_DATA = 65535

def http_sniffer():
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        print("HTTP Sniffer running.")

        while True:
            raw_data, addr = conn.recvfrom(MAX_PACKET_DATA)
            ip_header = parse_ip_header(raw_data[:20])
            if FILTER_IP and ip_header['src_ip'] != FILTER_IP:
                continue

    except KeyboardInterrupt:
        print("\nExiting HTTP Sniffer.")
    except Exception as e:
        print(f"Error: {e}")

def parse_ip_header(data):
    unpacked = struct.unpack('!BBHHHBBH4s4s', data)
    return {
        'version': unpacked[0] >> 4,
        'header_length': (unpacked[0] & 15) * 4,
        'ttl': unpacked[5],
        'protocol': unpacked[6],
        'src_ip': socket.inet_ntoa(unpacked[8]),
        'dest_ip': socket.inet_ntoa(unpacked[9]),
    }

if __name__ == '__main__':
    http_sniffer()

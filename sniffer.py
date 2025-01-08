import socket
import struct
import textwrap

MONITORED_PORTS = [80, 8080]
FILTER_TARGET_IP = None
FILTER_SOURCE_IP = None
FILTER_METHOD = None


def main():
    """
    Main function to start the HTTP sniffer.
    Captures raw packets from the network and processes IPv4 and TCP packets
    to identify HTTP data matching the specified filters.
    """
    connect = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    try:
        while True:
            raw_data, address = connect.recvfrom(65535)
            destination_mac, source_mac, ethernet_protocol, ethernet_data = ethernet_frame(raw_data)

            if ethernet_protocol == 8:  # IPv4
                version, header_length, ttl, protocol, source, target, ipv4_data = unpack_ipv4_packet(ethernet_data)

                if protocol == 6:  # TCP
                    tcp_segment = unpack_tcp_segment(ipv4_data)
                    source_port, destination_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment

                    if FILTER_TARGET_IP and FILTER_TARGET_IP != target:
                        continue

                    if FILTER_SOURCE_IP and FILTER_SOURCE_IP != source:
                        continue

                    data = decode_tcp_data(data)

                    if FILTER_METHOD and FILTER_METHOD not in data:
                        continue

                    if destination_port in MONITORED_PORTS and flag_ack == 1 and flag_psh == 1:
                        print('\nEthernet Frame:')
                        print(
                            f'Destination: {destination_mac}, Source: {source_mac}, Ethernet Protocol: {ethernet_protocol}')

                        print('IPv4 Packet:')
                        print(f'Version: {version}, Header Length: {header_length}, TTL: {ttl}')
                        print(f'Protocol: {protocol}, Source: {source}, Target: {target}')

                        print('TCP Segment:')
                        print(f'Source Port: {source_port}, Destination Port: {destination_port}')
                        print(f'Sequence: {sequence}, Acknowledgment: {acknowledgement}')
                        print('Flags:')
                        print(
                            f'URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}')
                        print('Data:')
                        print(format_multi_line('\t', data))
                        print('#############################')

    except KeyboardInterrupt:
        print("\nExiting HTTP Sniffer.")
    except Exception as e:
        print(f"Error: {e}")


def ethernet_frame(data):
    """
    Parses an Ethernet frame.

    Args:
        data (bytes): The raw data of the Ethernet frame.

    Returns:
        tuple: Destination MAC address, source MAC address, protocol type, and the remaining data.
    """
    destination_mac, source_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(destination_mac), get_mac_address(source_mac), socket.htons(protocol), data[14:]


def get_mac_address(bytes_address):
    """
    Converts a MAC address from bytes to a human-readable string.

    Args:
        bytes_address (bytes): The MAC address in byte format.

    Returns:
        str: The MAC address in colon-separated hexadecimal format.
    """
    return ':'.join(f'{byte:02x}' for byte in bytes_address).upper()


def unpack_ipv4_packet(data):
    """
    Unpacks an IPv4 packet.

    Args:
        data (bytes): The raw data of the IPv4 packet.

    Returns:
        tuple: Version, header length, TTL, protocol, source IP, destination IP, and remaining data.
    """
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, protocol, source, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, protocol, ipv4(source), ipv4(target), data[header_length:]


def unpack_tcp_segment(data):
    """
    Unpacks a TCP segment.

    Args:
        data (bytes): The raw data of the TCP segment.

    Returns:
        tuple: Source port, destination port, sequence number, acknowledgment number, flags, and remaining data.
    """
    (source_port, destination_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H',
                                                                                                      data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1

    return source_port, destination_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[
                                                                                                                                 offset:]


def decode_tcp_data(data):
    """
    Decodes TCP segment data as a UTF-8 string.

    Args:
        data (bytes): The raw TCP data.

    Returns:
        str: The decoded string, or an empty string if decoding fails.
    """
    try:
        return data.decode('utf-8', errors='ignore')
    except UnicodeDecodeError:
        return ''


def ipv4(address):
    """
    Converts an IPv4 address from bytes to a human-readable string.

    Args:
        address (bytes): The IPv4 address in byte format.

    Returns:
        str: The IPv4 address in dot-decimal format.
    """
    return '.'.join(map(str, address))


def format_multi_line(prefix, string, size=80):
    """
    Formats a string to wrap over multiple lines with a prefix.

    Args:
        prefix (str): The string to prefix each line with.
        string (str): The string to format.
        size (int, optional): The maximum line width. Defaults to 80.

    Returns:
        str: The formatted multi-line string.
    """
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(f'\\{byte:02x}' for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


if __name__ == '__main__':
    main()

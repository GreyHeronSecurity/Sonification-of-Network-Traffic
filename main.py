import pyshark
import pandas as pd
import time
import ipaddress
import random
import socket
import argparse
import os
import matplotlib.pyplot as plt

# UDP IP and ports for socket variables to message PureData.
udp_ip = "127.0.0.1"  # PureData IP (localhost)
udp_ports = 5000      # Random Port
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Addresses used to identify internal or external direction of traffic in the is_internal() function.
internal_networks = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16")
]


def map_to_range(value, old_min, old_max, new_min, new_max):
    """
            map_to_range() maps a numeric value from one range to another using linear scaling.

            Parameters: value (float): The value to be converted from the old range to the new range.
                        old_min (float): The minimum value of the original range.
                        old_max (float): The maximum value of the original range.
                        new_min (float): The minimum value of the new target range.
                        new_max (float): The maximum value of the new target range.
            Returns:    float: The value scaled proportionally to the new range.

            Example:    map_to_range(5, 0, 10, 0, 100)  # Returns 50.0
            """
    return new_min + ((value - old_min) * (new_max - new_min) / (old_max - old_min))


def map_to_range_inverted(value, old_min, old_max, new_min, new_max):
    """
            map_to_range_inverted() maps a numeric value from one range to another using linear scaling,
            but inverts the direction of the mapping.

            Parameters: value (float): The value to be mapped from the old range.
                        old_min (float): The minimum value of the original range.
                        old_max (float): The maximum value of the original range.
                        new_min (float): The minimum value of the new range.
                        new_max (float): The maximum value of the new range.
            Returns:    float: The value scaled to the new range, but with inverted direction.
            Example:    # Original range: 0 to 10, new range: 0 to 100
                        # Normal mapping: value 2 → 20
                        # Inverted mapping: value 2 → 80
                        map_to_range_inverted(2, 0, 10, 0, 100)  # Returns 80.0
            """
    return new_max - ((value - old_min) * (new_max - new_min) / (old_max - old_min))


def is_internal(ip):
    """
            is_internal() function checks if a given IPv4 address belongs to the set of internal networks.

            Parameters: ip (str): A string representation of an IPv4 address (e.g., "192.168.1.10").
            Returns:    True if the IP is valid and belongs to one of the internal networks;
                        False if the IP is invalid, not IPv4, or not in any internal network.
            """
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        return any(ip_obj in network for network in internal_networks)
    except ValueError:
        return False  # in case it's an IPv6 or invalid IP


def get_packet_direction(src_ip, dst_ip):
    """
            get_packet_direction() determines the direction of a network packet based on
            source and destination IP addresses.

            Parameters: src_ip (str): The source IP address (e.g., "192.168.1.100").
                        dst_ip (str): The destination IP address (e.g., "192.168.1.101").
            Returns:    str: A two-character string for the direction:
                        1. "11": internal to internal
                        2. "01": internal to external
                        3. "10": external to internal
                        None if either IP is invalid or not supported by `is_internal()`.
            Example:    get_packet_direction("192.168.1.100","192.168.1.101")  # "11"
            Example:    get_packet_direction("192.168.1.100","8.8.8.8")  # "01"
            Example:    get_packet_direction("8.8.8.8","192.168.1.101")  # "10"
            """
    src_internal = is_internal(src_ip)
    dst_internal = is_internal(dst_ip)

    if src_internal and dst_internal:
        return "11"
    elif src_internal and not dst_internal:
        return "01"
    elif not src_internal and dst_internal:
        return "10"
    else:
        return


def plot_graph(x, y, x_label="X-axis", y_label="Y-axis", title="Plot"):
    """
            plot_graph() generates and displays a simple line plot.

            Parameters: x_data (list): The data for the x-axis.
                        y_data (list): The data for the y-axis.
                        x_label (str): The label for the x-axis.
                        y_label (str): The label for the y-axis.
                        title (str): The title of the plot
            Returns:    Graph in external window.
    """
    plt.plot(x, y, label=title, color='blue')
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.title(title)
    plt.grid(True)
    plt.legend()
    plt.show()


def process_pcap(file_path, rolling_window_size=50, output_csv=None):
    """
            process_pcap() processes a PCAP file to extract network statistics, identify potential anomalies,
            and optionally save rolling statistics to a CSV file.

            Parameters: file_path (str): The path to the PCAP file to be processed.
                        rolling_window_size (int, optional): The size of the rolling window used for calculating
                        statistics. Defaults to 50 packets.
                        output_csv (str, optional): The path to a CSV file where the rolling statistics will be saved.
                        If None, the statistics are not saved to a file. Defaults to None.
            Returns:    None: Messages sent to PureData patch throughout PCAP file processing.
        """
    cap = pyshark.FileCapture(file_path, keep_packets=False)

    df = pd.DataFrame(columns=["timestamp", "length", "is_tcp", "is_syn", "is_syn_ack"])
    rolling_stats = {
        'timestamp': [],
        'pps': [],
        'length': [],
        'tcp_pps': [],
        'syn_pps': [],
        'syn_to_synack_ratio': [],
    }

    excluded = 1
    rando = 1

    time_length = []

    ping_to_brd_ip = set()

    previous_time = None
    start_time = time.time()

    syn_flood_src_ports = set()

    for i, pkt in enumerate(cap):
        try:
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            direction = get_packet_direction(src_ip, dst_ip)

            pkt_time = float(pkt.sniff_timestamp)
            pkt_len = int(pkt.length)
            is_tcp = hasattr(pkt, 'tcp')
            is_syn = False
            is_syn_ack = False

            if is_tcp:
                tcp_flags = int(pkt.tcp.flags, 16)
                is_syn = bool(tcp_flags & 0x02) and not bool(tcp_flags & 0x10)  # SYN only
                if is_syn:
                    try:
                        src_port = int(pkt.tcp.srcport)
                        syn_flood_src_ports.add(src_port)
                    except AttributeError:
                        pass  # Source port might not be available on malformed TCP packet

                is_syn_ack = bool(tcp_flags & 0x02) and bool(tcp_flags & 0x10)  # SYN + ACK

            # Check for ICMP Echo Request to broadcast address
            if hasattr(pkt, 'icmp'):
                icmp_type = int(pkt.icmp.type)

                if icmp_type == 8:  # Echo Request
                    if dst_ip.endswith('.255') or dst_ip == '255.255.255.255':
                        ping_to_brd_ip.add(src_ip)
                        heron_message = "i12"
                        sock.sendto(heron_message.encode(), (udp_ip, udp_ports))
                        print(f"TTL: {pkt.ip.ttl}")
                        print("BRD")
                        print(ping_to_brd_ip)
                elif icmp_type == 0:  # Echo Reply
                    if dst_ip in ping_to_brd_ip:
                        print("BRD22")
                        heron_message = "i23"
                        sock.sendto(heron_message.encode(), (udp_ip, udp_ports))

            if is_tcp:
                retransmission_types = {
                    'analysis_retransmission': 'Regular Retransmission',
                    'analysis_fast_retransmission': 'Fast Retransmission',
                    'analysis_spurious_retransmission': 'Spurious Retransmission'
                }

                for attr, label in retransmission_types.items():
                    if hasattr(pkt.tcp, attr):

                        while rando == excluded:
                            rando = random.randint(1, 3)

                        retry_message = f"e{rando}"
                        sock.sendto(retry_message.encode(), (udp_ip, udp_ports))
                        excluded = rando
                        # print(f"RETRY TYPE: {rando}{rando1}")

        except AttributeError as e:

            print(f"AttributeError: {e} - Skipping packet with missing attribute.")

            continue  # Skip packets with missing fields

        except Exception as e:

            print(f"Unexpected error: {e}")

            continue  # Skip any unexpected errors

        if previous_time is not None:
            delay = pkt_time - previous_time
            if delay <= 0:
                time.sleep(0)
            else:
                time.sleep(delay)
        previous_time = pkt_time

        df.loc[i] = [pkt_time, pkt_len, is_tcp, is_syn, is_syn_ack]

        # Rolling calculation
        if len(df) >= rolling_window_size:
            rolling_df = df[-rolling_window_size:]
        else:
            rolling_df = df

        time_span = rolling_df['timestamp'].iloc[-1] - rolling_df['timestamp'].iloc[0] + 1e-5
        pps = len(rolling_df) / time_span
        avg_len = rolling_df['length'].mean()
        tcp_pps = rolling_df['is_tcp'].sum() / time_span
        syn_pps = rolling_df['is_syn'].sum() / time_span

        syn_count = rolling_df['is_syn'].sum()
        syn_ack_count = rolling_df['is_syn_ack'].sum()
        syn_ratio = syn_count / syn_ack_count if syn_ack_count > 0 else 0

        # print(syn_count)
        # print(syn_ack_count)

        rolling_stats['timestamp'].append(pkt_time)
        rolling_stats['pps'].append(pps)
        rolling_stats['length'].append(avg_len)
        rolling_stats['tcp_pps'].append(tcp_pps)
        rolling_stats['syn_pps'].append(syn_pps)
        rolling_stats['syn_to_synack_ratio'].append(syn_ratio)

        # print(syn_count)
        # print(syn_ack_count)

        time_length.append(time.time() - start_time)
        # time_length.append(pkt_time - 1744893613.163825)
        port_count_two = len(syn_flood_src_ports)

        mapped_pps = map_to_range(pps, 0, 1000, 0.01, 0.3)
        mapped_len = map_to_range(avg_len, 0, 900, 0.01, 0.4)
        mapped_tcp = map_to_range(tcp_pps, 0, 150, 0, 1)
        mapped_syn = map_to_range(syn_pps, 0, 150, 0, 2)
        mapped_syn_ratio = map_to_range(syn_ratio, 0, 5, 0.02, 1.2)
        mapped_woodpecker = map_to_range_inverted(port_count_two, 0, 2500, 0, 1)
        mapped_woodpecker_amp = map_to_range(port_count_two, 0, 2500, 0.2, 1)

        # A - Total PPS, Direction, Average Packet-Length
        # print(pps)
        message = f"a{mapped_pps:.3f}{direction}{mapped_len:.3f}"
        sock.sendto(message.encode(), (udp_ip, udp_ports))

        # B - TCP PPS
        tcp_message = f"b{mapped_tcp:.3f}"
        sock.sendto(tcp_message.encode(), (udp_ip, udp_ports))

        # C - SYN PPS
        syn_message = f"c{mapped_syn:.3f}"
        sock.sendto(syn_message.encode(), (udp_ip, udp_ports))

        # D - SYN/ACK Ratio

        ratio_message = f"d{mapped_syn_ratio:.3f}"
        print(syn_ratio)
        print(ratio_message)

        sock.sendto(ratio_message.encode(), (udp_ip, udp_ports))

        # E - SYN Flood Port Count
        message_woodpecker = f"h{mapped_woodpecker}j{mapped_woodpecker_amp}"
        sock.sendto(message_woodpecker.encode(), (udp_ip, udp_ports))


    elapsed_time = time.time() - start_time
    print(f"{elapsed_time}")
    cap.close()

    rolling_stats['timestamp'] = rolling_stats['timestamp'][5:]
    rolling_stats['pps'] = rolling_stats['pps'][5:]
    rolling_stats['length'] = rolling_stats['length'][5:]
    rolling_stats['tcp_pps'] = rolling_stats['tcp_pps'][5:]
    rolling_stats['syn_pps'] = rolling_stats['syn_pps'][5:]
    rolling_stats['syn_to_synack_ratio'] = rolling_stats['syn_to_synack_ratio'][5:]

    time_length = time_length[5:]

    plot_graph(time_length, rolling_stats['pps'], x_label="Time (seconds)",
               y_label="Rolling Average Total PPS", title="Rolling Stats - Total PPS")
    plot_graph(time_length, rolling_stats['length'], x_label="Time (seconds)",
               y_label="Rolling Average Packet-Length", title="Rolling Stats - Packet-Length")
    plot_graph(time_length, rolling_stats['tcp_pps'], x_label="Time (seconds)",
               y_label="Rolling Average TCP PPS", title="Rolling Stats - TCP PPS")
    plot_graph(time_length, rolling_stats['syn_pps'], x_label="Time (seconds)",
               y_label="Rolling Average SYN PPS", title="Rolling Stats - SYN PPS")
    plot_graph(time_length, rolling_stats['syn_to_synack_ratio'], x_label="Time (seconds)",
               y_label="Rolling SYN - SYN/ACK Ratio", title="Rolling Stats - SYN - SYN/ACK Ratio")

    plt.figure(figsize=(15, 8))
    plt.plot(rolling_stats['timestamp'], rolling_stats['pps'], label='Avg PPS')
    plt.plot(rolling_stats['timestamp'], rolling_stats['tcp_pps'], label='TCP PPS')
    plt.plot(rolling_stats['timestamp'], rolling_stats['syn_pps'], label='SYN PPS')
    plt.xlabel("Time (seconds)")
    plt.ylabel("Rolling Stats - Total, TCP, SYN PPS")
    plt.title("Network Metrics Over Time")
    plt.legend()
    plt.grid(True)
    plt.show()

    # Export to CSV if requested
    if output_csv:
        stats_df = pd.DataFrame(rolling_stats)
        stats_df.to_csv(output_csv, index=False)
        print(f"Rolling stats written to: {output_csv}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Real-time pcap simulator with rolling averages.")
    parser.add_argument("pcap_file", help="Path to the .pcap file")
    parser.add_argument("--window", type=int, default=50, help="Rolling window size (default: 50 packets)")
    parser.add_argument("--output", type=str, help="Optional path to CSV output file")

    args = parser.parse_args()

    if not os.path.exists(args.pcap_file):
        print(f"File not found: {args.pcap_file}")
        exit(1)

    process_pcap(args.pcap_file, rolling_window_size=args.window, output_csv=args.output)

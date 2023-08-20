import dpkt
import datetime
import json
import os
import socket
import networkx as nx
import matplotlib.pyplot as plt

def calculate_throughput(pcap_file, interval):
    # Open the pcap file
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        # Initialize variables
        start_time = None
        end_time = None
        total_bytes = 0
        interval_start_time = None
        interval_bytes = 0

        # Iterate over each packet in the pcap file
        for ts, buf in pcap:
            # If this is the first packet, set the start time
            if start_time is None:
                start_time = ts
                interval_start_time = ts

            # Update the end time and total bytes
            end_time = ts
            total_bytes += len(buf)

            # If the current time minus the interval start time is greater than or equal to the interval
            if ts - interval_start_time >= interval:
                # Calculate the throughput for the interval
                interval_throughput = (interval_bytes * 8) / (1024 * 1024)  # Megabits per second
                # Print the throughput
                print(f"The throughput from {datetime.datetime.fromtimestamp(interval_start_time)} to {datetime.datetime.fromtimestamp(ts)} is {interval_throughput} Megabits per {interval} second(s).")
                # Reset the interval start time and interval bytes
                interval_start_time = ts
                interval_bytes = 0
            else:
                # If the current time minus the interval start time is less than the interval, add the bytes of the current packet to the interval bytes
                interval_bytes += len(buf)

        # Calculate the total time delta and the average throughput
        time_delta = end_time - start_time
        throughput = (total_bytes * 8) / (1024 * 1024) / time_delta  # Megabits per second

        # Return the throughput, start time, end time, and duration
        return throughput, start_time, end_time, time_delta

def parse_pcap_to_json(pcap_file):
    flows = {}
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for _, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                bytes_transferred = len(buf)

                # Check if the IP packet contains TCP/UDP to get the ports
                if isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                    transport = ip.data
                    src_port = transport.sport
                    dst_port = transport.dport
                else:
                    src_port = None
                    dst_port = None

                # Use a tuple (src_ip, dst_ip, src_port, dst_port) as the key for the flows dictionary
                flow_key = (src_ip, dst_ip, src_port, dst_port)
                if flow_key in flows:
                    flows[flow_key]["bytes_transferred"] += bytes_transferred
                else:
                    flows[flow_key] = {
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "source_port": src_port,
                        "destination_port": dst_port,
                        "bytes_transferred": bytes_transferred
                    }

    return {"flows": list(flows.values())}

def visualize_network_flows(filename):
    # Load the data from the JSON file
    with open(filename, 'r') as file:
        data = json.load(file)

    # Now the 'data' variable contains the data from the JSON file
    print(data)  # This will print the loaded data for verification

    # Create a directed graph
    G = nx.DiGraph()

    # Add nodes and edges based on the flows
    for flow in data["flows"]:
        src_ip = flow["source_ip"]
        dst_ip = flow["destination_ip"]
        bytes_transferred = flow["bytes_transferred"]

        # Add nodes
        G.add_node(src_ip)
        G.add_node(dst_ip)

        # Add or update edge
        if G.has_edge(src_ip, dst_ip):
            G[src_ip][dst_ip]["weight"] += bytes_transferred
        else:
            G.add_edge(src_ip, dst_ip, weight=bytes_transferred)

    # Draw the graph
    pos = nx.spring_layout(G)
    edges = G.edges(data=True)
    nx.draw(G, pos, with_labels=True, node_size=2000, node_color="skyblue", font_size=10, width=1)
    edge_labels = {(u, v): f"{d['weight']} bytes" for u, v, d in edges}
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=8)

    # Display the plot
    plt.title("Network Flows Visualization")
    plt.show()

def main():
    while True:
        # Present menu to the user
        print("\nSelect an option:")
        print("1. Calculate throughput from a pcap file.")
        print("2. Convert a pcap file to JSON.")
        print("3. Visualize network flows from a JSON file.")
        print("4. Exit.")
        choice = input("Enter the number of your choice: ")

        if choice == "1":
            pcap_file = input("Enter the path of the pcap file: ")
            interval = int(input("Enter the time interval in seconds: "))
            throughput, start_time, end_time, duration = calculate_throughput(pcap_file, interval)
            print(f"The average throughput of data in this file is {throughput} Megabits per second.")
            print(f"The packet capture started at {datetime.datetime.fromtimestamp(start_time)} and ended at {datetime.datetime.fromtimestamp(end_time)}.")
            print(f"The total duration of the packet capture was {duration} seconds.")

        elif choice == "2":
            pcap_file = input("Enter the path of the pcap file: ")
            data = parse_pcap_to_json(pcap_file)
            json_file = os.path.splitext(pcap_file)[0] + ".json"
            with open(json_file, 'w') as f:
                json.dump(data, f, indent=4)
            print(f"Data saved to {json_file}")

        elif choice == "3":
            filename = input("Enter the path of the JSON file: ")
            visualize_network_flows(filename)

        elif choice == "4":
            print("Goodbye!")
            break

        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()

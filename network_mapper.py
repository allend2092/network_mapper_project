import subprocess
import re
import networkx as nx
import matplotlib.pyplot as plt


def run_traceroute(target):
    # Define the command and the output file
    command = ["traceroute", "-I", "-n", target]
    output_file = "/home/daryl/PycharmProjects/network_mapper/traceroute1.txt"
    # Open the file in write mode
    with open(output_file, "w") as outfile:
        # Execute the command and direct the output to the file
        subprocess.run(command, stdout=outfile)


def parse_traceroute_file(file_path):
    # Regular expression to match IP addresses
    regex = re.compile(r"((?:[0-9]{1,3}\.){3}[0-9]{1,3})")

    edges = []
    last_ip = None
    # Open the file and parse each line
    with open(file_path, "r") as file:
        for line in file:
            # Find all IP addresses in the line
            ip_addresses = regex.findall(line)
            for ip in ip_addresses:
                # Skip if this is the first IP address found
                if last_ip is None:
                    last_ip = ip
                    continue
                # Add an edge for each consecutive pair of addresses
                edges.append((last_ip, ip))
                last_ip = ip
    return edges


def create_network_graph(edges):
    G = nx.DiGraph()  # create a directed graph
    for i in range(len(edges) - 1):
        G.add_edge(edges[i][1], edges[i + 1][1])
    return G


def draw_network_graph(G):
    pos = nx.spectral_layout(G)  # Change this line to use a different layout
    nx.draw(G, pos, with_labels=True)
    plt.show()


# traceroute output
run_traceroute("8.8.8.8")
edges = parse_traceroute_file("/home/daryl/PycharmProjects/network_mapper/traceroute1.txt")
G = create_network_graph(edges)
draw_network_graph(G)


# Import the necessary libraries
import pyshark
import pandas as pd

# Specify the paths to the PCAP files
pcap_files = ["/Users/taniajaswal/Wireshark/Wireshark_at_night_Dec11.pcap",
              "/Users/taniajaswal/Wireshark/Wireshark_at_morning_20min_Oct6.pcap",
              "/Users/taniajaswal/Wireshark/Wireshark_at_afternoon_20min_Oct18.pcap"]

# Create a list to store the dataframes
dfs = []

# Analyze each PCAP file and store the data in separate dataframes
for pcap_file in pcap_files:
    # Open the PCAP file for packet capture
    cap = pyshark.FileCapture(pcap_file)
    packet_data = []

    # Initialize variables for time and data size
    start_time = None
    end_time = None
    total_data_size = 0

    # Create dictionaries to track conversation counts and data size for top talkers
    conversation_counts = {}
    conversation_data_size = {}

    # Iterate through each packet in the PCAP file
    for packet in cap:
        # Extract information from the packet and store it in a dictionary
        packet_info = {
            "Packet Number": packet.number,
            "Timestamp": packet.sniff_time,
            "Source IP": packet.ip.src if 'IP' in packet else "",
            "Destination IP": packet.ip.dst if 'IP' in packet else "",
            "Source Port": packet.tcp.srcport if 'TCP' in packet else "",
            "Destination Port": packet.tcp.dstport if 'TCP' in packet else "",
            "Protocol": packet.transport_layer,
            "Packet Length": packet.length if 'length' in packet else ""
        }
        packet_data.append(packet_info)

        # Update time and data size information
        if start_time is None:
            start_time = packet.sniff_time
        end_time = packet.sniff_time
        total_data_size += int(packet.length)

        # Track conversation counts and data size for top talkers
        conversation_key = f"{packet_info['Source IP']}:{packet_info['Source Port']} - {packet_info['Destination IP']}:{packet_info['Destination Port']}"
        if conversation_key in conversation_counts:
            conversation_counts[conversation_key] += 1
            conversation_data_size[conversation_key] += int(packet.length)
        else:
            conversation_counts[conversation_key] = 1
            conversation_data_size[conversation_key] = int(packet.length)

    # Create a DataFrame from the collected packet data and store it in the 'dfs' list
    df = pd.DataFrame(packet_data)
    dfs.append(df)

    # Close the PCAP file
    cap.close()

    # Calculate the duration and total data size for this PCAP file
    duration = end_time - start_time
    duration_in_seconds = duration.total_seconds()

    # Print the analysis results for each PCAP file
    print(f"\nAnalysis for {pcap_file}:\n")
    print(f"Duration: {duration_in_seconds} seconds")
    print(f"Total Data Size: {total_data_size} bytes")

    # Analyze top talkers for this PCAP file
    print("Top Talkers:")
    sorted_conversation_counts = sorted(conversation_counts.items(), key=lambda x: x[1], reverse=True)
    for conversation, count in sorted_conversation_counts[:5]:  # Show the top 5 talkers
        data_size = conversation_data_size[conversation]
        print(f"Conversation: {conversation}, Packets: {count}, Data Size: {data_size} bytes")

# Packet statistics
stats = []

# Calculate various statistics for each PCAP file and store them in a list of dictionaries
for i, df in enumerate(dfs):
    stats.append({
        "PCAP File": pcap_files[i],
        "Total Packets": len(df),
        "Total Unique Source IPs": len(df["Source IP"].unique()),
        "Total Unique Destination IPs": len(df["Destination IP"].unique()),
        "Total Unique Protocols": len(df["Protocol"].unique())
    })

# Common protocols
common_protocols = []

# Compare protocols between different PCAP files
for i, df1 in enumerate(dfs):
    for j, df2 in enumerate(dfs):
        if i != j:
            common_protocols_df1 = df1["Protocol"].dropna().unique()
            common_protocols_df2 = df2["Protocol"].dropna().unique()
            common_protocols_set = set(common_protocols_df1) & set(common_protocols_df2)
            common_protocols_list = list(common_protocols_set)
            common_protocols_str = ", ".join(common_protocols_list)
            common_protocols.append({
                "PCAP File 1": pcap_files[i],
                "PCAP File 2": pcap_files[j],
                "Common Protocols": common_protocols_str
            })

# Source-Destination pairs
source_dest_pairs = []

# Count common source-destination pairs between different PCAP files
for i, df1 in enumerate(dfs):
    for j, df2 in enumerate(dfs):
        if i != j:
            common_pairs = df1.groupby(["Source IP", "Destination IP"]).size().reset_index(name="Count")
            source_dest_pairs.append({
                "PCAP File 1": pcap_files[i],
                "PCAP File 2": pcap_files[j],
                "Common Source-Destination Pairs": len(common_pairs)
            })

# Print the analysis results
print("\nAnalysis Results:")
for result in stats:
    print(result)

print("\nCommon Protocols:")
for result in common_protocols:
    print(result)

print("\nSource-Destination Pairs:")
for result in source_dest_pairs:
    print(result)

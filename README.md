# Wireshark PCAP Analysis

This repository contains a Python script to analyze PCAP (Packet Capture) files using the `pyshark` and `pandas` libraries. The script extracts key information from packets and provides insights into network traffic.

## Purpose and Goals

The goal of this script is to provide a detailed analysis of network traffic captured in PCAP files. By examining these files, we aim to:

- Understand the volume and duration of network traffic.
- Identify the most active communicators (top talkers) in the network.
- Compare network protocols and communication patterns across different time periods.
- Gain insights into the distribution of source and destination IP addresses.
- Highlight common protocols and source-destination pairs between different PCAP files.

## Requirements

- Python 3.x
- pyshark
- pandas

## Installation

1. Install Python 3.x from [python.org](https://www.python.org/downloads/).
2. Install the required libraries:

    ```sh
    pip install pyshark pandas
    ```

## Usage

1. **Set the PCAP file paths:**

    Update the `pcap_files` list with the paths to your PCAP files.

    ```python
    pcap_files = [
        "/path/to/pcap_file1.pcap",
        "/path/to/pcap_file2.pcap",
        "/path/to/pcap_file3.pcap"
    ]
    ```

2. **Run the script:**

    ```sh
    python analyze_pcap.py
    ```

## Script Details

The script performs the following steps:

1. **Import Libraries:**

    ```python
    import pyshark
    import pandas as pd
    ```

2. **Specify PCAP Files:**

    Define the paths to your PCAP files.

    ```python
    pcap_files = [
        "/Users/taniajaswal/Wireshark/Wireshark_at_night_Dec11.pcap",
        "/Users/taniajaswal/Wireshark/Wireshark_at_morning_20min_Oct6.pcap",
        "/Users/taniajaswal/Wireshark/Wireshark_at_afternoon_20min_Oct18.pcap"
    ]
    ```

3. **Analyze Each PCAP File:**

    - Open the PCAP file using `pyshark`.
    - Extract packet details (packet number, timestamp, source IP, destination IP, source port, destination port, protocol, and packet length).
    - Track the duration and total data size.
    - Identify top talkers by tracking conversation counts and data sizes.

4. **Store Data in DataFrames:**

    Collected data is stored in `pandas` DataFrames for further analysis.

5. **Print Analysis Results:**

    For each PCAP file, the script prints:
    - Duration of the capture
    - Total data size
    - Top talkers (conversations with the most packets and data)

6. **Calculate Statistics:**

    The script calculates and prints:
    - Total packets
    - Unique source IPs
    - Unique destination IPs
    - Unique protocols

7. **Compare Protocols and Source-Destination Pairs:**

    The script compares:
    - Common protocols between different PCAP files
    - Common source-destination pairs between different PCAP files

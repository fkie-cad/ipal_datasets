#!/usr/bin/env python3
import json
import gzip
from scapy.all import IP, TCP, Ether, wrpcap, Raw

"""
    0   MB frame (received by master or slave)
    1,2 Cagegory and specific attack
    3,4 Source and Destination of the MB frame
        - 1 master sent packet
        - 2 MITM sent packet
        - 3 slave sent packet
    5   Timestamp

"""
master_ip = "192.168.1.1"
master_port = 60000
slave_ip = "192.168.1.2"
slave_port = 502

packet_counter = 0
seq_master = 0
seq_slave = 0

# Create required files
open("ipal/IanDataset.pcap", "w").close()
attacks = []

# Create packets
with gzip.open("raw/IanRawDataset.txt.gz", "r") as f:
    for line in f.readlines():
        line = line.decode().strip("\n").split(",")

        line[0] = bytes.fromhex(line[0])
        data = b"\x11\x22"  # Some static transaction ID
        data += b"\x00\x00"  # Protocol ID (always 0000)
        data += (len(line[0]) - 2).to_bytes(2, "big")  # Data length
        data += line[0][:-2]  # MB frame - checksum

        if (line[3] == "1" and line[4] == "3") or (
            line[3] == "2" and line[4] == "3"
        ):  # Master/MITM -> Slave
            l3 = IP(src=master_ip, dst=slave_ip)
            l4 = TCP(sport=master_port, dport=slave_port, seq=seq_master, flags=24)
            seq_master += len(data)

        elif (line[3] == "3" and line[4] == "1") or (
            line[3] == "2" and line[4] == "1"
        ):  # Slave/MITM -> Master
            l3 = IP(src=slave_ip, dst=master_ip)
            l4 = TCP(sport=slave_port, dport=master_port, seq=seq_slave, flags=24)
            seq_slave += len(data)
        else:
            assert False

        l2 = Ether()
        l5 = Raw(load=data)
        pkt = l2 / l3 / l4 / l5
        pkt.time = float(line[5])

        wrpcap("ipal/IanDataset.pcap", pkt, append=True)

        # Generate attack dataset
        if line[2] != "0":
            attacks.append(
                {
                    "id": line[2],
                    "attack_point": [],
                    "description": "",
                    "ipalid": packet_counter,
                }
            )

        packet_counter += 1

# Write attack file
with open("attacks.json", "w") as f:
    f.write(json.dumps(attacks, indent=4) + "\n")

#!/usr/bin/env python3
import gzip
import json

from scapy.all import IP, TCP, Ether, Raw, wrpcap

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
attacks = []
names = [
    "PID Setpoint",
    "PID Gain",
    "PID Reset",
    "PID Deadband",
    "PID Cycle Time",
    "PID Rate",
    "system mode",
    "control schema",
    "pump",
    "solenoid",
    "Scaled Gas Pressure",
]


def convert(val):
    if "?" == val:
        return None
    elif "." in val:
        return float(val)
    else:
        return int(val)


# Create packets
with gzip.open("raw/IanArffDataset.arff.gz", "r") as f:
    i = -1

    for line in f.readlines()[31:]:
        i += 1

        line = line.decode().strip("\n").split(",")

        ipal = {}

        ipal["id"] = i
        ipal["timestamp"] = float(line[16])
        ipal["protocol"] = "modbus"
        ipal["malicious"] = line[19] if line[19] != "0" else False

        ipal["src"] = int(line[0])
        ipal["dest"] = int(line[0])
        ipal["length"] = int(line[2])
        ipal["crc"] = True

        ipal["type"] = int(line[1])
        ipal["activity"] = line[15]

        ipal["responds to"] = [i - 1] if ipal["activity"] == "0" else []

        data = [convert(value) for value in line[3:14]]

        ipal["data"] = {}
        ipal["data"]["control schema"] = data[names.index("control schema")]
        ipal["data"]["system mode"] = data[names.index("system mode")]
        ipal["data"]["pump"] = data[names.index("pump")]
        ipal["data"]["solenoid"] = data[names.index("solenoid")]
        ipal["data"]["PID Setpoint"] = data[names.index("PID Setpoint")]
        ipal["data"]["PID Gain"] = data[names.index("PID Gain")]
        ipal["data"]["PID Reset"] = data[names.index("PID Reset")]
        ipal["data"]["PID Rate"] = data[names.index("PID Rate")]
        ipal["data"]["PID Deadband"] = data[names.index("PID Deadband")]
        ipal["data"]["PID Cycle Time"] = data[names.index("PID Cycle Time")]
        ipal["data"]["Scaled Gas Pressure"] = data[names.index("Scaled Gas Pressure")]

        ipal["data"]["hash"] = int(line[14])

        print(json.dumps(ipal))

        if ipal["malicious"] is not False:
            attacks.append(
                {
                    "id": line[19],
                    "start": ipal["timestamp"],
                    "end": ipal["timestamp"],
                    "attack_point": [],
                    "description": "",
                    "ipalid": ipal["id"],
                }
            )

        packet_counter += 1

# Write attack file
with open("attacks-arff.json", "w") as f:
    f.write(json.dumps(attacks, indent=4) + "\n")

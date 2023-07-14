#!/usr/bin/env python3
import copy
import json
import random
import sys

import numpy as np

# Parse script arguments
if len(sys.argv) != 2:
    print("Usage ./add-attacks.py [prefix]")
    exit(0)
prefix = sys.argv[1]

# Get timestamps and duration
times = []
with open("./{}_testing.ipal".format(prefix), "r") as ipal_file:
    for line in ipal_file.readlines():
        ipal_msg = json.loads(line)
        times.append(ipal_msg["timestamp"])
duration = np.max(times) - np.min(times)

segment_size = 60 * 20  # 20 minutes

##### Create flooding attack dataset
attacks = []
attackID = 0

start_of_flooding_attacks = []
i = 0
while (i + 1) * segment_size < duration:
    offset_from_segment_start = random.random() * 19 * 60
    start_of_flooding_attacks.append(
        np.min(times) + i * segment_size + offset_from_segment_start
    )
    i += 1

ipal_file = open("./{}_testing.ipal".format(prefix), "r")
flooding_file = open("./ipal/{}_flooding.ipal".format(prefix), "w")
msg = json.loads(ipal_file.readline())
for start_time in start_of_flooding_attacks:
    attackID += 1

    # Find attack start
    while start_time > msg["timestamp"]:
        flooding_file.write(json.dumps(msg) + "\n")
        msg = json.loads(ipal_file.readline())

    nb_of_inserted_messages = 60 * 10  # 1 packet every 100ms for 1 minute
    deviation = np.random.normal(0, 0.01)
    next_insertion = start_time + deviation
    inserted_msg = copy.deepcopy(msg)
    inserted_msg["malicious"] = str(attackID)
    insert_id = str(inserted_msg["id"])
    for i in range(nb_of_inserted_messages):
        while next_insertion > msg["timestamp"]:
            flooding_file.write(json.dumps(msg) + "\n")
            msg = json.loads(ipal_file.readline())

        # Craft malicious pkt
        inserted_msg["id"] = insert_id + "_" + str(i)
        inserted_msg["timestamp"] = next_insertion
        flooding_file.write(json.dumps(inserted_msg) + "\n")

        # Add attack
        attacks.append(
            {
                "id": str(attackID),
                "start": inserted_msg["timestamp"],
                "end": inserted_msg["timestamp"],
                "description": "flooding",
                "attack_point": "",
                "ipalid": inserted_msg["id"],
            }
        )
        deviation = np.random.normal(0, 0.01)
        next_insertion = start_time + (0.1 * i) + deviation

flooding_file.write(json.dumps(msg) + "\n")
line = ipal_file.readline()
while line:
    msg = json.loads(line)
    flooding_file.write(json.dumps(msg) + "\n")
    line = ipal_file.readline()
ipal_file.close()
flooding_file.close()

with open("attacks_{}_flooding.json".format(prefix), "w") as f:
    f.write(json.dumps(attacks, indent=4))

##### Create injection attack dataset
attacks = []
attackID = 0

timestamp_of_injected_messages = []
i = 1  # TODO NOTE fix (usually i=0)
while (i + 1) * segment_size < duration:
    deviation = np.random.normal(0, 0.01)
    timestamp_of_injected_messages.append(np.min(times) + i * segment_size + deviation)
    i += 1

ipal_file = open("./{}_testing.ipal".format(prefix), "r")
injection_file = open("./ipal/{}_injection.ipal".format(prefix), "w")
msg = json.loads(ipal_file.readline())
for timestamp in timestamp_of_injected_messages:
    attackID += 1

    while timestamp > msg["timestamp"]:
        injection_file.write(json.dumps(msg) + "\n")
        msg = json.loads(ipal_file.readline())

    # Craft malicious pkt
    inserted_msg = copy.deepcopy(msg)
    inserted_msg["id"] = str(msg["id"]) + "_inject"
    inserted_msg["malicious"] = str(attackID)
    inserted_msg["timestamp"] = timestamp
    injection_file.write(json.dumps(inserted_msg) + "\n")

    # Add attack
    attacks.append(
        {
            "id": str(attackID),
            "start": inserted_msg["timestamp"],
            "end": inserted_msg["timestamp"],
            "description": "injection",
            "attack_point": "",
            "ipalid": inserted_msg["id"],
        }
    )

injection_file.write(json.dumps(msg) + "\n")
line = ipal_file.readline()
while line:
    msg = json.loads(line)
    injection_file.write(json.dumps(msg) + "\n")
    line = ipal_file.readline()
ipal_file.close()
injection_file.close()

with open("attacks_{}_injection.json".format(prefix), "w") as f:
    f.write(json.dumps(attacks, indent=4))

##### Create prediction attack dataset
attacks = []
attackID = 0

# TODO NOTE
if prefix == "res":
    mu = 1.0006896997134727
    std = 0.0038692116917476813
elif prefix == "req":
    mu = 1.0006894499971348
    std = 0.003466034179723686
else:
    assert False

# mu = 1.0
std = 0.014  # TODO NOTE fix

ipal_file = open("./{}_testing.ipal".format(prefix), "r")
prediction_file = open("./ipal/{}_prediction.ipal".format(prefix), "w")

packet_counter = 0
line = ipal_file.readline()
while line:
    msg = json.loads(line)

    if packet_counter % 1000 == 0:
        attack_start = msg["timestamp"]
        attackID += 1

    if 1 <= packet_counter % 1000 and packet_counter % 1000 < 101:  # ongoing attack
        attack_msg = copy.deepcopy(msg)
        attack_msg["malicious"] = str(attackID)
        attack_msg["timestamp"] = attack_start + (packet_counter % 1000) * mu - std
        attack_msg["id"] = str(attack_msg["id"]) + "_prediction"

        if attack_msg["timestamp"] < msg["timestamp"]:
            prediction_file.write(json.dumps(attack_msg) + "\n")
            # Add attack
            attacks.append(
                {
                    "id": str(attackID),
                    "start": attack_msg["timestamp"],
                    "end": attack_msg["timestamp"],
                    "description": "prediction",
                    "attack_point": "",
                    "ipalid": attack_msg["id"],
                }
            )
        # else: # TODO NOTE fix
        #    prediction_file.write(json.dumps(msg)+"\n")
    else:
        prediction_file.write(json.dumps(msg) + "\n")

    packet_counter += 1
    line = ipal_file.readline()

with open("attacks_{}_prediction.json".format(prefix), "w") as f:
    f.write(json.dumps(attacks, indent=4))

ipal_file.close()
prediction_file.close()

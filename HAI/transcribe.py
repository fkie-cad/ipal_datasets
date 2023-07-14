#!/usr/bin/python3
import datetime
import glob
import gzip
import json

FILES = [
    "test1.csv.gz",
    "test2.csv.gz",
    "test3.csv.gz",
    "test4.csv.gz",
    "test5.csv.gz",
    "train1.csv.gz",
    "train2.csv.gz",
    "train3.csv.gz",
]

attackID = 1
attacks = []


def add_new_attack(start, end):
    global attackID

    print(attackID, start, end, end - start)

    attacks.append(
        {
            "id": attackID,
            "attack_point": [],
            "description": "",
            "start": start,
            "end": end,
        }
    )

    attackID += 1


# Transcribe files
for filename in FILES:
    # Process a single test file
    print("\nProcessing", filename)

    with gzip.open("./raw/" + filename, "r") as f_in:
        with gzip.open("./ipal/" + filename.replace(".csv.", ".state."), "wt") as f_out:
            # Read column names
            columns = f_in.readline().decode().strip().split(",")
            attack_start = None
            prev = None

            for line in f_in.readlines():
                line = line.decode().strip().split(",")

                # Create state
                timestamp = int(
                    datetime.datetime.strptime(line[0], "%Y-%m-%d %H:%M:%S").timestamp()
                )
                state = {columns[i]: float(x) for i, x in list(enumerate(line))[1:-4]}

                if int(line[-4]) == 1:  # Attack
                    malicious = attackID
                    if attack_start is None:
                        attack_start = timestamp

                elif int(line[-4]) == 0:  # Benign
                    malicious = False
                    if attack_start is not None:  # attack end
                        add_new_attack(attack_start, prev["timestamp"])
                        attack_start = None

                else:
                    assert False

                # Craft IPAL message
                ipal = {
                    "timestamp": timestamp,
                    "state": state,
                    "malicious": malicious,
                }
                if prev is None:
                    prev = ipal

                # Fill gap present in the dataset
                while prev["timestamp"] + 1 < timestamp:
                    prev["timestamp"] += 1
                    f_out.write(json.dumps(prev) + "\n")
                    print("- Filled gap")

                # Output line
                f_out.write(json.dumps(ipal) + "\n")
                prev = ipal

            # Add final attack
            if attack_start is not None:
                add_new_attack(attack_start, prev["timestamp"])

# Write attacks to file
with open("attacks.json", "w") as f:
    f.write(json.dumps(attacks, indent=4) + "\n")

#!/usr/bin/env python3
import csv
import gzip
import json
from datetime import datetime


def get_attack(timestamp):
    for attack in attacks:
        if attack["start"] <= timestamp and timestamp <= attack["end"]:
            return attack
    return None


def transcribe(fin):
    print("Transcribing {}".format(fin))

    # Read input file
    with gzip.open("./raw/" + fin, "rt") as f:
        csv_data = f.readlines()
        data = csv.reader(csv_data, delimiter=";")

    # Extract attributes row
    attributes = next(data)
    attributes = [a.strip() for a in attributes]

    # Open output file
    fout = gzip.open("./ipal/" + fin.replace(".csv", ".state"), "wt")

    # Transcribe to ipal format
    prev = None
    for row in data:

        # Convert timestamp
        timestamp = int(
            datetime.strptime(row[0].strip(), "%d/%m/%Y %I:%M:%S %p").timestamp()
        )

        # Convert state
        state = {attributes[i]: row[i] for i in range(1, len(row) - 1)}
        for key, value in state.items():
            if "," in value:
                state[key] = float(value.replace(",", "."))
            else:
                state[key] = int(value)

        # Malicious (assert against attacks.json file)
        if row[len(row) - 1] == "Normal":
            assert get_attack(timestamp) is None
            malicious = False

        elif row[len(row) - 1] in ["Attack", "A ttack"]:
            assert get_attack(timestamp) is not None
            malicious = get_attack(timestamp)["id"]
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
            fout.write(json.dumps(prev) + "\n")
            print("- Filled gap")

        # Output line
        fout.write(json.dumps(ipal) + "\n")
        prev = ipal

    # Close output file
    fout.close()


if __name__ == "__main__":

    # Load attack file
    with open("attacks.json") as f:
        attacks = json.load(f)

    # Transcribe datasets
    transcribe("SWaT_Dataset_Normal_v0.csv.gz")
    transcribe("SWaT_Dataset_Normal_v1.csv.gz")
    transcribe("SWaT_Dataset_Attack_v0.csv.gz")

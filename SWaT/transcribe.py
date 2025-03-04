#!/usr/bin/env python3
import gzip
import json
from datetime import datetime

from pandas import read_excel


def get_attack(timestamp):
    for attack in attacks:
        if attack["start"] <= timestamp and timestamp <= attack["end"]:
            return attack
    return None


def transcribe(fin):
    print("Transcribing {}".format(fin))

    # Read input file
    xlsx = read_excel("./raw/" + fin)

    # Extract attributes row
    attributes = [a.strip() for a in xlsx.iloc[0]]

    # Open output file
    fout = gzip.open("./ipal/" + fin.replace(".xlsx", ".state.gz"), "wt")

    # Transcribe to ipal format
    prev = None
    for row in xlsx.itertuples():
        if row[0] == 0:  # Skip first row
            continue
        row = row[1:]  # Remove row counter

        # Convert timestamp
        timestamp = int(
            datetime.strptime(row[0].strip(), "%d/%m/%Y %I:%M:%S %p").timestamp()
        )

        # Convert state
        state = {attributes[i]: round(row[i], 9) for i in range(1, len(row) - 1)}

        # Malicious (assert against attacks.json file)
        if row[len(row) - 1] == "Normal":
            assert get_attack(timestamp) is None
            malicious = False

        elif row[len(row) - 1] in ["Attack", "A ttack"]:
            if 1451367000 <= timestamp and timestamp <= 1451367720:  # Unknown attack
                malicious = "-1"
            else:
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
    transcribe("SWaT_Dataset_Normal_v0.xlsx")
    transcribe("SWaT_Dataset_Normal_v1.xlsx")
    transcribe("SWaT_Dataset_Attack_v0.xlsx")

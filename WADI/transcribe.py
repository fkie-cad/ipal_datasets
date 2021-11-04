#!/usr/bin/env python3
import datetime
import gzip
import json
import math


def row_to_timestamp(row, data_collection_start):
    return data_collection_start + int(row) - 1


def get_attack(timestamp):
    for attack in attacks:
        if attack["start"] <= timestamp and timestamp <= attack["end"]:
            return attack
    return None


def transcribe(fin):
    print("Transcribing {}".format(fin))

    if fin == "WADI_14days_new.csv.gz":
        data_collection_start = 1506355200
    elif fin == "WADI_attackdataLABLE.csv.gz":
        data_collection_start = 1507565794
    else:
        assert False

    with gzip.open("./raw/" + fin, "r") as f_in:
        with gzip.open("./ipal/" + fin.replace(".csv.gz", ".state.gz"), "wb") as f_out:

            # Parse columns
            columns = f_in.readline().decode().strip().split(",")
            if fin == "WADI_14days_new.csv.gz":
                END = len(columns)
            elif fin == "WADI_attackdataLABLE.csv.gz":
                END = -1
            else:
                assert False
            prev_state = {col: None for col in columns[3:END]}
            prev_timestamp = data_collection_start - 1

            # Parse dataset line by line
            for line in f_in.readlines():

                # Parse line and replace strange srings
                line = line.decode().strip().replace("1.#QNAN", "nan").split(",")
                line = ["nan" if item == "" else item for item in line]

                # Calculate timestamp
                timestamp = row_to_timestamp(int(line[0]), data_collection_start)
                if prev_timestamp + 1 != timestamp:
                    print("- Found gap", prev_timestamp, timestamp)
                prev_timestamp = timestamp

                # Get state and replace nan with previous value
                state = {columns[i]: float(x) for i, x in list(enumerate(line))[3:END]}
                for col in state:
                    if math.isnan(state[col]):
                        state[col] = prev_state[col]
                prev_state = state

                # Calculate attack scenario and assert
                if fin == "WADI_attackdataLABLE.csv.gz":
                    if line[-1] == "1":  # No attack
                        assert get_attack(timestamp) is None
                        malicious = False
                    elif line[-1] == "-1":  # Attack
                        assert get_attack(timestamp) is not None
                        malicious = get_attack(timestamp)["id"]
                    else:
                        assert False

                elif fin == "WADI_14days_new.csv.gz":
                    malicious = False
                else:
                    assert False

                # Craft IPAL message
                ipal = {
                    "timestamp": timestamp,
                    "state": state,
                    "malicious": malicious,
                }
                f_out.write((json.dumps(ipal) + "\n").encode())


if __name__ == "__main__":

    # Load attack file
    with open("attacks.json") as f:
        attacks = json.load(f)

    # Transcribe datasets
    transcribe("WADI_14days_new.csv.gz")
    transcribe("WADI_attackdataLABLE.csv.gz")

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


def get_timestamp(time, short_year=False):
    if short_year:
        date_format = "%d/%m/%y %H"
    else:
        date_format = "%d/%m/%Y %H"

    date = datetime.strptime(time, date_format)
    date = date.timestamp()

    if date > 1490490000:  # account for DST hour
        date += 3600
    if date == 1490490000 and time == "26/03/17 03":
        date += 3600
    return date


def transcribe_attacks():
    with open("documentation/attacks.json", "r") as f:
        attacks = json.load(f)

    for attack in attacks:
        attack["start"] = int(get_timestamp(attack["start"]))
        attack["end"] = int(get_timestamp(attack["end"]))
        del attack["duration"]

    with open("attacks.json", "w") as f:
        f.write(json.dumps(attacks, indent=4))


def transcribe(fin):
    print("Transcribing {}".format(fin))

    # Read input file
    with gzip.open("./raw/" + fin, "rt") as f:
        csv_data = f.readlines()
        data = csv.reader(csv_data, delimiter=",")

    # Extract attributes row
    attributes = next(data)
    attributes = [a.strip() for a in attributes]

    # Open output file
    fout = gzip.open("./ipal/" + fin.replace(".csv", ".state"), "wt")

    # Transcribe to ipal format
    for row in data:
        # Convert timestamp
        timestamp = int(get_timestamp(row[0].strip(), short_year=True))

        # Convert state
        if attributes[-1] == "ATT_FLAG":
            state = {attributes[i]: row[i] for i in range(1, len(row) - 1)}
        else:
            state = {attributes[i]: row[i] for i in range(1, len(row))}

        for key, value in state.items():
            if "." in value:
                state[key] = float(value)
            else:
                state[key] = int(value)

        # Get attack according to documentation
        attack = get_attack(timestamp)

        # Use label if provided
        if attributes[-1] == "ATT_FLAG":
            if row[-1] in ["0", " -999"]:
                malicious = False
            else:
                assert attack is not None
                malicious = attack["id"]

        # Test data has no labels, use documentation
        else:
            malicious = False if attack is None else attack["id"]

        # Craft IPAL message
        ipal = {
            "timestamp": timestamp,
            "state": state,
            "malicious": malicious,
        }

        # Output line
        fout.write(json.dumps(ipal) + "\n")

    # Close output file
    fout.close()


if __name__ == "__main__":
    transcribe_attacks()

    # Load attack file
    with open("attacks.json") as f:
        attacks = json.load(f)

    # Transcribe datasets
    transcribe("BATADAL_dataset03.csv.gz")
    transcribe("BATADAL_dataset04.csv.gz")
    transcribe("BATADAL_test_dataset.csv.gz")

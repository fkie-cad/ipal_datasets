#!/usr/bin/env python3
import gzip
import json

attacks = []


def get_attack(timestamp):
    for attack in attacks:
        if attack["start"] <= timestamp and timestamp <= attack["end"]:
            return attack
    return False


def transcribe(filename):

    print("Transcribing: {}".format(filename))

    with gzip.open("./raw/" + filename, "r") as f_in:
        with gzip.open("./ipal/" + filename.replace(".csv.", ".state."), "wt") as f_out:

            time = 0

            for line in f_in.readlines():
                line = line.decode().strip().split(",")

                time += 1
                timestamp = time

                state = {str(i + 1): float(line[i]) for i in range(len(line))}

                if timestamp >= 4000:
                    malicious = get_attack(timestamp)["id"]
                    assert malicious is not False
                else:
                    malicious = False
                    assert get_attack(timestamp) is False

                # Craft IPAL message
                ipal = {
                    "timestamp": timestamp,
                    "state": state,
                    "malicious": malicious,
                }

                # Output line
                f_out.write(json.dumps(ipal) + "\n")


if __name__ == "__main__":

    # Load attack file
    with open("attacks.json") as f:
        attacks = json.load(f)

    transcribe("SA1.csv.gz")
    transcribe("SA2.csv.gz")
    transcribe("SA3.csv.gz")

    transcribe("DA1.csv.gz")
    transcribe("DA2.csv.gz")

#!/usr/bin/env python3
import gzip
import json
import os

attacks = []


def get_attack(timestamp):
    for attack in attacks:
        if attack["start"] <= timestamp and timestamp <= attack["end"]:
            return attack
    return False


OFFSET = -5000


def transcribe(fin, fout):
    global OFFSET
    OFFSET += 5000

    print("Transcribing: {}".format(fin))

    with open("./raw/" + fin, "r") as f_in:
        with gzip.open("./ipal/" + fout + ".state.gz", "wt") as f_out:
            time = 0

            for line in f_in.readlines():
                line = line.strip().split(",")

                time += 1
                timestamp = time + OFFSET

                state = {str(i + 1): float(line[i]) for i in range(len(line))}

                if timestamp - OFFSET >= 4000:
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

    transcribe("1 - Scenario DA1/xmv10_359_data_1.csv", "DA1")
    transcribe("2 - Scenario DA2/xmeas7_zero_data_1.csv", "DA2")
    transcribe("3 - Scenario SA1/xmv9_hundred_data_1.csv", "SA1")
    transcribe("4 - Scenario SA2/xmv6_twentyeight_data_1.csv", "SA2")
    transcribe("5 - Scenario SA3/xmeas10_001_data_1.csv", "SA3")

    os.system("./train.sh")

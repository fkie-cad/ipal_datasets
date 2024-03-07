#!/usr/bin/env python3
import gzip
import json
import sys

if len(sys.argv) < 3:
    print("Usage: ./test.py [attacks.json] [files]")
    sys.exit(1)


def get_attack(timestamp):
    for attack in attacks:
        if attack["start"] <= timestamp and timestamp <= attack["end"]:
            return attack
    return None


with open(sys.argv[1], "r") as f:
    attacks = json.load(f)
    for attack in attacks:
        attack["_found"] = False

FAILED = False

for file in sys.argv[2:]:
    print(f"Testing {file}")

    with gzip.open(file, "r") as f:
        for line in f.readlines():
            line = json.loads(line)
            a = get_attack(line["timestamp"])

            if line["malicious"] is False:  # label is benign
                if a is not None:  # attack.json should not contain an attack
                    print(f"- attack.json contains attack {a['id']}, but not labelled")
                    FAILED = True

            else:  # label is attack
                if a is None:  # attack.json should contain an attack
                    print(f"- attack.json is benign, but label is {line['malicious']}")
                    FAILED = True
                    continue

                if line["malicious"] != a["id"]:  # attack id should be the same
                    print(
                        f"- attack.json is {a['id']}, but label is {line['malicious']}"
                    )
                    FAILED = True

                a["_found"] = True

print(f"Testing {sys.argv[1]}")
for attack in attacks:
    if not attack["_found"]:
        print(f"- attack {attack['id']} was not used in the labels")
        FAILED = True

if FAILED:
    print("TEST FAILED\n")
    sys.exit(-1)
else:
    print("TEST SUCCESSFUL\n")

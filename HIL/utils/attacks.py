#!/usr/bin/python3
import gzip
import json
from datetime import datetime


def to_timestamp(val):
    if "." not in val:  # at exactly .0000 the float values are missing?
        print(val)
        val += ".0"

    return datetime.strptime(val, "%Y-%m-%d %H:%M:%S.%f").timestamp()


attacks = []

for fname in ["attack_1", "attack_2", "attack_3"]:
    print("Extracting attacks {}".format(fname))
    attack = None
    prev_time = None

    with gzip.open("raw/Network datatset/csv/{}.csv.gz".format(fname), "r") as fin:
        txt = fin.read().decode().split("\n")
        columns = txt[0].strip().split(",")

        for line in txt[1:]:
            if len(line) == 0:
                continue
            line = line.strip().split(",")

            time = to_timestamp(line[0])
            malicious = (
                False if line[-1] in ["normal", "nomal", "anomaly"] else line[-1]
            )

            # Collect attack start and ends
            if malicious and attack is None:
                attack = malicious
                attack_start = time
            elif malicious is False and attack is not None:
                attacks.append([attack, attack_start, prev_time])
                attack = None
            prev_time = time

out = []
for name, start, end in attacks:
    out.append(
        {"id": name, "attack_point": [], "description": "", "start": start, "end": end}
    )

with open("attacks.json", "w") as f:
    f.write(json.dumps(out, indent=4))

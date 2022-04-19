#!/usr/bin/env python3
from datetime import datetime
import json
import sys

ATTACKID = 0
STRPTIME = "%Y-%m-%d %H:%M:%S.%f"
DIFF = -9 * 3600  # Account for time difference!


def parse_file(file):
    global ATTACKID

    with open(file, "r") as f:
        while True:
            line1 = f.readline()
            line2 = f.readline()
            if not line2:
                break  # EOF

            line1 = line1.strip().split(" ")
            line2 = line2.strip().split(" ")
            assert line1[-1] == "START" and line2[-1] == "END"

            start = " ".join(line1[:2])
            attack1 = " ".join(line1[2:-1])
            end = " ".join(line2[:2])
            attack2 = " ".join(line2[2:-1])
            assert attack1 == attack2

            ATTACKID += 1
            yield {
                "id": ATTACKID,
                "attack_point": [],
                "description": attack1,
                "start": datetime.strptime(start, STRPTIME).timestamp() + DIFF,
                "end": datetime.strptime(end, STRPTIME).timestamp() + DIFF,
            }


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: ./gen_attacks.py [input dir raw/**] [output dir ipal/**]")
        sys.exit(-1)

    dir_in = sys.argv[1]
    dir_out = sys.argv[2]

    attacks = parse_file("{}/Attack_script_log.log".format(dir_in))

    with open("{}/attacks.json".format(dir_out), "w") as f:
        f.write(json.dumps(list(attacks), indent=4))

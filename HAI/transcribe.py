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

attack_points = {
    1: ["state;P1_B2016"],
    2: ["state;P1_B3005"],
    3: ["state;P1_LCV01D"],
    4: ["state;P2_SCO"],
    5: ["state;P2_AutoSD"],
    6: ["state;P2_VTR02"],
    7: ["state;P1_B2016", "state;P1_PIT01"],
    8: ["state;P1_LCV01D"],
    9: ["state;P1_B3005", "state;P1_FT03"],
    10: ["state;P1_B2016"],
    11: ["state;P1_FCV03D", "state;P1_FT03"],
    12: ["state;P2_VTR01"],
    13: ["state;P1_B3004", "state;P1_LIT01"],
    14: ["state;P1_B3004"],
    15: ["state;P1_PCV01D", "state;P1_PIT01"],
    16: ["state;P2_AutoSD"],
    17: ["state;P2_AutoSD", "state;P2_SIT01"],
    18: ["state;P1_LCV01D", "state;P1_LIT01"],
    19: ["state;P1_PCV01D"],
    20: ["state;P2_SCO", "state;P2_SIT01"],
    21: ["state;P1_FCV03D"],
    22: ["state;P2_RTR"],
    23: ["state;P1_FCV03D"],
    24: ["state;P3_LCP01D"],
    25: ["state;P2_LCV01D"],
    26: ["state;P1_LCV01D", "state;P1_B3005"],
    27: ["state;P1_B2016", "state;P1_PIT01", "state;P1_B3005"],
    28: ["state;P1_PCV01D", "state;P1_LCV01D"],
    29: ["state;P2_AutoSD", "state;P2_VTR01"],
    30: ["state;P2_SCO", "state;P2_VTR02"],
    31: ["state;P1_B2016", "state;P2_AutoSD"],
    32: ["state;P1_FCV03D", "state;P2_VTR01"],
    33: ["state;P1_LCV01D", "state;P1_LIT01", "state;P2_AutoSD"],
    34: ["state;P1_PCV01D", "state;P1_B3004", "state;P1_LIT01"],
    35: ["state;P1_B3005", "state;P1_FT03", "state;P2_LCV01D"],
    36: ["state;P1_B3004", "state;P1_LIT01", "state;P2_LCV01D"],
    37: ["state;P2_SCO", "state;P2_SIT01", "state;P1_LCV01D", "state;P1_LIT01"],
    38: ["state;P2_AutoSD", "state;P2_LCV01D"],
    39: ["state;P1_PCV01D", "state;P2_VTR02"],
    40: ["state;P1_FCV03D", "state;P1_FT03", "state;P2_SCO"],
    41: ["state;P1_B3004", "state;P1_LIT01", "state;P2_SCO"],
    42: ["state;P1_FCV03D", "state;P2_LCV01D"],
    43: ["state;P1_B3004", "state;P2_AutoSD"],
    44: ["state;P2_SCO", "state;P2_SIT01", "state;P2_LCV01D"],
    45: ["state;P2_AutoSD", "state;P2_VTR01"],
    46: ["state;P1_FCV03D", "state;P1_LCV01D"],
    47: ["state;P1_B2016", "state;P1_PCV01D"],
    48: ["state;P1_B3004", "state;P1_LCV01D", "state;P1_LIT01"],
    49: ["state;P2_RTR", "state;P2_LCV01D"],
    50: ["state;P1_B3005", "state;P1_FCV03D", "state;P1_FT03"],
}

def add_new_attack(start, end):
    global attackID

    print(attackID, start, end, end - start)

    attacks.append(
        {
            "id": attackID,
            "attack_point": attack_points[attackID],
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

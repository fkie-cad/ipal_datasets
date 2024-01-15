import os
import sys

import pandas as pd


def search_timings(row, ipal):
    if "ipalid" not in row.keys():
        return row
    id = row["ipalid"]
    start = ipal["timestamp"].iloc[id]
    if id == ipal.shape[0] - 1:
        row["end"] = start
        return row

    end = ipal["timestamp"].iloc[id + 1]
    row["start"] = start
    row["end"] = end
    return row


if __name__ == "__main__":
    # filename = sys.argv[1]

    # for file in os.listdir('/home/lenz/datasets/PowerDuck/malicious/'):
    #     filename = os.fsdecode(file)
    #     # print(filename)
    #     if filename.endswith('.json'):
    #         path_to_attack = '/home/lenz/datasets/PowerDuck/malicious/' + filename
    path_to_attack = sys.argv[1]
    print(f"Processing {path_to_attack}")
    attack_file = pd.read_json(path_to_attack)
    prefix = path_to_attack.split("/")[6]
    prefix = prefix.split(".")[0]
    path_to_ipal = "~/datasets/PowerDuck/ipal/attack/" + prefix + ".ipal"
    ipal_file = pd.read_json(path_to_ipal, lines=True)
    attack_file = attack_file.apply(
        lambda x: search_timings(row=x, ipal=ipal_file), axis=1
    )

    # print()

    i = 0
    while i < attack_file.shape[0] - 2:
        j = 1
        # print(attack_file)
        # print(attack_file.shape[0])
        while (
            int(attack_file["ipalid"].iloc[i + j])
            == int(attack_file["ipalid"].iloc[i]) + j
        ):
            attack_file.at[i, "end"] = attack_file["end"].iloc[i + j]
            attack_file.at[i + j, "end"] = -1
            # print(j+1 >= attack_file.shape[0])
            if j + 1 >= attack_file.shape[0] - 1:
                break

            j += 1
        i += j

    attack_file = attack_file[attack_file["end"] != -1]
    attack_file.to_json(path_to_attack, orient="records")

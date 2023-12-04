#!/usr/bin/python3
import gzip
import json
from datetime import datetime


def convert(val):
    if val.lower() in ["false", "true"]:
        return val.lower() == "true"
    else:
        return int(val)


def to_timestamp(val):
    return int(datetime.strptime(val, "%d/%m/%Y %H:%M:%S").timestamp())


for fname in ["phy_att_1", "phy_att_2", "phy_att_3", "phy_att_4", "phy_norm"]:
    print("Transcribing {}".format(fname))

    with gzip.open("raw/Physical dataset/{}.csv.gz".format(fname), "r") as fin:
        with gzip.open("ipal/{}.state.gz".format(fname), "wt") as fout:
            txt = fin.read().decode("utf-16").split("\n")
            columns = txt[0].strip().split("\t")

            for line in txt[1:]:
                if len(line) == 0:
                    continue
                line = line.strip().split("\t")

                state = {
                    "timestamp": to_timestamp(line[0]),
                    "state": {k: convert(v) for k, v in list(zip(columns, line))[1:-2]},
                    "malicious": False if line[-1] in ["normal", "nomal"] else line[-1],
                }

                fout.write(json.dumps(state) + "\n")

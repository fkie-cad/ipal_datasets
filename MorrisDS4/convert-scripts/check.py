#!/usr/bin/python3
import gzip
import json
from math import isclose


def float_eq(val, msg, key):
    if val == "?":
        return key not in msg["data"] or msg["data"][key] is None

    else:
        if key not in msg["data"] or msg["data"][key] is None:
            return False
        else:
            erg = isclose(float(val), msg["data"][key], rel_tol=0.001)
            if not erg:
                print("DIFF", float(val), msg["data"][key])
            return isclose(float(val), msg["data"][key], rel_tol=0.001)


def diff(arff, ipal):
    diffs = []

    if not (int(arff[0]) == ipal["src"] and int(arff[0]) == ipal["dest"]):  # Address
        diffs.append(-1)
    if not (int(arff[1]) == ipal["type"]):  # Function
        diffs.append(-2)
    if not int(arff[2]) == ipal["length"]:  # Length
        diffs.append(-3)
    if not (float_eq(arff[3], ipal, "PID Setpoint")):  # Setpoint
        diffs.append(-4)
    if not (float_eq(arff[4], ipal, "PID Gain")):  # Gain
        diffs.append(-5)
    if not (float_eq(arff[5], ipal, "PID Reset")):  # Reset rate
        diffs.append(-6)
    if not (float_eq(arff[6], ipal, "PID Deadband")):  # Deadband
        diffs.append(-7)
    if not (float_eq(arff[7], ipal, "PID Cycle Time")):  # Cycle Time
        diffs.append(-8)
    if not (float_eq(arff[8], ipal, "PID Rate")):  # Rate
        diffs.append(-9)
    if not (float_eq(arff[9], ipal, "system mode")):  # System Mode
        diffs.append(-10)
    if not (float_eq(arff[10], ipal, "control schema")):  # control schema
        diffs.append(-11)
    if not (float_eq(arff[11], ipal, "pump")):  # Pump
        diffs.append(-12)
    if not (float_eq(arff[12], ipal, "solenoid")):  # Solenoid
        diffs.append(-13)
    if not (float_eq(arff[13], ipal, "Scaled Gas Pressure")):  # Pressure
        diffs.append(-14)
    # NOTE arff[14] CRC ignored!
    if not (arff[15] == ipal["activity"]):
        diffs.append(-16)
    if not (isclose(float(arff[16]), ipal["timestamp"], rel_tol=0.001)):  # Timestamp
        diffs.append(-17)
    if not (
        (arff[19] == "0" and ipal["malicious"] is False)
        or (arff[19] == ipal["malicious"])
    ):  # Malicious
        diffs.append(-18)

    return diffs


arff = []
ipal = []

with gzip.open("raw/IanArffDataset.arff.gz", "r") as f:
    for line in f.readlines():
        line = line.decode().strip("\n")
        if len(line) == 0 or line[0] in ["%", "@"]:
            continue
        arff.append(line.split(","))

with gzip.open("ipal/IanArffDataset.ipal.gz", "r") as f:
    for line in f.readlines():
        ipal.append(json.loads(line))

if len(arff) != len(ipal):
    print(
        "WARNING: Datasets differ in size (arff {}, ipal {})!\n".format(
            len(arff), len(ipal)
        )
    )

for i in range(min([len(arff), len(ipal)])):
    try:
        assert len(diff(arff[i], ipal[i])) == 0
    except Exception as e:
        print(arff[i][-3:], i)

        errno = diff(arff[i], ipal[i])
        print("Error {} in packet {}".format(errno, i + 1))
        print(arff[i])
        print(ipal[i])
        print(e)
        print("")

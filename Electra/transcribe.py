#!/usr/bin/env python3
import gzip
import json

#  0 time
#  1 smac
#  2 dmac
#  3 sip
#  4 dip
#  5 request
#  6 function code
#  7 error
#  8 address
#  9 data
# 10 label

IPALID = -1


def new_ipal():
    global IPALID
    global protocol
    IPALID += 1

    return {
        "id": IPALID,
        "timestamp": None,
        "protocol": "s7" if protocol == "s7comm" else protocol,
        "malicious": None,
        "src": None,
        "dest": None,
        "length": None,
        "crc": True,
        "type": None,
        "activity": None,
        "responds to": [],
        "data": {},
    }


def label_to_malicious(label):

    if label in ["NORMAL", "MITM_UNALTERED"]:
        return False
    elif label in [
        "RECOGNITION_ATTACK",
        "RESPONSE_ATTACK",
        "FORCE_ERROR_ATTACK",
        "READ_ATTACK",
        "WRITE_ATTACK",
        "REPLAY_ATTACK",
        "COMMAND_ATTACK",
        "FALSE_ERROR_RESPONSE_ATTACK",
    ]:
        return label
    else:
        assert False


def request_to_activity(request):
    if request == "0":
        return "inform"
    elif request == "1":
        return "interrogate"
    else:
        assert False


def write_attack(ipal):
    global attacks

    if ipal["malicious"] is None or ipal["malicious"] is False:
        return

    attacks.append(
        {
            "id": ipal["malicious"],
            "attack_point": [],
            "description": "",
            "ipalid": ipal["id"],
        }
    )


for protocol in ["modbus", "s7comm"]:
    print("Transcribing", protocol)
    attacks = []

    with gzip.open("raw/electra_{}.csv.gz".format(protocol), "rt") as fin:
        line = fin.readline()  # Skip first line

        with gzip.open("ipal/electra_{}.ipal.gz".format(protocol), "wt") as fout:

            line = fin.readline()
            ipal = None
            prev_line = ""

            while line:
                (
                    time,
                    _,
                    _,
                    sip,
                    dip,
                    request,
                    fc,
                    _,
                    address,
                    data,
                    label,
                ) = line.strip().split(",")
                time = int(time)
                data = int(data)
                request = request_to_activity(request)
                label = label_to_malicious(label)

                if line == prev_line:
                    print("Skipped dupplicated line", line.strip())

                elif ipal is None or (
                    time != ipal["timestamp"]
                    or sip != ipal["src"]
                    or dip != ipal["dest"]
                    or fc != ipal["type"]
                ):
                    if ipal is not None:
                        fout.write(json.dumps(ipal) + "\n")
                        write_attack(ipal)

                    ipal = new_ipal()
                    ipal["timestamp"] = time
                    ipal["src"] = sip
                    ipal["dest"] = dip
                    ipal["type"] = fc
                    ipal["activity"] = request
                    ipal["data"][address] = data
                    ipal["malicious"] = label

                else:
                    assert (
                        time == ipal["timestamp"]
                        and sip == ipal["src"]
                        and dip == ipal["dest"]
                        and request == ipal["activity"]
                        and fc == ipal["type"]
                    )

                    try:
                        assert (
                            address not in ipal["data"] or ipal["data"][address] == data
                        )
                    except AssertionError:
                        if protocol == "s7comm":
                            print("Warning: got data for same time and address twice.")
                        else:
                            exit(1)
                    ipal["data"][address] = data

                    assert (
                        label is False
                        or ipal["malicious"] is False
                        or ipal["malicious"] == label
                    )
                    ipal["malicious"] = ipal["malicious"] or label

                prev_line = line
                line = fin.readline()

            # Write last message
            fout.write(json.dumps(ipal) + "\n")
            write_attack(ipal)

    with open("attacks_{}.json".format(protocol), "w") as fattacks:
        fattacks.write(json.dumps(attacks, indent=4))

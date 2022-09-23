#!/usr/bin/env python3
import gzip
import json
from scipy.io import arff


def transcribe(arff, meta):
    """
    Transcribe an arff file into an ipal object.
    """
    id = 0

    attributes = meta.names()
    attributes.remove("snort_log1")
    attributes.remove("snort_log2")
    attributes.remove("snort_log3")
    attributes.remove("snort_log4")
    attributes.remove("marker")

    for i, msg in enumerate(arff):
        marker = int(msg["marker"])

        natural_event = marker in [1, 2, 3, 4, 5, 6, 13, 14]
        no_event = marker == 41

        malicious = not natural_event and not no_event
        attack_details = f"{0 if no_event else (1 if natural_event else 2)};{marker}"
        id += 1

        state = {attr: float(msg[attr]) for attr in attributes}

        yield {
            "id": id,
            "timestamp": id,
            "malicious": malicious,
            "attack_details": attack_details,
            "state": state,
        }


def main():
    in_files = [f"./raw/data{i+1} Sampled Scenarios.csv.arff.gz" for i in range(15)]

    with gzip.open("ipal/AdhikariArffDataset.state.gz", "wt") as out_f:
        for in_file in in_files:
            with gzip.open(in_file, "rt") as in_f:
                data, meta = arff.loadarff(in_f)

                for ipal_msg in transcribe(data, meta):
                    json.dump(ipal_msg, out_f)
                    out_f.write("\n")


if __name__ == "__main__":
    main()

#!/usr/bin/env bash
TRANSCRIBER="ipal-transcriber --protocol modbus --ipal.out - --malicious.default false --malicious attacks.json --log info --rules utils/rules.py"

# Remove previous files
rm -f ipal/*.ipal*

echo "Build attacks.json"
python3 utils/attacks.py

echo "Transcribing state"
python3 utils/state.py

echo "Transcribing normal.pcap"
$TRANSCRIBER \
    --pcap raw/Network\ datatset/pcap/normal.pcap.gz \
    | pv -l | gzip > ipal/normal.ipal.gz

echo "Transcribing attack_1.pcap"
$TRANSCRIBER \
    --pcap raw/Network\ datatset/pcap/attack_1.pcap.gz \
    | pv -l | gzip > ipal/attack_1.ipal.gz

echo "Transcribing attack_2.pcap"
$TRANSCRIBER \
    --pcap raw/Network\ datatset/pcap/attack_2.pcap.gz \
    | pv -l | gzip > ipal/attack_2.ipal.gz

echo "Transcribing attack_3.pcap"
$TRANSCRIBER \
    --pcap raw/Network\ datatset/pcap/attack_3.pcap.gz \
    | pv -l | gzip > ipal/attack_3.ipal.gz

echo "Transcribing attack_4.pcap"
$TRANSCRIBER \
    --pcap raw/Network\ datatset/pcap/attack_4.pcap.gz \
    | pv -l | gzip > ipal/attack_4.ipal.gz

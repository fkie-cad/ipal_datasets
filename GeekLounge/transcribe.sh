#!/usr/bin/env bash
TRANSCRIBER="ipal-transcriber --protocol s7 --ipal.out - --malicious.default false"

# Remove previous files
rm -f ipal/*.ipal*

# Clean pcap
echo "Cleaning original dataset"
tshark \
    -r raw/4SICS-GeekLounge-151022.pcap.gz \
    -w cleaned.pcap \
    s7comm and ip.addr eq 10.10.10.20 and not tcp.analysis.retransmission and not tcp.analysis.fast_retransmission

# Create traning dataset
echo "Transcribing training dataset" # (10/90 split)
$TRANSCRIBER --pcap cleaned.pcap | head -n 10638 > training.ipal
cat training.ipal | grep inform > ipal/res_training.ipal
cat training.ipal | grep interrogate > ipal/req_training.ipal

# Create testing dataset
echo "Transcribing testing dataset" # (10/90 split)
$TRANSCRIBER --pcap cleaned.pcap | tail -n +10639 > testing.ipal
cat testing.ipal | grep inform > res_testing.ipal
cat testing.ipal | grep interrogate > req_testing.ipal

# Add attacks
echo "Adding attacks"
python3 convert-scripts/add-attacks.py res
python3 convert-scripts/add-attacks.py req

# Compress files
gzip ipal/*.ipal

# Remove temporary files
echo "Removing temporary files"
rm cleaned.pcap
rm training.ipal *testing.ipal

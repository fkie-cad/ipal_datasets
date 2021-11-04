#!/usr/bin/env bash

set -e

# Remove previous files
rm -f ipal/*

# Creates pcap and attacks.json
echo "Creating pcap from raw messages"
python3 convert-scripts/from-raw.py 2>/dev/null
gzip ipal/*.pcap

# Transcribe raw dataset
echo "Transcribing training dataset"
ipal-transcriber \
    --protocol modbus \
    --malicious.default false --malicious attacks.json \
    --rules convert-scripts/config.py \
    --log info \
    --pcap ipal/IanDataset.pcap.gz \
    --ipal.out - | pv -l > ipal/IanRawDataset.ipal

# Create Arff ipal file
python3 convert-scripts/from-arff.py > ipal/IanArffDataset.ipal

# Compress files
gzip ipal/*.ipal

# Test dataset differences
echo "Attacks should not differ! output:"
diff attacks.json attacks-arff.json
rm -f attacks-arff.json

echo "Testing dataset"
python3 convert-scripts/check.py

# Cleanup
rm -f ipal/*pcap.gz

./add-state.sh

#!/usr/bin/env bash
TRANSCRIBER="ipal-transcriber --protocol modbus --ipal.out - --malicious.default false --log info"

# Remove previous files
rm -f -r ipal/*

# Transcribe normal data
echo "Transcribing MiTM Normal Data"
mkdir ipal/normal
for f in ./raw/normal/*pcap.gz; do
    f=$(basename $f)
    f=${f%.*.*}
    echo Transcribing $f

    $TRANSCRIBER \
        --pcap raw/normal/$f.pcap.gz \
        | pv -l | gzip > ipal/normal/$f.ipal.gz
done

# Transcribe channel attack data
echo "Transcribing channel data"
mkdir ipal/channel
for f in ./raw/channel/*pcap.gz; do
    f=$(basename $f)
    f=${f%.*}
    echo Transcribing $f

    $TRANSCRIBER \
        --pcap raw/channel/$f.gz \
        | pv -l | gzip > ipal/channel/$f.ipal.gz
done

# Transcribe attack data
echo "Transcribing MiTM Attack data"
mkdir ipal/attack
for f in ./raw/attack/*pcap.gz; do
    f=$(basename $f)
    f=${f%.*.*}
    echo Transcribing $f

    $TRANSCRIBER \
        --pcap raw/attack/$f.pcap.gz \
        --malicious attacks-$f.json \
        | pv -l | gzip > ipal/attack/$f.ipal.gz
done

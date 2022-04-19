#!/usr/bin/env bash
TRANSCRIBER="ipal-transcriber --ipal.out - --malicious.default false"

echo "Removing previous files"
rm -rf ipal/*

echo "Generate attack.json files"
find raw -type d -print0 -mindepth 1 -maxdepth 1 |
while read -d $'\0' dir_in
do
    # File path magic
    dir_out=$(echo $dir_in | sed 's/^raw/ipal/g')
    echo "- " $dir_in "->" $dir_out
    mkdir -p $dir_out

    # Generate attack.json from .log file
    python3 gen_attacks.py $dir_in $dir_out
done

echo "Transcribe each experiment"
find raw -type d -print0 -mindepth 3 |
while read -d $'\0' dir_in
do
    # File path magic
    dir_out=$(echo $dir_in | sed 's/^raw/ipal/g')
    echo "- " $dir_in "->" $dir_out
    mkdir -p $dir_out

    # Transcribe master and slave pcaps
    $TRANSCRIBER \
        --pcap $dir_in/master.pcap.gz --malicious $dir_out/../../attacks.json \
    | pv -l | gzip > $dir_out/master.ipal.gz

    $TRANSCRIBER \
        --pcap $dir_in/slave.pcap.gz --malicious $dir_out/../../attacks.json \
    | pv -l | gzip > $dir_out/slave.ipal.gz
done

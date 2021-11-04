#!/usr/bin/env bash
rm -rf ipal/*
rm -rf raw/train.pcap raw/test.pcap raw/*txt raw/*-*

TRANSCRIBER="ipal-transcriber --protocol iec104 --malicious.default false"

echo -e "Filter IEC-104 for one connection\n"
tshark \
    -r raw/orig.pcap \
    -w raw/filtered.pcap \
    -Y "ip.addr == 10.0.104.11 and iec60870_104 and !(iec60870_104.type == 0x03)"

# Artificially increase pcap length
echo -e "Increase pcap length\n"
cp raw/filtered.pcap raw/filteredXtimes.pcap
for i in {1..31} # 31 repetitions
do
    tcprewrite --portmap=57012:$((58000+$i)) --infile=raw/filtered.pcap --outfile=append.pcap
    mergecap -a -w merged.pcap raw/filteredXtimes.pcap append.pcap
    mv merged.pcap raw/filteredXtimes.pcap
    rm append.pcap
done

# 50/50 train test split
echo -e "Perform train-test split\n"
pkt_count=$(tshark -r raw/filteredXtimes.pcap | wc -l)
editcap -c $(($pkt_count/2)) raw/filteredXtimes.pcap out
mv out_00000* raw/train.pcap
mv out_00001*  raw/test.pcap

$TRANSCRIBER --pcap raw/train.pcap --ipal.out  ipal/train.ipal.gz
$TRANSCRIBER --pcap raw/test.pcap --ipal.out  ipal/test.ipal.gz

rm -f raw/filtered*

# Add attacks
echo "Adding attacks"
# Three attack probabilities
Ns=(
    "0.001"
    "0.01"
    "0.1"
)
# Three attack types
Ts=(
    "C"
    "R"
    "S"
)

pkt_count=$(tshark -r raw/test.pcap | wc -l)

for i in {0..9} # 10 repetitions
do
    for T in "${Ts[@]}"; do # 3x attack type
        for N in "${Ns[@]}"; do # 3x parameters
            echo $T $N $i $( python -c "print int(round($N * $pkt_count))" )

            python3 ./manipulateTraces/__init__.py \
                -$T $( python -c "print int(round($N * $pkt_count))" ) \
                -t raw/test.pcap \
                -o raw/$T-$N-$i.pcap

            # Transcribe
            $TRANSCRIBER --pcap raw/$T-$N-$i.pcap --ipal.out ipal/$T-$N-$i.ipal.gz
        done
    done
done

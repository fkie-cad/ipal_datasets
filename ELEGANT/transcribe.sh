#!/usr/bin/env bash
TRANSCRIBER="ipal-transcriber --protocol modbus --ipal.out - --malicious.default false"

# Remove previous files
rm -f ipal/*.ipal*

# Transcribe normal data
echo "Transcribing MiTM Normal Data"
mergecap -w normal.pcap raw/MiTM_normal_PLC_traffic/* # Join normal data
$TRANSCRIBER \
    --pcap normal.pcap \
    | pv -l | gzip > ipal/MiTM_normal.ipal.gz
rm normal.pcap

# Transcribe MiTM_ARP_Poisoning
echo "Transcribing MiTM_ARP_Poisoning 1"
$TRANSCRIBER \
    --pcap raw/MiTM_ARP_Poisoning/cap_00001_20210318034103.pcapng \
    --malicious attacks_MiTM_ARP_Poisoning_1.json \
    | pv -l | gzip > ipal/MiTM_ARP_Poisoning_1.ipal.gz

echo "Transcribing MiTM_ARP_Poisoning 2"
$TRANSCRIBER \
    --pcap raw/MiTM_ARP_Poisoning/cap_00001_20210318084952.pcapng \
    --malicious attacks_MiTM_ARP_Poisoning_2.json \
    | pv -l | gzip > ipal/MiTM_ARP_Poisoning_2.ipal.gz

# Transcribe MiTM_Full_Chain
echo "Transcribing MiTM_Full_Chain 1"
$TRANSCRIBER \
    --pcap raw/MiTM_Full_Chain/cap_00001_20210318095210.pcapng \
    --malicious attacks_MiTM_Full_Chain_1.json \
    | pv -l | gzip > ipal/MiTM_Full_Chain_1.ipal.gz

echo "Transcribing MiTM_Full_Chain 2"
$TRANSCRIBER \
    --pcap raw/MiTM_Full_Chain/cap_00001_20210318100414.pcapng \
    --malicious attacks_MiTM_Full_Chain_2.json \
    | pv -l | gzip > ipal/MiTM_Full_Chain_2.ipal.gz

echo "Transcribing MiTM_Full_Chain 3"
$TRANSCRIBER \
    --pcap raw/MiTM_Full_Chain/cap_00001_20210318101444.pcapng \
    --malicious attacks_MiTM_Full_Chain_3.json \
    | pv -l | gzip > ipal/MiTM_Full_Chain_3.ipal.gz

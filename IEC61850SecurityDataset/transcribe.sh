#!/usr/bin/env bash

TRANSCRIBER="ipal-transcriber --log info --malicious.default false"

echo "Transcribing normal files"
rm -rf ipal/Normal && mkdir -p ipal/Normal
$TRANSCRIBER --pcap raw/Normal/Normal.pcapng.gz --ipal.out ipal/Normal/Normal.ipal.gz
$TRANSCRIBER --pcap raw/Normal/VariableLoad.pcapng.gz --ipal.out ipal/Normal/VariableLoad.ipal.gz

echo "Transcribing disturbance files"
rm -rf ipal/Disturbance && mkdir -p ipal/Disturbance
$TRANSCRIBER --pcap raw/Disturbance/BreakFailure.pcapng.gz --ipal.out ipal/Disturbance/BreakFailure.ipal.gz
$TRANSCRIBER --pcap raw/Disturbance/BusbarProtection.pcapng.gz --ipal.out ipal/Disturbance/BusbarProtection.ipa.gz
$TRANSCRIBER --pcap raw/Disturbance/UnderFrequency.pcapng.gz --ipal.out ipal/Disturbance/UnderFrequency.ipal.gz

echo "Transcribing attack files"

echo "- DM"
rm -rf ipal/Attack/DM && mkdir -p ipal/Attack/DM
$TRANSCRIBER --pcap raw/Attack/Data\ Manipulation\ \(DM\)/AS1.pcapng.gz --ipal.out ipal/Attack/DM/AS1.ipal.gz --malicious attacks-dm1.json
$TRANSCRIBER --pcap raw/Attack/Data\ Manipulation\ \(DM\)/AS2.pcapng.gz --ipal.out ipal/Attack/DM/AS2.ipal.gz --malicious attacks-dm2.json
$TRANSCRIBER --pcap raw/Attack/Data\ Manipulation\ \(DM\)/AS3.pcapng.gz --ipal.out ipal/Attack/DM/AS3.ipal.gz --malicious attacks-dm3.json

echo "- DoS"
rm -rf ipal/Attack/DoS && mkdir -p ipal/Attack/DoS
$TRANSCRIBER --pcap raw/Attack/Denial\ of\ Service\ \(DoS\)/AS1.pcapng.gz --ipal.out ipal/Attack/DoS/AS1.ipal.gz --malicious attacks-dos.json

echo "- MS"
rm -rf ipal/Attack/MS && mkdir -p ipal/Attack/MS
$TRANSCRIBER --pcap raw/Attack/Message\ Suppression\ \(MS\)/AS1.pcapng.gz --ipal.out ipal/Attack/MS/AS1.ipal.gz --malicious attacks-ms1.json
$TRANSCRIBER --pcap raw/Attack/Message\ Suppression\ \(MS\)/AS2.pcapng.gz --ipal.out ipal/Attack/MS/AS2.ipal.gz --malicious attacks-ms2.json
$TRANSCRIBER --pcap raw/Attack/Message\ Suppression\ \(MS\)/AS3.pcapng.gz --ipal.out ipal/Attack/MS/AS3.ipal.gz --malicious attacks-ms3.json
$TRANSCRIBER --pcap raw/Attack/Message\ Suppression\ \(MS\)/AS4.pcapng.gz --ipal.out ipal/Attack/MS/AS4.ipal.gz --malicious attacks-ms4.json

echo "- CompositeAttack"
$TRANSCRIBER --pcap raw/Attack/CompositeAttack.pcapng.gz --ipal.out ipal/Attack/CompositeAttack.ipal.gz --malicious attacks-composite.json

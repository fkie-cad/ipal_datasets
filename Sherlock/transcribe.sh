#!/usr/bin/env bash

# 01-Basic
ipal-transcriber \
    --protocols iec104 \
    --pcap raw/01-Basic/train.n302.pcap.gz \
    --rules raw/01-Basic/rules.py \
    --malicious ipal/01-Basic/train.events.json \
    --malicious.default false \
    --state.output ipal/01-Basic/train.n302.state.gz \
    --initial_state raw/01-Basic/train.initial_state.json \
    timeslice

ipal-transcriber \
    --protocols iec104 \
    --pcap raw/01-Basic/test.n302.pcap.gz \
    --rules raw/01-Basic/rules.py \
    --malicious ipal/01-Basic/test.events.json \
    --malicious.default false \
    --state.output ipal/01-Basic/test.n302.state.gz \
    --initial_state raw/01-Basic/test.initial_state.json \
    timeslice


# 02-Semiurban
ipal-transcriber \
    --protocols iec104 \
    --pcap raw/02-Semiurban/train.n406.pcap.gz \
    --rules raw/02-Semiurban/rules.py \
    --malicious ipal/02-Semiurban/train.events.json \
    --malicious.default false \
    --state.output ipal/02-Semiurban/train.n406.state.gz \
    --initial_state raw/02-Semiurban/train.initial_state.json \
    timeslice

ipal-transcriber \
    --protocols iec104 \
    --pcap raw/02-Semiurban/test.n406.pcap.gz \
    --rules raw/02-Semiurban/rules.py \
    --malicious ipal/02-Semiurban/test.events.json \
    --malicious.default false \
    --state.output ipal/02-Semiurban/test.n406.state.gz \
    --initial_state raw/02-Semiurban/test.initial_state.json \
    timeslice


# 03-Rural
ipal-transcriber \
    --protocols iec104 \
    --pcap raw/03-Rural/test.n402.pcap.gz \
    --rules raw/03-Rural/rules.py \
    --malicious ipal/03-Rural/test.events.json \
    --malicious.default false \
    --state.output ipal/03-Rural/test.n402.state.gz \
    --initial_state raw/03-Rural/test.initial_state.json \
    timeslice

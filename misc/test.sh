#!/usr/bin/env sh
set -e
cd "$(dirname "$0")/.."

./misc/test.py BATADAL/attacks.json BATADAL/ipal/*

./misc/test.py ELEGANT/attacks_MiTM_ARP_Poisoning_1.json ELEGANT/ipal/MiTM_ARP_Poisoning_1.ipal.gz
./misc/test.py ELEGANT/attacks_MiTM_ARP_Poisoning_2.json ELEGANT/ipal/MiTM_ARP_Poisoning_2.ipal.gz
./misc/test.py ELEGANT/attacks_MiTM_Full_Chain_1.json ELEGANT/ipal/MiTM_Full_Chain_1.ipal.gz
./misc/test.py ELEGANT/attacks_MiTM_Full_Chain_2.json ELEGANT/ipal/MiTM_Full_Chain_2.ipal.gz
./misc/test.py ELEGANT/attacks_MiTM_Full_Chain_3.json ELEGANT/ipal/MiTM_Full_Chain_3.ipal.gz

./misc/test.py HAI/attacks.json HAI/ipal/*

./misc/test.py QUT_S7_Myers/attacks.json QUT_S7_Myers/ipal/AttackDataset/master.ipal.gz

./misc/test.py QUT_S7comm/attacks.json QUT_S7comm/ipal/s7_process_attacks/master.ipal.gz

./misc/test.py SWaT/attacks.json SWaT/ipal/*

./misc/test.py WADI/attacks.json WADI/ipal/*

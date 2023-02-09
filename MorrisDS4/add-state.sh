#!/usr/bin/env bash

# Add state
echo "Adding state to raw"

ipal-state-extractor \
    --ipal.in ipal/IanRawDataset.ipal.gz \
    --state.out - \
    --state-in-message true \
    default | \
tail -n +4 | gzip > ipal/IanRawDataset.state.gz

# Add state
echo "Adding state to arff"
# Ugly replace of activity 0 -> inform and 1 -> interrogate and back
gunzip -c ipal/IanArffDataset.ipal.gz | \
sed s/activity\":\ \"1\"/activity\":\ \"interrogate\"/g | sed s/activity\":\ \"0\"/activity\":\ \"inform\"/g | \
\
ipal-state-extractor \
    --ipal.in - \
    --state.out - \
    --state-in-message true \
    --filter "4:Scaled Gas Pressure;4:control schema;4:system mode;4:pump;4:solenoid;4:PID Setpoint;4:PID Gain;4:PID Reset;4:PID Rate;4:PID Deadband;4:PID Cycle Time" \
    default | \
\
sed s/activity\":\ \"interrogate\"/activity\":\ \"1\"/g | sed s/activity\":\ \"inform\"/activity\":\ \"0\"/g | \
tail -n +4 | gzip > ipal/IanArffDataset.state.gz # Removes the first 4 incomplete states

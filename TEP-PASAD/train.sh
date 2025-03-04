#!/usr/bin/env bash

rm -rf ipal/train.state.gz

for filename in ./ipal/*state.gz; do
    gunzip -c $filename | head -n 4000 >> ipal/train.state
done

gzip ipal/train.state

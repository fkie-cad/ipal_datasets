#!/usr/bin/env bash

# Remove MacOS files
find . -name .DS_Store -print0  | xargs -0 rm -v

# Remove all documentation files
rm -rfv */documentation/*

# Empty all ipal files
find */ipal -type f -print0 | xargs -0 truncate -s 0

# Empty all raw files
find */raw -type f -print0 | xargs -0 truncate -s 0

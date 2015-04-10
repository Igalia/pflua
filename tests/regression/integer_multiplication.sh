#!/bin/bash
# https://github.com/Igalia/pflua/issues/83
# Pflua: large multiplications use floats, leading to different results
# Old, buggy pflua checked against 1588910592
# Modern pflua, and tcpdump, check against 1588910545
./check-compile "405434949 * 1881196573 == 1588910545" true

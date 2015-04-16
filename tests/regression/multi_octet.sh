#!/bin/bash
# https://github.com/Igalia/pflua/issues/139
# Multi-octet packet access is broken
./pflua-pipelines-match ../data/wingolog.pcap "ip[29:2] < 231" 16794

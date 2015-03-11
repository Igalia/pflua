#!/bin/bash
# https://github.com/Igalia/pflua/issues/129
# BPF and pure-lua pipelines diverge on portrange N-M, M<N
./pflua-pipelines-match ../data/wingolog.pcap "portrange 49577-19673" 938

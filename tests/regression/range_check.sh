#!/bin/bash
# https://github.com/Igalia/pflua/issues/120
# Range-checking off-by-one error.

# Make sure the original and badly-optimized IR don't match
! ./pflua-pipelines-match --ir ../data/wingolog.pcap ir_wrongresult_bug120.txt ir_wrongresult_bug120_badopt.txt 11400

# Make sure the original and currently-optimized IR match
./pflua-pipelines-match --ir ../data/wingolog.pcap ir_wrongresult_bug120.txt HEAD 11400

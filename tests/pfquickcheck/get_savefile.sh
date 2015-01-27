#!/bin/bash

URL="https://github.com/Igalia/pflua-test/blob/master/savefiles/wingolog.org.pcap?raw=true"
if [ -f savefiles/wingolog.org.pcap ]; then
    echo "Savefile already exists, not fetching again."
else
    if [ ! -d savefiles ]; then
        mkdir savefiles
    fi
    wget --output-document savefiles/wingolog.org.pcap $URL
fi


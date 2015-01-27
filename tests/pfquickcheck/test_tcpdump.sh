#!/bin/bash

if (tcpdump -d 'len < 3' 2>&1 >/dev/null) ; then
    echo "tcpdump appears to be installed and you can use -d"
else
    echo "Please make sure tcpdump is installed and has enough permissions."
    echo "Under Linux, there are several options, including:"
    echo "a) Running setcap cap_net_raw=ep /usr/sbin/tcpdump"
    echo " (Warning: restrict tcpdump access to one group or anyone can sniff)"
    echo "b) Run as root (not recommend)"
    exit 1
fi


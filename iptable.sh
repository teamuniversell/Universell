#!/bin/bash

iptables --flush
iptables -I OUTPUT -j NFQUEUE --queue-num 0
iptables -I INPUT -j NFQUEUE --queue-num 0

python3 hack.py
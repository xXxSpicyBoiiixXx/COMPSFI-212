"""
==========================================================
Course:    COMPSFI 212 – Scripting for Cybersecurity
Module:    Chapter 1 – Fulfilling Pre-ATT&CK Objectives
Script:    HoneyScan.py
Purpose:   Make a small honeypot for attackers
Author:    Dr. Md Ali
Date:      2025-08-24
Version:   1.0

Description:
    - This will defeat the SYNScan function

Dependencies:
    - Python 3.9+
    - scapy
    - ipaddress

Usage:
    $ python PortScan.py
    Enter IP Address: 8.8.8.8

==========================================================
"""

from scapy.all import *

ip = "172.26.32.1"
ports = [53,80]
honeys = [8080,8443]

blocked = []

def analyzePackets(p):
    global blocked
    if p.haslayer(IP):
        response = Ether(src=p[Ether].dst,dst=p[Ether].src)/\
                IP(src=p[IP].dst,dst=p[IP].src)/\
                   
                   TCP(sport=p[TCP].dport,dport=p[TCP].sport,ack=p[TCP].seq+1)


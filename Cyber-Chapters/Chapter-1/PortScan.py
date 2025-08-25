"""
==========================================================
Course:    COMPSFI 212 – Scripting for Cybersecurity
Module:    Chapter 1 – Fulfilling Pre-ATT&CK Objectives
Script:    PortScan.py
Purpose:   Demonstrates a simple SYN and DNS scan using Python's scapy.
Author:    Dr. Md Ali
Date:      2025-08-23
Version:   1.0

Description:
    - Sends crafted TCP SYN packets to test for open ports
    - Sends DNS queries to identify DNS servers
    - Output lists detected open ports and active DNS services

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
import ipaddress

# Do you know what ports these are?
ports = [25,80,53,443,445,8080,8443]

# What does 'def' mean in the following code?

# Please describe what is going on in SynScan.
def SynScan(host):
    ans,uans = sr(
            IP(dst=host)/
            TCP(sport=33333,dport=ports,flags="S"),timeout=2,verbose=0)
    print("Open ports at %s:" % host)
    for(s,r,) in ans:
        if s[TCP].dport == r[TCP].sport and r[TCP].flags=="SA":
            print(s[TCP].dport)

# Please describe what is going on in DNSScan.
def DNSScan(host):
    ans,uans = sr(
            IP(dst=host)/
            UDP(dport=53)/
            DNS(rd=1,qd=DNSQR(qname="google.com")),timeout=2,verbose=0)
    if ans and ans[UDP]:
        print("DNS Server at %s"%host)

host = input("Enter IP Address: ")
try:
    ipaddress.ip_address(host)
except:
    print("Invalid address")
    exit(-1)

SynScan(host)
DNSScan(host)

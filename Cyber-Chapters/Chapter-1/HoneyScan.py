"""
==========================================================
Course:    COMPSFI 212 – Scripting for Cybersecurity
Module:    Chapter 1 – Fulfilling Pre-ATT&CK Objectives
Script:    HoneyScan.py
Purpose:   Demonstrates a defensive deception technique
           by misleading port scanners.
Author:    Dr. Md Ali
Date:      2025-08-24
Version:   1.0

Description:
    - Listens for inbound TCP SYN packets to a target.
    - If packet is from a "blocked" source:
        * Responds to real ports with RST/ACK (appear CLOSED).
        * Responds to honey ports with SYN/ACK (appear OPEN).
    - If packet is from a new source:
        * Adds it to blocked list if probing a non-real port.
        * Responds to honey ports with SYN/ACK.
    - Intended to confuse attackers and waste their time.

Dependencies:
    - Python 3.x
    - scapy (requires admin/root privileges)

Usage:
    sudo python HoneyScan.py <target_ip> <iface>
==========================================================
"""

from scapy.all import *
import sys

# Command line arguments: target IP, interface
if len(sys.argv) != 3:
    print("Usage: python HoneyScan.py <Target IP> <Interface>")
    sys.exit(1)

target = sys.argv[1]
iface = sys.argv[2]

# Real services
real_services = [53, 80]
# Honey services (appear open to attackers)
honey_services = [8080, 8443]

# Track blocked sources
blocked_sources = []

def analyzePackets(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        if pkt[IP].dst == target and pkt[TCP].flags == "S":
            ip = pkt[IP].src
            tcp = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, ack=(pkt[TCP].seq+1))
            ip_layer = IP(src=pkt[IP].dst, dst=pkt[IP].src)
            ether = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src)
            reply = ether / ip_layer / tcp

            if ip in blocked_sources:
                if pkt[TCP].dport in real_services:
                    reply[TCP].flags = "RA"
                    sendp(reply, iface=iface, verbose=0)
                    print("RST/ACK sent to " + str(ip) + " for real service " + str(pkt[TCP].dport))
                elif pkt[TCP].dport in honey_services:
                    reply[TCP].flags = "SA"
                    sendp(reply, iface=iface, verbose=0)
                    print("SYN/ACK sent to " + str(ip) + " for honey service " + str(pkt[TCP].dport))
            else:
                if pkt[TCP].dport not in real_services:
                    blocked_sources.append(ip)
                if pkt[TCP].dport in honey_services:
                    reply[TCP].flags = "SA"
                    sendp(reply, iface=iface, verbose=0)
                    print("SYN/ACK sent to " + str(ip) + " for honey service " + str(pkt[TCP].dport))

print("HoneyScan is running on " + target + " via interface " + iface)
sniff(filter="tcp and dst host " + target, prn=analyzePackets, iface=iface, store=0)


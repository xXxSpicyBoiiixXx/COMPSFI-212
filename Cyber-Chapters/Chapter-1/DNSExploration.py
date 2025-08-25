"""
==========================================================
Course:    COMPSFI 212 – Scripting for Cybersecurity
Module:    Chapter 1 – Fulfilling Pre-ATT&CK Objectives
Script:    DNSExploration.py
Purpose:   Enumerate common subdomains and follow reverse-DNS links
           to discover related hosts using public DNS.
Author:    Dr. Md Ali
Date:      2025-08-24
Version:   1.0

Description:
    - Uses dnspython to resolve hostnames and collect IPs
    - Uses socket.gethostbyaddr for reverse DNS
    - Recursively explores newly discovered domains
    - Reads candidate subdomains from dns_search.txt

Dependencies:
    - Python 3.x
    - dnspython

Usage:
    python DNSExploration.py
==========================================================
"""

import dns
import dns.resolver
import socket

domains = {}
subs = "dns_search.txt"

res = dns.resolver.Resolver()
res.nameservers = ["8.8.8.8"]
res.port = 53

domain = "google.com"
nums = True

def ReverseDNS(ip):
    try:
        result = socket.gethostbyaddr(ip)
        return [result[0]] + result[1]
    except socket.herror:
        return []

def DNSRequest(domain):
    ips = []
    try:
        result = res.resolve(domain)
        if result:
            addresses = [a.to_text() for a in result]
            if domain in domains:
                domains[domain] = list(set(domains[domain] + addresses))
            else:
                domains[domain] = addresses
            for a in addresses:
                rd = ReverseDNS(a)
                for d in rd:
                    if d not in domains:
                        domains[d] = [a]
                        DNSRequest(d)
                    else:
                        domains[d] = [a]
    except (dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoAnswer):
        return []
    return ips

def HostSearch(domain, dictionary, nums):
    successes = []
    for word in dictionary:
        d = word + "." + domain
        DNSRequest(d)
        if nums:
            for i in range(0, 10):
                s = word + str(i) + "." + domain
                DNSRequest(s)

dictionary = []
with open(subs, "r") as f:
    dictionary = f.read().splitlines()

HostSearch(domain, dictionary, nums)

for domain in domains:
    print("%s: %s" % (domain, domains[domain]))


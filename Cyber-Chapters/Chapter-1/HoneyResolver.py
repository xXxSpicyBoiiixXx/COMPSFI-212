"""
==========================================================
Course:    COMPSFI 212 – Scripting for Cybersecurity
Module:    Chapter 1 – Fulfilling Pre-ATT&CK Objectives
Script:    HoneyResolver.py
Purpose:   Minimal DNS deception resolver (book-style)
Author:    Dr. Md Ali
Date:      2025-08-24
Version:   1.0
==========================================================
"""

from dnslib import DNSRecord, RR, QTYPE, A
from dnslib.server import DNSServer
import time

host = "localhost"
port = 8053

subdomains = {
    "www.":  "10.0.0.1",
    "smtp.": "10.0.0.2",
}

domain  = "example.com"
honeyip = "10.0.0.0"

class HoneyResolver:
    def resolve(self, request, handler):
        # qname like "www.example.com."
        qname = str(request.q.qname).rstrip(".")
        # If it ends with the domain, extract the leading label part (e.g., "www.")
        if qname == domain:
            sub = ""  # root of zone
        elif qname.endswith("." + domain):
            sub = qname[: -(len(domain) + 1)] + "."
        else:
            sub = ""  # outside domain; still answer with honey (per simple textbook logic)

        reply = request.reply()
        ip = subdomains.get(sub, honeyip)
        reply.add_answer(RR(
            rname=request.q.qname,
            rtype=QTYPE.A,
            rclass=1,
            ttl=300,
            rdata=A(ip)
        ))
        return reply

resolver = HoneyResolver()
server = DNSServer(resolver, port=port, address=host)
server.start_thread()

try:
    while True:
        time.sleep(5)
except KeyboardInterrupt:
    pass


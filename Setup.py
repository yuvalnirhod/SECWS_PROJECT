#!/usr/bin/env python2


import os


os.system("rmmod firewall.ko")
os.system("insmod firewall.ko")
os.system("./main load_rules Rules2")
os.system("python3 run_usr_space_programs.py")


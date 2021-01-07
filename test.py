#!/usr/bin/env python2
import sys
import os
from scapy.all import IP, TCP, UDP, send, Raw


def send_xmas_packet(sport, dport, ip):
    # Create the skeleton of our packet
    template = IP(dst=ip)/TCP()

    # Start lighting up those bits!
    template[TCP].flags = 'UFP'

    # Create a list with a large number of packets to send
    # Each packet will have a random TCP dest port for attack obfuscation
    xmas = []
    for pktNum in range(0,1):
        xmas.extend(template)
        xmas[pktNum][TCP].sport = sport
        xmas[pktNum][TCP].dport = dport
    # Send the list of packets
    send(xmas)

def send_tcp_ack(sport, dport, ip):
    # Create the skeleton of our packet
    template = IP(dst=ip)/TCP()

    # Start lighting up those bits!
    template[TCP].flags = 'A'

    # Create a list with a large number of packets to send
    # Each packet will have a random TCP dest port for attack obfuscation
    xmas = []
    for pktNum in range(0,1):
        xmas.extend(template)
        xmas[pktNum][TCP].sport = sport
        xmas[pktNum][TCP].dport = dport

    # Send the list of packets
    send(xmas)


def send_tcp(sport, dport, ip):
    # Create the skeleton of our packet
    template = IP(dst=ip)/TCP()

    # Start lighting up those bits!
    template[TCP].flags = 'S'

    # Create a list with a large number of packets to send
    # Each packet will have a random TCP dest port for attack obfuscation
    xmas = []
    for pktNum in range(0,1):
        xmas.extend(template)
        xmas[pktNum][TCP].sport = sport
        xmas[pktNum][TCP].dport = dport

    # Send the list of packets
    send(xmas)

def send_udp(sport, dport, ip):
    # Create the skeleton of our packet
    template = IP(dst=ip)/UDP(dport=dport,sport=sport)/Raw(load="Reuven Hamelech")
    send(template)

def send_icmp(ip, count=3):
    os.system("ping " +ip +" -c " +str(count) + " -w 5")

Rules_path = "Rules"
mode = sys.argv[1]
dir = ""
ip = ""
if mode == "c":
    dir = "out"
    ip = "10.1.2.2"
else:
    dir = "in"
    ip = "10.1.1.1"


with open(Rules_path, 'r') as rules:
    send_xmas_packet(4000, 8000, ip)

    line=rules.readline()
    i = 0
    while (line):
        i = i + 1
        Arr = line.split(" ")
        if (Arr[1] == "any" or Arr[1] == dir):
            
            sport = 0
            if (Arr[5] == ">1023"):
                sport = 1024
            elif (Arr[5] == "any"):
                sport = 2000
            else:
                sport = int(Arr[5])

            dport = 0
            if (Arr[6] == ">1023"):
                dport = 1024
            elif (Arr[6] == "any"):
                dport = 2000
            else:
                dport = int(Arr[6])
            
            Prot = Arr[4]
            if (Prot == "TCP"):
                if (Arr[7] == "yes"):
                    send_tcp_ack(sport,dport,ip)
                elif (Arr[7] == "no"):
                    send_tcp(sport,dport,ip)
                else:
                    send_tcp_ack(sport,dport,ip)
                    send_tcp(sport,dport,ip)

            elif (Prot == "ICMP"):
                send_icmp(ip)

            elif (Prot == "UDP"):
                send_udp(sport,dport,ip)

            else:
                send_tcp_ack(sport,dport,ip)
                send_tcp(sport,dport,ip)
                send_icmp(ip)
                send_udp(sport,dport,ip)
        line=rules.readline()
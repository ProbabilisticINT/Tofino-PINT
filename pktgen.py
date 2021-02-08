#!/usr/bin/env python

#from scapy.all import send, IP, ICMP
from scapy.all import *
import random


pktID = random.randint(1,1000)
pkt = Ether()/IP(src="10.0.0.101",dst="10.0.0.102",id=pktID,ttl=255)

print("Sending packet", pkt)
sendp(pkt, iface="enp4s0f0")

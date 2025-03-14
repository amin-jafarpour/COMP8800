from scapy.all import IP, ICMP, sr1
import ipaddress
from inet import Inet 

class ICMP:
    @staticmethod
    def ping_device(iface:str, dst:str, timeout:int=2):
        pkt = IP(dst=dst) / ICMP() 
        reply = sr1(pkt, timeout=timeout, verbose=False)
        return reply

    @staticmethod 
    def ping_subnet(iface:str, single_timeout:int):
        subnet = Inet.get_net_cidr(iface=iface)
        hosts = ipaddress.ip_network(subnet, strict=False).hosts()
        replies = []
        for dst in hosts:
            reply = ICMP.ping_device(dst, single_timeout)
            replies.append(reply)
        return reply











# Pinging via ICMP$

# Port scaning: single, range, list of ports. 

# Aggressive Scaning: OS detection, version detection, script scanning, and traceroute.

# Service scaning and service version scaning. 

# TCP ACK Scan

# SYN Scan


#  Nmap Scripting Engine (NSE) for CVEs and miscongurations? 
#nmap --script vuln <target>

# Open Proxy Servers? 

# SMB Shares? 

# Exploits scanning?

# Traceroute Scan

# DNS scanning 

# Decoy Scan?

# ARP poisoning

# Heartbleed Vulnerability? 

# EternalBlue Vulnerability?

#Randomizes source IP 

#Randomizes source MAC

#SYN Flood Attack

# UDP Flood Attack

# ICMP  Flood Attack

# FIN Scan





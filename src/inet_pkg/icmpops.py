import ipaddress
from inet import Inet 

from scapy.all import IP, ICMP, sr1, traceroute, srflood



# Aggressive Scaning: OS detection, service/version detection, script scanning, and traceroute.
# ARP poisoning
#Randomizes source IP 
#Randomizes source MAC
# ICMP  Flood Attack

# ICMP 	Router Advertisement	Router advertises itself.







#  Nmap Scripting Engine (NSE) for CVEs and miscongurations? 
#nmap --script vuln <target>

# Open Proxy Servers? 
# SMB Shares? 
# Exploits scanning?
# Decoy Scan?
# Heartbleed Vulnerability? 
# EternalBlue Vulnerability?



class ICMPOps:
    @staticmethod
    def ping(iface:str, dst:str, timeout:int=2):
        pkt = IP(dst=dst) / ICMP() 
        reply = sr1(pkt, iface=iface, timeout=timeout, verbose=False)
        return reply

    @staticmethod 
    def ping_subnet(iface:str, single_timeout:int=2):
        subnet = Inet.get_net_cidr(iface=iface)
        hosts = ipaddress.ip_network(subnet, strict=False).hosts()
        replies:dict = {} 
        for addr_obj in hosts:
            dst = str(addr_obj)
            reply = ICMPOps.ping(iface=iface,dst=dst, timeout=single_timeout)
            replies[dst] = reply 
        return reply



    @staticmethod
    def echo_req_flood(iface:str, dst:str, timeout:int=5):
        # ICMP echo request by default.
        pkt = IP(dst=dst) / ICMP()  
        # "not ip and not arp" is BPF filter to discard responses at kernel level.
        srflood(pkt, iface=iface, timeout=timeout, verbose=False, filter='not ip and not arp')
        
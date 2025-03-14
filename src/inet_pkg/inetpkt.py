from scapy.all import IP, ICMP, sr1, TCP, send, RandShort, traceroute
import ipaddress
from inet import Inet 

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
    def traceroute(iface:str, dst:str, max_hops:int=30, dport:int=80):
        res, _ = traceroute(target=dst, iface=iface, maxttl=max_hops, dport=dport, verbose=False)
        hops = []
        index_counter = 1
        start_time = None
        for snd, rcv in res:
            if start_time is None:
                start_time = rcv.time
            hop_ip = rcv.src if rcv else "*"
            hops.append(f'{index_counter} \t{hop_ip}\t{(rcv.time - start_time) * 1000:.4f}ms')
            index_counter = index_counter + 1
        hops = ['Index   IP Hop\tTime'] + hops
        return '\n'.join(hops)



class TCPOps:
    @staticmethod
    def syn_scan(iface:str, dst:str, dport:int, timeout:int=2):
        pkt = IP(dst=dst) / TCP(dport=dport, flags="S")
        reply = sr1(pkt, iface=iface, timeout=timeout, verbose=False)
        if reply is None:
            return {'state': 'filtered', 'reply': reply}
        if reply.haslayer(TCP):
            tcp_layer = reply.getlayer(TCP)
            # 0x12: SYN-ACK (open)
            if tcp_layer.flags == 0x12:
                # Send RST to gracefully close the connection
                rst_pkt = IP(dst=dst) / TCP(dport=dport, flags="R", ack=tcp_layer.seq + 1)
                send(rst_pkt, iface=iface, verbose=False)
                return {'state': 'open', 'reply': reply}
            # 0x14: RST-ACK (closed)
            elif tcp_layer.flags == 0x14:
                return {'state': 'closed', 'reply': reply}
        return {'state': 'unknown', 'reply': reply}


    # Incomplete
    @staticmethod      
    def os_scan(iface:str, dst:str, single_timeout:int=2):
        # TTL ~64 often indicates Linux/Unix.
        # TTL ~128 typically suggests Windows.
        # TTL >128 may indicate Cisco/Solaris.
        port_range = RandShort()
        ports = {}
        for dport in range(port_range.min, port_range.max + 1):
            ports[port] = TCPOps.syn_scan(iface=iface, dst=dst, dport=dport, timeout=single_timeout)
        for dport, port_info in ports.items():
            pass 
            # Infer OS here
            #ttl = tcp_layer.ttl 
            #win = tcp_layer.window

    # Incomplete
    @staticmethod
    def service_scan():
        pass 















# Pinging via ICMP $

# Port scaning: single, range, list of ports. $ 

# Aggressive Scaning: OS detection, version detection, script scanning, and traceroute.

# Service scaning and service version scaning. 

# TCP ACK Scan

# SYN Scan $ 


#  Nmap Scripting Engine (NSE) for CVEs and miscongurations? 
#nmap --script vuln <target>

# Open Proxy Servers? 

# SMB Shares? 

# Exploits scanning?

# Traceroute Scan $ 

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





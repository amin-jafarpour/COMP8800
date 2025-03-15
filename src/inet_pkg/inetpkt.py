from scapy.all import IP, ICMP, sr1, TCP, send, RandShort, traceroute, DNS, DNSQR, UDP
import ipaddress
from inet import Inet 

# scapy.all.srploop(
# scapy.all.srpflood(
# scapy.all.srp1flood(
# scapy.all.srflood(     
# scapy.all.sr1flood(

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
        hops = ['Index   IP Hop\t\tTime'] + hops
        return '\n'.join(hops)



class TCPOps:
    @staticmethod
    def syn_scan(iface:str, dst:str, dport:int, timeout:int=2):
        pkt = IP(dst=dst) / TCP(dport=dport, flags="S")
        reply = sr1(pkt, iface=iface, timeout=timeout, verbose=False)
        if reply is None:
            return {'state': 'unknown', 'reply': reply}
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
        else:
            return {'state': 'unknown', 'reply': reply}


    @staticmethod
    def ack_scan(iface:str, dst:str, dport:int, timeout:int=2):
        # An ACK scan determines whether a firewall is filtering packets 
        # by sending TCP packets with the ACK flag set to different ports.
        # It determines which ports are filtered or unfiltered.
        # If an unfiltered port receives an ACK packet, 
        # it responds with an RST (reset) packet.
        # If a filtered port is behind a firewall, 
        # there will be no response or an ICMP unreachable message.
        pkt = IP(dst=dst) / TCP(dport=dport, flags="A")
        reply = sr1(pkt, iface=iface, timeout=timeout, verbose=False)
        if pkt is None: 
            return {'state': 'filtered', 'reply': None}
        elif pkt.haslayer(TCP) and pkt.getlayer(TCP).flags & 0x14: # 0x14: RST
            return {'state': 'unfiltered', 'reply': reply}
        elif reply.haslayer(ICMP): # ICMP unreachable msg
            return {'state': 'filtered', 'reply': reply}
        else:
            return {'state': 'unknown', 'reply': reply}

    
    @staticmethod
    def fin_scan(iface:str, dst:str, dport:int, timeout:int=2):
        # FIN packet is sent to a closed port, the target should respond with a RST packet, 
        # while an open port typically produces no response. 
        # This behavior allows the scanner to infer the state of the port.
        # Although note that some operating systems (such as Windows) may handle FIN packets 
        # differently, often returning a RST regardless of the port state.

        pkt = IP(dst=dst) / TCP(dport=dport, flags="F")
        reply = sr1(pkt, timeout=timeout, verbose=False)
        if reply is None:
            return {'state': 'open|unknown', 'reply': None} 
        elif reply.haslayer(TCP):
            tcp_layer = reply.getlayer(TCP)
            if tcp_layer.flags & 0x04: #  0x04: RST flag
                return {'state': 'closed', 'reply': reply} 
            else: 
                return {'state': 'unknown', 'reply': reply} 
        # ICMP indicate filtering or unreachable ports
        elif reply.haslayer("ICMP"):
            return {'state': 'filtered', 'reply': reply} 
        return  {'state': 'unknown', 'reply': None} 







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




class UDPOps:
    # Type A: Address Record, maps a domain name to an IPv4 address.
    A_RD_TYPE:str = 'A'
    # Type AAAA: Quad A Record, maps a domain name to an IPv6 address.
    AAAA_RD_TYPE:str = 'AAAA'
    # Type MX: Mail Exchange Record, specifies the mail servers.
    MX_RD_TYPE:str = 'MX'
    # Type NS: Name Server Record, Specifies the authoritative name servers for a domain.
    NS_RD_TYPE:str = 'NS'
    # Type SOA: Start of Authority Record, contains admin info, e.g., primary name server and last update timestamp.
    SOA_RD_TYPE:str = 'SOA'
    # Type TXT: Text Record, Stores arbitrary text for verification and security purposes.
    TXT_RD_TYPE:str = 'TXT'
    
    @staticmethod
    def dns_scan(iface:str, dst:str, qname:str, dport:int=53, qtype:str=A_RD_TYPE, timeout:int=2):
        # RD (Recursion Desired): Is a flag use to  perform a recursive query, where 
        # DNS server to fully resolve the query instead of referring the client to another DNS server.
        # QD (Query Domain): Refers to the Query Section of a DNS message. It contains the details 
        # of the domain name being queried, including the type of record requested 
        # (A, MX, TXT, etc.) and the class (typically IN for internet).

        # "qname" is domian name and "qtype" is record type.
        pkt = IP(dst=dst) / UDP(dport=dport) / DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype)) 
        reply = sr1(pkt, iface=iface, timeout=timeout, verbose=False)
        if reply is None: 
            return {'msg': 'No response recevied for query', 'addresses': [], 'reply': None} 
        if reply.haslayer(DNS):
            dns_layer = reply.getlayer(DNS)
            # "ancount" stands for "Answer Count", which indicates the number of 
            # resource records (RRs) in the Answer Section of a DNS response.
            if dns_layer.ancount == 0:
                return {'msg': 'No records found.', 'addresses': [], 'reply': reply}
            else: 
                addresses = []
                for i in range(dns_layer.ancount):
                    addresses.append(dns_layer.an.rdata)
                return {'msg': 'Records found.', 'addresses': addresses, 'reply': reply}
    

    @staticmethod
    def udp_scan(iface:str, dst:str, dport:int, timeout:int=2):
        # No response: Port is classified as open or filtered.
        # ICMP response with type 3 and code 3: Port is closed.
        # Other ICMP messages (e.g., type 3 with codes 1, 2, 9, 10, 13): Typically indicate filtering. 
        pkt = IP(dst=dst) / UDP(dport=dport)
        reply = sr1(pkt, timeout=timeout, verbose=False)
        if reply is None: 
            return {'state': 'open|filtered', 'reply': reply} 
        if reply.haslayer(ICMP):
             icmp_layer = reply.getlayer(ICMP)
             # Check for "destination unreachable - port unreachable" message.
             if icmp_layer.type == 3 and icmp_layer.code == 3:
                return {'state': 'closed', 'reply': reply} 
            # Other ICMP codes can indicate filtering.
            elif icmp_layer.type == 3 and icmp_layer.code in [1, 2, 9, 10, 13]:
                return {'state': 'filtered', 'reply': reply} 
        # Receiving a UDP response (rare) can be interpreted as an open port.
        if response.haslayer(UDP):
            return {'state': 'open', 'reply': reply} 
        return {'state': 'unknown', 'reply': reply}


































# Pinging via ICMP $

# Port scaning: single, range, list of ports. $ 

# FIN Scan $ 

# TCP ACK Scan $ 

# SYN Scan $ 

# Traceroute Scan $ 

# DNS scanning $ 



# Aggressive Scaning: OS detection, service/version detection, script scanning, and traceroute.



#  Nmap Scripting Engine (NSE) for CVEs and miscongurations? 
#nmap --script vuln <target>

# Open Proxy Servers? 

# SMB Shares? 

# Exploits scanning?



# Decoy Scan?

# ARP poisoning

# Heartbleed Vulnerability? 

# EternalBlue Vulnerability?

#Randomizes source IP 

#Randomizes source MAC

#SYN Flood Attack

# UDP Flood Attack

# ICMP  Flood Attack



# christmas flood 





from scapy.all import IP,sr1, TCP, send, RandShort, DNS, DNSQR, Raw, srflood

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

    
    @staticmethod
    def syn_flood(iface:str, dst:str, dport:int, timeout:int=2):
        pkt = IP(dst=dst) / TCP(dport=dport, flags="S")
        # "not ip and not arp" is BPF filter to discard responses at kernel level.
        srflood(pkt, iface=iface, timeout=timeout, verbose=False, filter='not ip and not arp') 

    @staticmethod 
    def xmas_flood(iface:str, dst:str, dport:int, timeout:int=5):
        # An Xmas TCP packet has all flags set: FIN, SYN, RST, PSH, ACK, URG.
        pkt = IP(dst=dst) / TCP(dport=dport, flags="FSRPAU")
        # "not ip and not arp" is BPF filter to discard responses at kernel level.
        srflood(pkt, iface=iface, timeout=timeout, verbose=False, filter='not ip and not arp')








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




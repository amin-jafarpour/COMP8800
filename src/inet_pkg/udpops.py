from scapy.all import IP,sr1, UDP, Raw, srflood



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
    
    @staticmethod
    def udp_flood(iface:str, dst:str, dport:int, timeout:int=5):
        pkt = IP(dst=dst) / UDP(dport=dport) / Raw('heey')
        # "not ip and not arp" is BPF filter to discard responses at kernel level.
        srflood(pkt, iface=iface, timeout=timeout, verbose=False, filter='not ip and not arp')


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






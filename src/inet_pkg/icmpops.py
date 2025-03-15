import ipaddress
from inet import Inet 

from scapy.all import IP, ICMP, sr1, traceroute, srflood




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
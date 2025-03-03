"""
Inet.py

This module provides functionality to interact with Internet. Functionalities such as packet construction, arp scan, network scan
and such. 

:author: Amin Jafarpour
:version: 1.0
:license: GPL
"""


import subprocess 
import scapy.all as scap 



class Inet:
    @staticmethod
    def get_cidr(iface:str):
        # runs bash cmd -> ip addr show wlp164s0  | grep -oP 'inet \K[\d.]+/\d+'
        ip_result = subprocess.run(['ip', 'addr', 'show', iface], capture_output=True, text=True)
        lines = ip_result.stdout.splitlines()
        trimmed_lines = list(map(lambda x: x.strip(), lines))
        items = map(lambda x: x if x.startswith('inet ') else None, trimmed_lines)
        inet_line = list(filter(lambda x: x != None, items))[0]
        cidr = inet_line.split()[1]
        return cidr
    
    @staticmethod
    def get_net_cidr(iface:str):
        cidr_str = Inet.get_cidr(iface)
        parts_lst = cidr_str.split('.')
        last_part = parts_lst[3]
        mask_str = last_part.split('/')[1]
        net_cidr_str = '.'.join(parts_lst[:3] + ['0']) + '/' + mask_str
        return net_cidr_str
    
    @staticmethod
    def get_ip_mac(iface:str):
        net_cidr_str = Inet.get_net_cidr(iface)
        ip_mac:dict = {}
        answered, _ = scap.arping(net_cidr_str, verbose=False)
        for _, received in answered:
            ip_mac[received.hwsrc] = received.psrc
        return ip_mac
        
        
    
   
    
   

    

        
    


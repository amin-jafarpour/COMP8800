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
    """
    
    A class representing Internet.
    """
    @staticmethod
    def get_cidr(iface:str):
        """
        
        Returns Classless Inter-Domain Routing (CIDR) address of default gateaway connected to `iface` 
        network interface adaptor.
        
        :param iface: Network Interface Adapter Name.
        :type iface: str
        
        :return: CIDR of default gateaway
        :rtype: str
        """

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
        """
        
        Returns Classless Inter-Domain Routing (CIDR) address of network `iface` network interface adaptor is connected to.
        
        :param iface: Network Interface Adapter Name.
        :type iface: str
        
        :return: CIDR of network
        :rtype: str
        """
        cidr_str = Inet.get_cidr(iface)
        parts_lst = cidr_str.split('.')
        last_part = parts_lst[3]
        mask_str = last_part.split('/')[1]
        net_cidr_str = '.'.join(parts_lst[:3] + ['0']) + '/' + mask_str
        return net_cidr_str
    
    @staticmethod
    def get_ip_mac(iface:str):
        """
        
        Returns a dictionary where keys are MAC addresses of devices connected to network and values are
        IPv4 addresses of devices associated with MAC addresses. 
        

        :param iface: Network Interface Adapter Name.
        :type iface: str

        :return: MAC-IP bindings where keys are MAC addresses and values are IPv4 addresses associated with MAC addresses. 
        :rtype: dict
        """
        net_cidr_str = Inet.get_net_cidr(iface)
        ip_mac:dict = {}
        answered, _ = scap.arping(net_cidr_str, verbose=False)
        for _, received in answered:
            ip_mac[received.hwsrc] = received.psrc
        return ip_mac
        
        
    @staticmethod
    def layers_fields(pkt):
        """
        Returns dictionary where keys are layer names and values are lists of dictionaries 
        where keys are field names and values are field values of each layer.
    
        :param pkt: Packet
        :type pkt: 
                
        Returns:Returns dictionary where each key is layer name and each value is  
                list containing field and field value dictionaries.
                {"layer": [{"field1": "value1"}, ...], ...}
                
        :rtype: dict
        """
        # List of all available Layers of packet `pkt`
        layers:list = [layer.__name__ for layer in pkt.layers()]
        # Dict where key is layer name and value is list of dict where 
        # key is field name and value is field value
        layer_fields:dict = {}
        # For each layer,
        for layer in layers:
            # List of dict where key is field name and value is field value.
            fields_lst:list = []
            for field in pkt[layer].fields:
            # For each field of current layer,
               fields_lst.append({field: pkt[layer].getfieldval(field)})
            layer_fields[layer] = {layer: fields_lst}
        return layer_fields











def process_packet(pkt, discovered_networks, limit):
   if pkt.haslayer(Dot11) and len(discovered_networks) < limit:

      bssid = pkt[Dot11].addr2
      if bssid != None and  bssid not in discovered_networks:
         pkt_info = bundle(pkt)
         discovered_networks[bssid] = pkt_info







def discover_networks(iface:str, limit:int):
    discovered_networks = {}
    while (len(discovered_networks) < limit):
        scap.sniff(iface=iface, count=limit, store=False, prn=lambda pkt: process_packet(pkt, discovered_networks, limit))
    return discovered_networks
   
    
   
  

        
    


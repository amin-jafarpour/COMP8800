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
    
    IFACE_MONITOR_MODE:str = 'monitor'
    IFACE_MANAGED_MODE:str = 'managed'
    
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
        # Rin bash cmd: ip addr show wlp164s0  | grep -oP 'inet \K[\d.]+/\d+'
        ip_result = subprocess.run(['ip', 'addr', 'show', iface], capture_output=True, text=True)
        # Split lines of output
        lines = ip_result.stdout.splitlines()
        # Trim each line of output
        trimmed_lines = list(map(lambda x: x.strip(), lines))
        # Find lines starting with "inet " token
        items = map(lambda x: x if x.startswith('inet ') else None, trimmed_lines)
        # Extract the first line match
        inet_line = list(filter(lambda x: x != None, items))[0]
        # Tokenize the line and extract the second token
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
        # Fetch default gateaway's address in CIDR notation
        cidr_str = Inet.get_cidr(iface)
        # Split the address by dot
        parts_lst = cidr_str.split('.')
        # Extract the first three parts
        last_part = parts_lst[3]
        # Extract netmask number from fourth part
        mask_str = last_part.split('/')[1]
        # Reassmble the parts replacing the fourth part by zero and append netmask 
        # at the end
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
        # Get CIDR address of network
        net_cidr_str = Inet.get_net_cidr(iface)
        # Stores MAC-IP bindings
        ip_mac:dict = {}
        # Send ARP request
        answered, _ = scap.arping(net_cidr_str, verbose=False)
        # For each packet reply received,
        for _, received in answered:
            # Store MAC-IP binding
            ip_mac[received.hwsrc] = received.psrc
        return ip_mac
        
        
    @staticmethod
    def layers_fields(pkt):
        """
        Returns dictionary where keys are layer names and values are lists of dictionaries 
        where keys are field names and values are field values of each layer.
    
        :param pkt: Packet
        :type pkt: 
                
        :return:Returns dictionary where each key is layer name and each value is  
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


    @staticmethod
    def iface_mpde(iface:str, mode:str):
        """

        """
        cmds = [
            ["sudo", "ip", "link", "set", iface, "down"],
            ["sudo", "iw", "dev", iface, "set", "type", mode],
            ["sudo", "ip",  "link", "set", iface, "up"]
        ]
        try:
            for cmd in cmds:
               subprocess.run(cmd, check=True, text=True)
        except subprocess.CalledProcessError as e:
            print(f"Error: {e}")



    @staticmethod
    def discover_networks(iface:str, net_count:int):
        """
        
        Discovers nearby networks reachable and extracts information about such networks. 
        NOTE: The given `iface` network interface card must support monitor mode and is
              put into monitor mode while sniffing for packets. 
        
        :param iface: Name of metwork interface card name to sniff from.
        :type iface: str
        :param net_count: Number of networks to discover. 
        :type net_count: int
        
        :return: Returns dictionary where keys are BSSID of network AP and values are
                 various layers' fields. 
        """
        discovered_networks:dict = {}
        
        # Inner function to process each packet received
        def handle_pkt(pkt, network_acc:dict, net_count:int):
            # If received packet has IEEE 802.11 layer and network count has not been reached,
            if pkt.haslayer(scap.Dot11) and len(network_acc) < net_count:
                # Store BSSID of sender of packet
                bssid = pkt[scap.Dot11].addr2
                # If BSSID is not none and iff according to BSSID sender is no already recorded,
                if bssid != None and  bssid not in network_acc:
                    # Extract fields of packet by packet layers
                    pkt_data:dict = Inet.layers_fields(pkt)
                    # Store sender's BSSID as key and various layer fields are value
                    network_acc[bssid] = pkt_data
        # While network count has not been reached,
        while (len(discovered_networks) < net_count):
            # Sniffing for packets
            scap.sniff(iface=iface, count=net_count, store=False,
                    prn=lambda pkt: handle_pkt(pkt, discovered_networks, net_count))
            
        return discovered_networks



def extract_fields(data, keys, result=None, duplicates=0):
    keys = list(map(lambda x: x.lower(), keys))
    
    if result is None:
        result = {}

    if isinstance(data, dict):
        for key, value in data.items():
            if key.lower() in keys:
                if key.lower() in result:
                    duplicates = duplicates + 1
                    result[key.lower() + str(duplicates)] = value
                else:
                    result[key] = value  # Store the value
            extract_fields(value, keys, result, duplicates)  # Recursive call

    elif isinstance(data, list):
        for item in data:
            extract_fields(item, keys, result, duplicates)  # Recursive call

    return result




def get_network_lst(iface, pkt_count):
    change_mode(iface, 'monitor')
    networks = discover_networks(iface, pkt_count)
    network_lst = []
    for key, value in networks.items():
        res = extract_fields(value, ESSENTIAL_FIEDS)
        network_lst.append(res)
    change_mode(iface, 'managed')
    return network_lst



        














    
   
  

        
    


"""
Inet.py

This module provides functionality to interact with Internet. Functionalities such as packet construction, arp scan, network scan
and such. 

NOTE: Only compatiable with Linux and requires `ip` and `iw` Linux commands to work.

:author: Amin Jafarpour
:version: 1.0
:license: GPL
"""

import subprocess 
import scapy.all as scap
import ipaddress
import random


# scap.conf.ifaces 
# scap.conf.iface 


class Inet:
    """
    
    A class representing Internet.
    """
    
    IFACE_MONITOR_MODE:str = 'monitor'
    IFACE_MANAGED_MODE:str = 'managed'
    NETWORK_FIEDS:list = ['BSSID', 'addr1', 'addr2', 'addr3', 'country_string', 'num_channels', 
                       'dBm_AntSignal', 'rates', 'ChannelFrequency', 'rate', 'info']
    
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
    def iface_mode(iface:str, mode:str):
        """
        Puts `iface` network interface adaptor into `mode` mode.
        
        :param iface: Name of network interface adaptor to put into `mode` mode.
                      Can be set to `Inet.IFACE_MONITOR_MODE`, `Intet.IFACE_MANAGED_MODE`
        :type iface: str 
        :param mode: Mode to put `iface` network interface adaptor into.
        :type mode: str
        
        :return: N/A
        :rtype: None
        """
        # Runs the following shell cmds:
        #    sudo ip link set `iface` down
        #    sudo iw dev dev `iface` set type `mode`
        #    sudo ip link set `iface` up
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
    def gather_net_data(iface:str, net_count:int, timeout:int):
        """
        
        Discovers nearby networks reachable and extracts information about such networks. 
        NOTE: The given `iface` network interface card must support monitor mode and is
              put into monitor mode while sniffing for packets. 
        
        :param iface: Name of metwork interface card name to sniff from.
        :type iface: str
        :param net_count: Number of networks to discover. 
        :param timeout: timeout in seconds after which it stops sniffing packets. 
        :type timeout: int
        :type net_count: int
        
        :return: Returns dictionary where keys are BSSID of network AP and values are
                 various layers' fields. 
        """
        # Stores BSSID of AP as keys and various layers' fields as values.
        discovered_networks:dict = {}
        # Put `iface` into monitor mode
        Inet.iface_mode(iface, Inet.IFACE_MONITOR_MODE)
        
        # Inner function to process each packet received
        def handle_pkt(pkt, network_acc:dict):
            # If received packet has IEEE 802.11 layer,
            if pkt.haslayer(scap.Dot11):
                # Store BSSID of sender of packet
                bssid = pkt[scap.Dot11].addr2
                # If BSSID is not none and iff according to BSSID sender is no already recorded,
                if bssid != None and  bssid not in network_acc:
                    # Extract fields of packet by packet layers
                    pkt_data:dict = Inet.layers_fields(pkt)
                    # Store sender's BSSID as key and various layer fields are value
                    network_acc[bssid] = pkt_data
        # sniff for `timeout` seconds on `iface` interface hoping to capture `net_cout` packets. 
        scap.sniff(iface=iface, timeout=timeout, count=net_count, store=False,
                    prn=lambda pkt: handle_pkt(pkt, discovered_networks))
            
        # Put `iface` back into managed mode
        Inet.iface_mode(iface, Inet.IFACE_MANAGED_MODE)
        return discovered_networks


    @staticmethod
    def extract_net_fields(structure, field_keys:list, acc:dict=None, duplicates:dict=None):
        """
        
        Recursive function traversing nested lists and dictionaries, extracting dictionary key-value pairs 
        whose key is present in `field_keys`.
        
        :param structure: A nested dictionary or list containing other dictionaries and list.
        :param field_keys: A list containing names of fields to extract. 
        :type field_keys: list
        :param acc: Dictionary accumulating fields present in `field_keys`
        :type acc: dict 
        NOTE: Ensure that all string values names in field_keys are all lowercase. 
        :param duplicates: Stores count index of duplicates to be appended to duplicate field names.
        :type duplicates: dict
        
        :return: Returns a dictionary of fields indicated by `field_keys` if they are present in `structure`
        :rtype: dict
        """
        # if either `acc` or `duplicates` is None, set them to empty dict
        if acc is None:
            acc = {}
            field_keys = list(map(lambda x: x.lower(), field_keys))
        if duplicates is None:
            duplicates = {}

        # If structure is a dict, 
        if isinstance(structure, dict):
            # Traverse key-value pairs of dict,
            for key, value in structure.items():
                # If current key is in `field_keys`,
                if key.lower() in field_keys:
                    # Check whether current key already exists in `acc`,
                    if key.lower() in acc:
                        # If so, add it to `duplicates` dict starting with count 2
                        # get(key.lower(), 1) + 1 in case if key intitialy not in dict
                        duplicates[key.lower()] = duplicates.get(key.lower(), 1) + 1
                    # Add field to `acc`
                    # duplicates.get(key.lower(), "") so if field occured for first time
                    # no index gets appended at the end of field key name
                    acc[key.lower() + str(duplicates.get(key.lower(), ""))] = value
                # Recursive call to get to next inner layer
                Inet.extract_net_fields(value, field_keys, acc, duplicates) 

        # If structure is a list, 
        elif isinstance(structure, list):
            # For each item in list, 
            for item in structure:
                # Recursive call to get to next inner layer
                Inet.extract_net_fields(item, field_keys, acc, duplicates) 

        # If structure is any value other than list or dict or if traversed all layers, return `acc`
        return acc


    @staticmethod
    def scan_networks(iface:str, net_count:int, timeout:int):
        """
        
        Scans neatby networks and returns infomation about them.
        
        :param iface: Network interface adaptor to use to scan for networks, which will be put in monitor mode and then
        back to managed mode. 
        :type iface: str
        :param net_count: Number of networks to scan.
        :type net_count: int
        :param timeout: timeout in seconds after which it stops sniffing packets. 
        :type timeout: int
        
        :return: A list containing dictionaries where each dictionary represents a networks' information. 
        :rtype: list
        """
        # Gather data for a total of `net_count` networks
        net_data = Inet.gather_net_data(iface, net_count, timeout)
        # Stores a dictionary for every network keys are field names and values are field values
        net_lst = []
        # For each network,
        for _, value in net_data.items():
            # Parse network's data gathering only the desired fields
            fields = Inet.extract_net_fields(value, Inet.NETWORK_FIEDS)
            # Append the network's fields as a dictionary to the list
            net_lst.append(fields)
        return net_lst

    @staticmethod 
    def get_rand_ip(iface:str):
        old_addr = scap.conf.iface.ip
        net_cidr = Inet.get_net_cidr(iface)
        # Create an IPv4Network object; strict=False allows non-network addresses as input.
        network = ipaddress.ip_network(net_cidr, strict=False)
        hosts_gen = network.hosts()
        # network.broadcast_address
        addrs = list(map(lambda x: str(x), hosts_gen))
        rand_addr = random.choice(addrs)
        return rand_addr

    @staticmethod
    def get_rand_mac():
        return ":".join(f"{random.randint(0x00, 0xFF):02x}" for _ in range(6))

        
    




import ipaddress 
import scapy.all as scap


iface_lst = scap.get_if_list()

ip_addr_str = scap.get_if_addr(iface_lst[1])

network = ipaddress.ip_network(ip_addr_str)

x = network

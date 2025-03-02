# from scapy.all import ARP, Ether, srp

# class Pkt:
#     pass













# def arp_scan(network):
#     print(f"Scanning network: {network}")
    
#     # Create an ARP request packet
#     arp = ARP(pdst=network)
    
#     # Create an Ethernet frame (broadcast)
#     ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    
#     # Combine Ethernet + ARP
#     packet = ether / arp
    
#     # Send packet and receive responses
#     answered, unanswered = srp(packet, timeout=2, verbose=False)
    
#     # Print results
#     print("Live hosts:")
#     for sent, received in answered:
#         print(f"IP: {received.psrc}, MAC: {received.hwsrc}")

# # Replace with your subnet (e.g., "192.168.1.1/24")
# arp_scan("192.168.1.0/24")





from scapy.all import get_if_addr, get_if_net, get_if_raw_hwaddr

# Get interface name (e.g., eth0, wlan0)
iface = "eth0"  # Change this to your interface

# Get IP address
ip_addr = get_if_addr(iface)

# Get network mask
netmask = get_if_net(iface)

# Print CIDR notation
print(f"{ip_addr}/{netmask}")

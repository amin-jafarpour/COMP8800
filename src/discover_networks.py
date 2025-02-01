from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt
import time
import sys

def process_packet(pkt, discovered_networks):
   print(pkt)

   if not (pkt.haslayer(Dot11Beacon)  or pkt.haslayer(Dot11ProbeResp) or pkt.haslayer(Dot11Elt)):
       print('BAD PACKET')
       return

   print('ACCEPTABLE PACKET')
   bssid = pkt[Dot11].addr2
   if bssid in discovered_networks:
       return

   ssid = "<Hidden>"
#   if pkt[Dot11Elt:][0].ID == 0: # Dot11Elt with ID=0 indicates SSID
#      ssid = pkt[Dot11Elt:][0].info.decode(errors="ignore").strip()
   if pkt.haslayer(Dot11):
      ssid = pkt[Dot11].info.decode(errors='ignore')

   stats_dict = {}
   if pkt.haslayer(Dot11Beacon):
      stats_dict = pkt[Dot11Beacon].network_stats()
   elif pkt.haslayer(Dot11ProbeResp):
      stats_dict = pkt[Dot11ProbeResp].network_stats()

   channel = stats_dict.get("channel", "N/A")
   crypto = stats_dict.get("crypto", "N/A")
   rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else "N/A"
   discovered_networks[bssid] = {"ssid": ssid,"bssid": bssid,"channel": channel,"encryption": crypto,"rssi": rssi}




def discover_networks(iface, count):
    discovered_networks = {}

    while (len(discovered_networks) <= count):
        print(discovered_networks)
        sniff(iface=iface, count=count, store=False, prn= lambda pkt: process_packet(pkt, discovered_networks))

    return discovered_networks







print(discover_networks(sys.argv[1], int(sys.argv[2])))


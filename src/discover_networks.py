from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt
import time
import sys



def bundle(pkt):
   layers = [layer.__name__ for layer in pkt.layers()]
   info = {}

   for layer in layers:
       pairs_lst = []

       for field in pkt[layer].fields:
          pairs_lst.append({field: pkt[layer].getfieldval(field)})

       info[layer] = {layer: pairs_lst}

   return info





def process_packet(pkt, discovered_networks, limit):
   if pkt.haslayer(Dot11) and len(discovered_networks) < limit:

      bssid = pkt[Dot11].addr2
      if bssid not in discovered_networks:
         pkt_info = bundle(pkt)
         discovered_networks[bssid] = pkt_info






#    bssid = pkt[Dot11].addr2
#    if bssid in discovered_networks:
#        return
#
#    ssid = "<Hidden>"
# #   if pkt[Dot11Elt:][0].ID == 0: # Dot11Elt with ID=0 indicates SSID
# #      ssid = pkt[Dot11Elt:][0].info.decode(errors="ignore").strip()
#    if pkt.haslayer(Dot11):
#       ssid = pkt[Dot11].info.decode(errors='ignore')
#
#    stats_dict = {}
#    if pkt.haslayer(Dot11Beacon):
#       stats_dict = pkt[Dot11Beacon].network_stats()
#    elif pkt.haslayer(Dot11ProbeResp):
#       stats_dict = pkt[Dot11ProbeResp].network_stats()
#
#    channel = stats_dict.get("channel", "N/A")
#    crypto = stats_dict.get("crypto", "N/A")
#    rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else "N/A"
#    discovered_networks[bssid] = {"ssid": ssid,"bssid": bssid,"channel": channel,"encryption": crypto,"rssi": rssi}




def discover_networks(iface, limit):
    discovered_networks = {}

    while (len(discovered_networks) <= limit):
        sniff(iface=iface, count=limit, store=False, prn=lambda pkt: process_packet(pkt, discovered_networks, limit))


    print('...', len(discovered_networks))
    return discovered_networks







print(discover_networks(sys.argv[1], int(sys.argv[2])))


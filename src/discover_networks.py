from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt
import time



def process_packet(pkt, discovered_networks):
   if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
      return
   bssid = pkt[Dot11].addr2
   if bssid in discovered_networks:
       return

   ssid = "<Hidden>"
   if pkt[Dot11Elt:][0].ID == 0: # Dot11Elt with ID=0 indicates SSID
      ssid = pkt[Dot11Elt:][0].info.decode(errors="ignore").strip()

   stats_dict = pkt[Dot11Beacon].network_stats()
   channel = stats_dict.get("channel", "N/A")
   crypto = stats_dict.get("crypto", "N/A")
   rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else "N/A"
   discovered_networks[bssid] = {"ssid": ssid,"bssid": bssid,"channel": channel,"encryption": crypto,"rssi": rssi}




def discover_networks(iface, count):
    discovered_networks = {}

    while (len(discovered_networks) <= count):
        sniff(iface=iface, store=False, count=1, prn= lambda pkt: process_packet(pkt, discovered_networks))

    return discovered_networks







print(discover_networks('wlan0mon', 20))


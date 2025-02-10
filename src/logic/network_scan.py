from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt
import time
import sys
import pprint
from iface_mode import change_mode


ESSENTIAL_FIEDS = ['BSSID', 'addr1', 'addr2', 'addr3', 'country_string', 'num_channels=11', 'dBm_AntSignal', 'rates', 'ChannelFrequency', 'rate']





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
      if bssid != None and  bssid not in discovered_networks:
         pkt_info = bundle(pkt)
         discovered_networks[bssid] = pkt_info





def discover_networks(iface, limit):
    discovered_networks = {}

    while (len(discovered_networks) < limit):
        sniff(iface=iface, count=limit, store=False, prn=lambda pkt: process_packet(pkt, discovered_networks, limit))
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







def main():
    if len(sys.argv) < 3:
        print('Error: Missing comamnd line arguments.')
        print(f'{sys.argv[0]} <Interface> <PacketCount>')
        sys.exit(1)


    change_mode(sys.argv[1], 'monitor')
    networks = discover_networks(sys.argv[1], int(sys.argv[2]))
    for key, value in networks.items():
        print(f'BSSID: {key}')
        # pprint.pprint(value)
        res = extract_fields(networks, ESSENTIAL_FIEDS)
        pprint.pprint(res)

    change_mode(sys.argv[1], 'managed')







if __name__ == '__main__':
   main()
















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

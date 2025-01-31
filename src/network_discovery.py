from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt
import time



def packet_handler(iface, count, interval=0.2):
    """
    """
    discovered_networks = {}
    while len(discovered_networks) <= count:
        pkt = sniff(iface=iface, store=False, count=count)
        # either Beacon Frame or Prob Response Frame?
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2 # MAC address, i.e., BSSID
            ssid = "<Hidden>"
            # Dot11Elt with ID=0 indicates SSID
            if pkt[Dot11Elt:][0].ID == 0:
                # parse SSID to a string
                ssid = pkt[Dot11Elt:][0].info.decode(errors="ignore").strip()
            stats_dict = pkt[Dot11Beacon].network_stats()
            channel = stats_dict.get("channel", "N/A")
            crypto = stats_dict.get("crypto", "N/A")
            rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else "N/A"
            # BSSID not already in existing_bssids?
            if bssid not in discovered_networks:
               discovered_networks[bssid] = {"ssid": ssid,"bssid": bssid,"channel": channel,
                                            "encryption": crypto,"rssi": rssi}
            time.sleep(interval)

    return discovered_networks







def main():
    """
    You must specify an interface in monitor mode (e.g. wlan0mon).
    """
    interface = "wlan0mon"
    print(f"[*] Starting sniff on {interface}...")



if __name__ == "__main__":
    main()


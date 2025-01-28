from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt
import time



def packet_handler(pkt):

    """
    """
    discovered_networks = []
    # check if Beacon Frame or Prob Response Frame
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        # Extract the MAC address of the AP (BSSID)

        bssid = pkt[Dot11].addr2
        ssid = None
        # Dot11Elt with ID=0 indicates SSID
        ssid_elt = pkt[Dot11Elt:][0]
        if ssid_elt.ID == 0:
            ssid = ssid_elt.info.decode(errors="ignore").strip()

        # If it’s an SSID broadcast (sometimes hidden)
        if not ssid:
            ssid = "<Hidden>"

        stats = pkt[Dot11Beacon].network_stats() if pkt.haslayer(Dot11Beacon) else {}
        channel = stats.get("channel", "N/A")
        crypto = stats.get("crypto", "N/A")
        rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else "N/A"

        # Check if we already discovered this BSSID
        existing_bssids = [net["bssid"] for net in discovered_networks]
        if bssid not in existing_bssids:
            discovered_networks.append({
                "ssid": ssid,
                "bssid": bssid,
                "channel": channel,
                "encryption": crypto,
                "rssi": rssi
            })

            print(f"[+] New AP found:")
            print(f"    SSID      : {ssid}")
            print(f"    BSSID     : {bssid}")
            print(f"    Channel   : {channel}")
            print(f"    Encryption: {crypto}")
            print(f"    RSSI: {rssi}")
            print()
            time.sleep(0.5)




def main():
    """
    You must specify an interface in monitor mode (e.g. wlan0mon).
    """
    interface = "wlan0mon"
    print(f"[*] Starting sniff on {interface}...")
    sniff(iface=interface, prn=packet_handler, store=False)


if __name__ == "__main__":
    main()


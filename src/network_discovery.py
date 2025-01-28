#!/usr/bin/env python3

from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt

# A global list to store discovered networks
discovered_networks = []


def packet_handler(pkt):
    """
    Callback function that is invoked for each captured packet.
    Checks for 802.11 Beacon or Probe Response frames,
    extracts SSID, BSSID, channel, and encryption details,
    and prints them if they're new.
    """
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        # Extract the MAC address of the AP (BSSID)
        bssid = pkt[Dot11].addr2

        # Extract the network name (SSID)
        ssid = None
        # Dot11Elt with ID=0 indicates SSID
        ssid_elt = pkt[Dot11Elt:][0]
        if ssid_elt.ID == 0:
            ssid = ssid_elt.info.decode(errors="ignore").strip()

        # If it’s an SSID broadcast (sometimes hidden), handle gracefully
        if not ssid:
            ssid = "<Hidden>"

        # Get channel and encryption info if available
        # Note: In some Scapy versions, Dot11Beacon has .network_stats() to parse AP info
        stats = pkt[Dot11Beacon].network_stats() if pkt.haslayer(Dot11Beacon) else {}
        channel = stats.get("channel", "N/A")
        crypto = stats.get("crypto", "N/A")

        # Check if we already discovered this BSSID
        existing_bssids = [net["bssid"] for net in discovered_networks]
        if bssid not in existing_bssids:
            discovered_networks.append({
                "ssid": ssid,
                "bssid": bssid,
                "channel": channel,
                "encryption": crypto
            })

            print(f"[+] New AP found:")
            print(f"    SSID      : {ssid}")
            print(f"    BSSID     : {bssid}")
            print(f"    Channel   : {channel}")
            print(f"    Encryption: {crypto}")
            print()


def main():
    """
    Main entry point of the script.
    You must specify an interface in monitor mode (e.g. wlan0mon).
    """
    interface = "wlan0mon"  # Modify this to match the name of your monitor-mode interface
    print(f"[*] Starting sniff on {interface}...")
    sniff(iface=interface, prn=packet_handler, store=False)


if __name__ == "__main__":
    main()


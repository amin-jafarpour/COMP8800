from scapy.all import *
import subprocess

"""

    wpa_supplicant

    ip link show | awk -F': ' '/^[0-9]+: / {print $2}'  ||   awk '{print $1}'



    sudo ifconfig wlan0 down
    sudo iwconfig wlan0 mode monitor
    sudo ifconfig wlan0 up
    iwconfig | grep mode
    -----------------------------------
    sudo apt-get install aircrack-ng net-tools
    sudo airmon-ng check kill
    sudo airmon-ng start wlan0


    sudo ifconfig wlan0mon down
    sudo iwconfig wlan0mon mode managed/station
    sudo ifconfig wlan0mon up
    sudo systemctl restart NetworkManager
"""


def get_cidr(network_adapter='wlp164s0'):
    #ip addr show wlp164s0  | grep -oP 'inet \K[\d.]+/\d+'
    ip_result = subprocess.run(['ip', 'addr', 'show', 'wlp164s0'], capture_output=True, text=True)

    if ip_result.returncode == 0:
        # Pipe the output to grep
        grep_result = subprocess.run(
            ['grep', '-oP', r'inet \K[\d.]+/\d+'],
            input=ip_result.stdout,
            text=True,
            capture_output=True
        )
        if grep_result.returncode == 0:
            return grep_result.stdout.strip()
        else:
            print(f"get_cidr(): Grep Error: {grep_result.stderr}")
            return None
    else:
        print(f"get_cidr(): IP Command Error: {ip_result.stderr}")
        return None



def arp_scan(cidr):
    bindings_IP_MAC = {}
    answered, unanswered = arping(cidr, verbose=False)
    for sent, received in answered:
        bindings_IP_MAC[received.hwsrc] = received.psrc

    return bindings_IP_MAC





def monitor_mode(network_adapter='wlp164s0', channel='6'):
    commands = [
        ['sudo', 'ifconfig', network_adapter, 'down'],
        ['sudo', 'iwconfig', network_adapter, 'mode', 'monitor'],
        ['sudo', 'ifconfig', network_adapter, 'up'],
        ['sudo', 'iwconfig', network_adapter, 'channel', channel]
    ]

    try:
        for command in commands:
            result = subprocess.run(command, check=True, text=True, capture_output=True)
            print(f"Command: {' '.join(command)}\nOutput: {result.stdout}\nError: {result.stderr}")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while running: {' '.join(e.cmd)}")
        print(f"Return code: {e.returncode}")
        print(f"Error output: {e.stderr}")





def wifi_sniff(network_interface='wlp164s0'):
    pkt = sniff(iface="wlan0")
    if pkt.haslayer(Dot11):
        # Check for beacon or probe response
        if pkt.type == 0 and pkt.subtype == 8:
            ssid = pkt.info.decode('utf-8', 'ignore') if pkt.info else 'hidden'
            bssid = pkt.addr2
            print(f"Found SSID: {ssid}  BSSID: {bssid}")



def syn_scan(target_ip, port_list):
    print(f"Scanning {target_ip} on ports {port_list}")
    for port in port_list:
        ip_layer = IP(dst=target_ip)
        tcp_layer = TCP(dport=port, flags='S') # SYN flag
        response = sr1(ip_layer / tcp_layer, timeout=0.5, verbose=0)

        if response:
            if response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12: # 0x12 indicates SYN+ACK
                    print(f"Port {port} is open.")
                    rst_packet = ip_layer / TCP(dport=port, flags='R') # RST flag
                    sr1(rst_packet, timeout=0.5, verbose=0)
                elif response.getlayer(TCP).flags == 0x14:
                    print(f"Port {port} is closed.")   # 0x14 indicates RST+ACK
                else:
                    print(f"Port {port} is filtered Flags = {response.getlayer(TCP).flags}.")
            else:
                print(f"Port {port} is filtered. No TCP layer in response.")
        else:
            print(f"Port {port} is filtered. No response.")









conf.verb = 0  # Disable verbose output of Scapy

syn_scan('18.239.199.38', ['80','135', '433', '445'])


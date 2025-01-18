from scapy.all import *
import subprocess




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
            print(f"Grep Error: {grep_result.stderr}")
            return None
    else:
        print(f"IP Command Error: {ip_result.stderr}")
        return None







def arp_scan(cidr):
    answered, unanswered = arping(cidr)
    for sent, received in answered:
        print(f"IP: {received.psrc}  MAC: {received.hwsrc}")





arp_scan(get_cidr())

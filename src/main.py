from scapy.all import *
import subprocess




def get_cidr(network_adapter='wlp164s0'):
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
            print(grep_result.stdout.strip())
        else:
            print(f"Grep Error: {grep_result.stderr}")
    else:
        print(f"IP Command Error: {ip_result.stderr}")





#ip addr show wlp164s0  | grep -oP 'inet \K[\d.]+/\d+'

def arp_scan():
    pass

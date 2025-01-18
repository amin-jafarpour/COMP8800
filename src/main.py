from scapy.all import *
import subprocess



"""
    Dependencies:
    scapy, ifconfig, iwconfig

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



monitor_mode()

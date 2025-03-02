import subprocess 
import sys 
import scapy.all as scap 



class Inet:
    @staticmethod
    def get_cidr(iface):
        # runs bash cmd -> ip addr show wlp164s0  | grep -oP 'inet \K[\d.]+/\d+'
        ip_result = subprocess.run(['ip', 'addr', 'show', iface], capture_output=True, text=True)
        lines = ip_result.stdout.splitlines()
        trimmed_lines = list(map(lambda x: x.strip(), lines))
        items = map(lambda x: x if x.startswith('inet ') else None, trimmed_lines)
        inet_line = list(filter(lambda x: x != None, items))[0]
        cidr = inet_line.split()[1]
        return cidr
    

import subprocess
from scapy.all import arping
import sys

def get_cidr(iface):
    # Bash Command: ip addr show wlp164s0  | grep -oP 'inet \K[\d.]+/\d+'
    ip_result = subprocess.run(['ip', 'addr', 'show', iface], capture_output=True, text=True)


    lines = ip_result.stdout.splitlines()
    trimmed_lines = list(map(lambda x: x.strip(), lines))
    items = map(lambda x: x if x.startswith('inet ') else None, trimmed_lines)
    inet_line = list(filter(lambda x: x != None, items))[0]
    cidr = inet_line.split()[1]
    return cidr
     

#    if ip_result.stderr == 0:
#            pass
         #print(ip_result.stdout.split())
#        # Pipe the output to grep
#        grep_result = subprocess.run(
#            ['grep', '-oP', r'inet \K[\d.]+/\d+'],
#            input=ip_result.stdout,
#            text=True,
#            capture_output=True
#        )
#          
#        print(grep_result.returncode)
#        if grep_result.returncode == 0:
#            return grep_result.stdout.strip()
#        else:
#            print(f"Error: {ip_result.stdout}")
#            return 
#    else:
#        print(f"Error: {ip_result.stdout}")
#        return 


def ip_mac_bindings(iface):
    cidr = get_cidr(iface)
    digits = cidr.split('.')
    last_digit = digits[3]
    mask = last_digit.split('/')[1]
    net_cidr = '.'.join(digits[:3] + ['0']) + '/' + mask
    print(net_cidr)
     
    if cidr == None:
       return None

    ip_mac_dict = {}
    answered, _ = arping(cidr, verbose=False)

    for _, received in answered:
        ip_mac_dict[received.hwsrc] = received.psrc

    return ip_mac_dict


if __name__ == '__main__':
   if len(sys.argv) < 2:
      print('Error: Missing command line arguments.')
      print(f'Usage {sys.argv[0]} <Network Interface Name>')
      sys.exit(1)
   
   bindings = ip_mac_bindings(sys.argv[1])
   if bindings == None:
      sys.exit(1)

   print('MAC, IP')
   for mac, ip in bindings:
      print(mac, ip)


   

   

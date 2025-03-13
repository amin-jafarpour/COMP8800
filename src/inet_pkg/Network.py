#open network
#password-protected network (WPA/WPA2)
#enterprise network (WPA2-Enterprise) with both username and password



sudo ip link set <interface> down

sudo iw dev <interface> set type <mode>

sudo ip link set <interface> up

sudo iwlist <interface> scan | grep -E "SSID|Encryption"

nmcli device wifi connect "<SSID>" ifname <interface> # open network 

nmcli device wifi connect "<SSID>" password "<password>" ifname <interface>











#sudo iwlist <interface> scan | grep -E "SSID|Encryption"



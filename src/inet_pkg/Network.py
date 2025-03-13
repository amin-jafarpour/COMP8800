#open network
#password-protected network (WPA/WPA2)
#enterprise network (WPA2-Enterprise) with both username and password

sudo ip link set <interface> up

sudo iwlist <interface> scan | grep -E "SSID|Encryption"


#sudo iwlist <interface> scan | grep -E "SSID|Encryption"



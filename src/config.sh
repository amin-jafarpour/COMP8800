sudo apt install bluez bluez-tools python3-bluez python3-gattlib rfkill libbluetooth-dev firmware-realtek python3-flask iw -y
sudo systemctl enable --now bluetooth
sudo rfkill unblock bluetooth 



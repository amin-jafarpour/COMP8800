sudo apt install bluez bluez-tools python3-bluez rfkill -y
sudo systemctl enable --now bluetooth
sudo rfkill unblock bluetooth 



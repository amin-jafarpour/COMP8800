# install bluez python3-pybluez bluez-tools
# sudo systemctl restart bluetooth
import bluetooth


class BL:
    @staticmethod
    def bl_scan(timeout:int):
        devices = bluetooth.discover_devices(duration=timeout, lookup_names=True, lookup_class=True)
        if not devices:
            return []
        
        devices_info = []
        for addr, name, cod in devices:
            services = bluetooth.find_service(address=addr)
            devices_info.append({'addr': addr, 'name': name, 'cod': cod, 'services': services})

        return devices_info

            


            




def scan_devices():
    print("Scanning for Bluetooth devices...")
    devices = bluetooth.discover_devices(duration=8, lookup_names=True, lookup_class=True)

    if not devices:
        print("No Bluetooth devices found.")
        return

    print("\nFound Devices:")
    for addr, name, device_class in devices:
        try:
            print(f"\nDevice Address: {addr}")
            print(f"Device Name: {name}")
            print(f"Device Class: {device_class}")
            
            # Fetch services running on the device
            services = bluetooth.find_service(address=addr)
            if services:
                print("Services Found:")
                for service in services:
                    print(f"  - Name: {service['name']}")
                    print(f"    Protocol: {service['protocol']}")
                    print(f"    Port: {service['port']}")
                    print(f"    Service ID: {service['service-id']}")
            else:
                print("  No services found.")

        except UnicodeEncodeError:
            print(f"  {addr} - {name.encode('utf-8', 'replace')}")







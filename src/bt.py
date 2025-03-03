# install bluez python3-pybluez bluez-tools
# sudo systemctl restart bluetooth
import bluetooth


class BT:
    @staticmethod
    def bt_scan(timeout:int):
        devices = bluetooth.discover_devices(duration=timeout, lookup_names=True, lookup_class=True)
        if not devices:
            return []
        
        devices_info = []
        for addr, name, cod in devices:
            services = bluetooth.find_service(address=addr)
            devices_info.append({'addr': addr, 'name': name, 'cod': cod, 'services': services})
        return devices_info

            
            
    @staticmethod
    def advertise():
        pass







#   print(f"  - Name: {service['name']}")
#                     print(f"    Protocol: {service['protocol']}")
#                     print(f"    Port: {service['port']}")
#                     print(f"    Service ID: {service['service-id']}")






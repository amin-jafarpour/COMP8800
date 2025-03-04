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
    def dummy():
        pass

          
          
          
          
          
# for svc in services:
#     print("\nService Name:", svc["name"])
#     print("    Host:       ", svc["host"])
#     print("    Description:", svc["description"])
#     print("    Provided By:", svc["provider"])
#     print("    Protocol:   ", svc["protocol"])
#     print("    channel/PSM:", svc["port"])
#     print("    svc classes:", svc["service-classes"])
#     print("    profiles:   ", svc["profiles"])
#     print("    service id: ", svc["service-id"])  
            
    # @staticmethod
    # def advertise():
    #     server_sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
    #     server_sock.bind(("", bluetooth.PORT_ANY)) 
    #     server_sock.listen(1)
    #     port = server_sock.getsockname()[1]
    #     #host_mac = bluetooth.read_local_bdaddr()[0]
    #     service_uuid = "94f39d29-7d6d-437d-973b-fba39e49d4ee" 
    #     bluetooth.advertise_service(
    #     server_sock, "MyBluetoothService",
    #     service_id=service_uuid,
    #     service_classes=[service_uuid, bluetooth.SERIAL_PORT_CLASS],  
    #     profiles=[bluetooth.SERIAL_PORT_PROFILE],)
    #     client_sock, client_info = server_sock.accept()
    #     data = client_sock.recv(1024)
    #     print(f"Received: {data.decode()}")
    #     client_sock.close()
    #     server_sock.close()
        
    
  
        

        
        
        

        

        










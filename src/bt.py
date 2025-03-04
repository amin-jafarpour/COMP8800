# install bluez python3-pybluez bluez-tools
# sudo systemctl restart bluetooth
# pip install pybluez gattlib
import bluetooth
import time 


class BT:
    @staticmethod
    def bt_scan(timeout:int):
        devices = bluetooth.discover_devices(duration=timeout, lookup_names=True, lush_cache=True, lookup_class=True)
        if not devices:
            return []
        
        devices_info = []
        for addr, name, cod in devices:
            services = bluetooth.find_service(address=addr)
            devices_info.append({'addr': addr, 'name': name, 'cod': cod, 'services': services})
        return devices_info
    
    
    @staticmethod
    def l2cap_server():    
        # advertise_service(
        # sock,
        # name,
        # service_id='',
        # service_classes=[],
        # profiles=[],
        # provider='',
        # description='',
        # protocols=[])
        server_sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        port = 0x1001
        server_sock.bind(("00:E0:03:00:19:D1", port))
        server_sock.listen(1)
        uuid = "0000180a-0000-1000-8000-00805f9b34fb"
        bluetooth.advertise_service(server_sock, "SampleServerL2CAP", service_id=uuid, service_classes = [uuid])
        client_sock, address = server_sock.accept()
        print("Accepted connection from", address)
        data = client_sock.recv(1024)
        print("Data received:", str(data))
        while data:
            client_sock.send("Echo =>", str(data))
            data = client_sock.recv(1024)
            print("Data received:", str(data))
        client_sock.close()
        server_sock.close()    
        
    @staticmethod
    def rfcomm_server():
        server_sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
        server_sock.bind(("00:E0:03:00:19:D1", bluetooth.PORT_ANY))
        server_sock.listen(1)
        port = server_sock.getsockname()[1]
        uuid = "94f39d29-7d6d-437d-973b-fba39e49d4ee"
        bluetooth.advertise_service(server_sock, "SampleServer", service_id=uuid,
                            service_classes=[uuid, bluetooth.SERIAL_PORT_CLASS],
                            profiles=[bluetooth.SERIAL_PORT_PROFILE],
                            # protocols=[bluetooth.OBEX_UUID]
                            )
        print("Waiting for connection on RFCOMM channel", port)
        client_sock, client_info = server_sock.accept()
        print("Accepted connection from", client_info)
        try:
            while True:
                data = client_sock.recv(1024)
                if not data:
                    break
                print("Received", data)
        except OSError:
            pass

        print("Disconnected.")
        client_sock.close()
        server_sock.close()
        print("All done.")
        


    @staticmethod
    def sdp_browse(addr=None):
       services = bluetooth.find_service(address=addr) # None address for all devices
       for svc in services:
           print("\nService Name:", svc["name"])
           print("    Host:       ", svc["host"])
           print("    Description:", svc["description"])
           print("    Provided By:", svc["provider"])
           print("    Protocol:   ", svc["protocol"])
           print("    channel/PSM:", svc["port"])
           print("    svc classes:", svc["service-classes"])
           print("    profiles:   ", svc["profiles"])
           print("    service id: ", svc["service-id"])
 
 
    @staticmethod
    def send_ble_beacon():
        service = bluetooth.ble.BeaconService()
        service.start_advertising("11111111-2222-3333-4444-555555555555",1, 1, 1, 200)
        time.sleep(15)
        service.stop_advertising()
        print("Done.")
        
    @staticmethod
    def ble_becan_scan():
        service = bluetooth.ble.BeaconService()
        devices = service.scan(2)
        for address, data in list(devices.items()):
            print(data, address)
        print("Done.")
        
 
 
 
 
            
          
# Client:   
# service_matches = bluetooth.find_service(uuid=uuid, address=addr)
# sock.connect((host, port))


            

    
  
        

        
        
        

        

        










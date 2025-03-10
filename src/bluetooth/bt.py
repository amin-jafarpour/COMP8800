# Special thanks to https://github.com/pybluez/pybluez/tree/master/examples/
import bluetooth
import time 


class BT:
    @staticmethod
    def device_scan(duration:int):
        # discover_devices(duration, lookup_names, lookup_class):
        #   lookup_names: Find name of each discovered device. 
        #   lookup_class: Find class of each discovered device. 
        #   Returns a list of (address, name, class) tuples, where CoD is Class of Device.
        devices = bluetooth.discover_devices(duration=duration, lookup_names=True, 
        lookup_class=True) 
        if not devices:
            return []
        devices_info= []
        for addr, name, cod in devices:
            # find_service(name=None, uuid=None, address=None):
            #   names: friendly name of the device.
            #   uuid: 16-bit or 128-bit UUID.
            #   address: 6 byte BD_ADDR (Bluetooth Device Address).
            #   Returns a list of dictionaries: {
            #       host: addr of host.
            #       name: ame of the service being advertised.
            #       description: description of service.
            #       protocol: RFCOMM, L2CAP, or UNKNOWN.
            #       port: RFCOMM channel number for RFCOMM or L2CAP PSM number for L2CAP or None for UNKNOWN.
            #       service-classes: list Service Class UUIDs, defines the type of service(s) offered.
            #       profiles: list of profiles, profile = (UUID, version) tuple.
            #       service-id: Unique 128-bit UUID identifing a particular service instance running on a device.
            #       }
            services = bluetooth.find_service(name=name, address=addr)
            services = []
            devices_info.append({'addr': addr, 'name': name, 'cod': BT.interpret_cod(cod), 'services': services})
        return devices_info
    

    @staticmethod
    def interpret_cod(cod: int) -> dict:
        """
        Interpret a 24-bit Bluetooth Class of Device (CoD) integer.
        
        Returns a dictionary with:
        - "major_service_classes": list of strings describing any set service bits
        - "major_device_class": a string describing the major device class
        - "minor_device_class": a string describing the minor device class
        
        Reference bit layout (from LSB to MSB in a 24-bit CoD):
            • Bits 0-1: Format type (usually '00' for baseband CoD format)
            • Bits 2-7: Minor Device Class (6 bits)
            • Bits 8-12: Major Device Class (5 bits)
            • Bits 13-23: Major Service Class bits (11 bits)
        
        For full details, see the "Assigned Numbers" document from the Bluetooth SIG.
        """
        if cod == None:
            return {{}}
        # --- 1) Extract bitfields ---
        # Service bits = upper 11 bits (bits 13..23)
        major_service_bits = (cod >> 13) & 0x7FF  # 11 bits
        # Major device class = next 5 bits (bits 8..12)
        major_device_class = (cod >> 8) & 0x1F
        # Minor device class = next 6 bits (bits 2..7)
        minor_device_class = (cod >> 2) & 0x3F
        # Format type could be read if needed: format_type = cod & 0x3

        # --- 2) Define the known Major Service bits ---
        # According to the Bluetooth spec, each bit in the 11-bit service field
        # (counting from LSB=bit0 of that subfield) indicates the presence of a service.
        # Note: bits 14 & 15 are often reserved in older docs; some expansions exist.
        # The mapping below is typical for the commonly used bits.
        service_class_map = {
            0: "Limited Discoverable Mode",  # bit 13 overall
            1: "Reserved (bit 14)",         # bit 14 overall
            2: "Reserved (bit 15)",         # bit 15 overall
            3: "Positioning",               # bit 16 overall
            4: "Networking",                # bit 17 overall
            5: "Rendering",                 # bit 18 overall
            6: "Capturing",                 # bit 19 overall
            7: "Object Transfer",           # bit 20 overall
            8: "Audio",                     # bit 21 overall
            9: "Telephony",                 # bit 22 overall
            10: "Information",              # bit 23 overall
        }

        # Determine which service class bits are set
        major_service_classes = []
        for bit_pos, descr in service_class_map.items():
            if major_service_bits & (1 << bit_pos):
                major_service_classes.append(descr)

        # --- 3) Define the Major Device Class mapping (5 bits) ---
        major_device_map = {
            0x00: "Miscellaneous",
            0x01: "Computer",
            0x02: "Phone",
            0x03: "LAN/Network Access Point",
            0x04: "Audio/Video",
            0x05: "Peripheral",
            0x06: "Imaging",
            0x07: "Wearable",
            0x08: "Toy",
            0x09: "Health",
            # The specs sometimes mention 0x1F for "Uncategorized" or "Unspecified".
            0x1F: "Uncategorized / Unspecified",
        }
        major_device_str = major_device_map.get(major_device_class, "Reserved/Unknown")

        # --- 4) Define the Minor Device Class mapping (6 bits) per Major Class ---
        # The minor class meaning depends on which major class we are in.
        # Below are some common subsets from the Assigned Numbers document.
        # If an entry is missing, it falls back to "Reserved/Unknown".
        minor_class_map = {
            0x00: "Uncategorized (default)",
            # ----------------------------
            # For Major Class = 0x01 (Computer)
            # ----------------------------
            (0x01, 0x01): "Desktop workstation",
            (0x01, 0x02): "Server-class computer",
            (0x01, 0x03): "Laptop",
            (0x01, 0x04): "Handheld PC/PDA",
            (0x01, 0x05): "Palm-sized PC/PDA",
            (0x01, 0x06): "Wearable computer (watch-sized)",
            # ----------------------------
            # For Major Class = 0x02 (Phone)
            # ----------------------------
            (0x02, 0x01): "Cellular",
            (0x02, 0x02): "Cordless",
            (0x02, 0x03): "Smartphone",
            (0x02, 0x04): "Wired modem or voice gateway",
            (0x02, 0x05): "Common ISDN Access",
            # ----------------------------
            # For Major Class = 0x03 (LAN/Network Access Point)
            # Minor device class is split into networking capability, e.g.:
            # 0x00: Fully available, 0x01: 1-17% used, 0x02: 17-33% used, etc.
            (0x03, 0x00): "Fully available",
            (0x03, 0x01): "1 - 17% utilized",
            (0x03, 0x02): "17 - 33% utilized",
            (0x03, 0x03): "33 - 50% utilized",
            (0x03, 0x04): "50 - 67% utilized",
            (0x03, 0x05): "67 - 83% utilized",
            (0x03, 0x06): "83 - 99% utilized",
            (0x03, 0x07): "No service available",
            # ----------------------------
            # For Major Class = 0x04 (Audio/Video)
            # ----------------------------
            (0x04, 0x01): "Headset",
            (0x04, 0x02): "Hands-free",
            # 0x03 is reserved
            (0x04, 0x04): "Microphone",
            (0x04, 0x05): "Loudspeaker",
            (0x04, 0x06): "Headphones",
            (0x04, 0x07): "Portable Audio",
            (0x04, 0x08): "Car Audio",
            (0x04, 0x09): "Set-top box",
            (0x04, 0x0A): "HiFi Audio Device",
            (0x04, 0x0B): "VCR",
            (0x04, 0x0C): "Video Camera",
            (0x04, 0x0D): "Camcorder",
            (0x04, 0x0E): "Video Monitor",
            (0x04, 0x0F): "Video Speaker",
            (0x04, 0x10): "Video Conferencing",
            (0x04, 0x12): "Gaming/Toy",
            # ----------------------------
            # For Major Class = 0x05 (Peripheral: mouse, keyboard, etc.)
            # The minor class has bits indicating keyboard, pointing device, etc.
            # Typically the low 6 bits are split: upper 2 bits for "Subclass", lower 4 bits for "Device type"
            # We'll include some common ones below:
            (0x05, 0x01): "Keyboard",
            (0x05, 0x02): "Pointing device (mouse)",
            (0x05, 0x03): "Combo keyboard/pointing device",
            # Subclass 01xx => Type: joystick, gamepad, etc.
            (0x05, 0x04): "Joystick",
            (0x05, 0x05): "Gamepad",
            (0x05, 0x06): "Remote control",
            (0x05, 0x07): "Sensing device (e.g. proximity)",
            (0x05, 0x08): "Digitizer tablet",
            (0x05, 0x09): "Card R/W",
            # ----------------------------
            # For Major Class = 0x06 (Imaging: printer, scanner, camera, display)
            # The minor device class bits typically break out printing, scanning, camera, display
            # Bits: 0x04=Display, 0x08=Camera, 0x10=Scanner, 0x20=Printer
            # We'll map some common combinations explicitly for illustration:
            (0x06, 0x01): "Display",
            (0x06, 0x02): "Camera",
            (0x06, 0x04): "Scanner",
            (0x06, 0x08): "Printer",
            # Combine bits e.g. camera+display = 0x03, etc. For brevity, only a few are shown.
            # ----------------------------
            # For Major Class = 0x07 (Wearable)
            (0x07, 0x01): "Wristwatch",
            (0x07, 0x02): "Pager",
            (0x07, 0x03): "Jacket",
            (0x07, 0x04): "Helmet",
            (0x07, 0x05): "Glasses",
            # ----------------------------
            # For Major Class = 0x08 (Toy)
            (0x08, 0x01): "Robot",
            (0x08, 0x02): "Vehicle",
            (0x08, 0x03): "Doll / Action Figure",
            (0x08, 0x04): "Controller",
            (0x08, 0x05): "Game",
            # ----------------------------
            # For Major Class = 0x09 (Health)
            (0x09, 0x01): "Blood Pressure Monitor",
            (0x09, 0x02): "Thermometer",
            (0x09, 0x03): "Weighing scale",
            (0x09, 0x04): "Glucose meter",
            (0x09, 0x05): "Pulse oximeter",
            (0x09, 0x06): "Heart/Pulse rate monitor",
            (0x09, 0x07): "Health Data Display",
            (0x09, 0x08): "Step counter",
            (0x09, 0x09): "Body composition analyzer",
        }

        # Look up the minor device class:
        # We'll check if there's a specific entry for (major_device_class, minor_device_class).
        # If not found, we try a general "0x00 => Uncategorized" or else "Reserved/Unknown".
        minor_device_str = "Reserved/Unknown"
        if (major_device_class, minor_device_class) in minor_class_map:
            minor_device_str = minor_class_map[(major_device_class, minor_device_class)]
        elif minor_device_class == 0x00 and major_device_class in [0x01, 0x02, 0x03,
                                                                0x04, 0x05, 0x06,
                                                                0x07, 0x08, 0x09]:
            # If it is exactly 0x00, often means "Uncategorized" for that major
            minor_device_str = "Uncategorized"
        elif minor_device_class in minor_class_map:
            # If there's a direct entry for minor_device_class alone
            minor_device_str = minor_class_map[minor_device_class]
        
        # Assemble the interpretation into a dictionary
        return {
            "major_service_classes": major_service_classes,
            "major_device_class": major_device_str,
            "minor_device_class": minor_device_str
        }




########################################################################################################
########################################################################################################
########################################################################################################
########################################################################################################
########################################################################################################

    
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
        
 
    @staticmethod
    def gatt(address):
        # Generic Attribute Profile
        requester = bluetooth.ble.GATTRequester(address, False)
        requester.connect(True)
        res = requester.read_by_uuid("00002a00-0000-1000-8000-00805f9b34fb")
        print(res)
        
    def ble_service_scan():
        discovery = bluetooth.ble.DiscoveryService()
        devices = discovery.discover(2)
        for address, name in devices.items():
            print("Name: {}, address: {}".format(name, address))
        
        

 
 
 
 
            
          
# Client:   
# service_matches = bluetooth.find_service(uuid=uuid, address=addr)
# sock.connect((host, port))


            

    
  
        

        
        
        

        

        










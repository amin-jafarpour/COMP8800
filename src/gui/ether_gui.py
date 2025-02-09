
import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

# --- Attempt to import Scapy ---
try:
    from scapy.all import Ether, sr1
    has_scapy = True
except ImportError:
    has_scapy = False
    
    
    
TIMEOUT_SECONDS = 3
    
    
# ------------------- Ethernet (Data Link) Window -------------------
class EthernetWindow(Gtk.Window):
    def __init__(self):
        super().__init__(title="Ethernet Frame Constructor")
        self.set_border_width(10)
        self.set_default_size(600, 300)

        main_vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.add(main_vbox)

        grid = Gtk.Grid(column_spacing=10, row_spacing=10)
        main_vbox.pack_start(grid, True, True, 0)

        # 1. Destination MAC
        dst_label = Gtk.Label(label="Destination MAC")
        grid.attach(dst_label, 0, 0, 1, 1)
        self.dst_entry = Gtk.Entry()
        # Typical format: "ff:ff:ff:ff:ff:ff" or "01:23:45:67:89:ab"
        self.dst_entry.set_text("ff:ff:ff:ff:ff:ff")
        grid.attach(self.dst_entry, 1, 0, 1, 1)

        # 2. Source MAC
        src_label = Gtk.Label(label="Source MAC")
        grid.attach(src_label, 0, 1, 1, 1)
        self.src_entry = Gtk.Entry()
        self.src_entry.set_text("00:11:22:33:44:55")
        grid.attach(self.src_entry, 1, 1, 1, 1)

        # 3. EtherType
        # Common values: 0x0800 = IPv4, 0x0806 = ARP, 0x86DD = IPv6
        ethertype_label = Gtk.Label(label="EtherType (e.g. 0x0800 for IPv4)")
        grid.attach(ethertype_label, 0, 2, 1, 1)
        self.ethertype_entry = Gtk.Entry()
        self.ethertype_entry.set_text("0x0800")
        grid.attach(self.ethertype_entry, 1, 2, 1, 1)

        # 4. Payload (Data)
        payload_label = Gtk.Label(label="Payload (ASCII / Hex)")
        grid.attach(payload_label, 0, 3, 1, 1)
        self.payload_textview = Gtk.TextView()
        self.payload_textview.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        payload_scrolled = Gtk.ScrolledWindow()
        payload_scrolled.set_hexpand(True)
        payload_scrolled.set_vexpand(True)
        payload_scrolled.add(self.payload_textview)
        grid.attach(payload_scrolled, 1, 3, 1, 1)

        # Buttons
        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        main_vbox.pack_start(button_box, False, False, 0)

        construct_button = Gtk.Button(label="Construct Ethernet Frame")
        construct_button.connect("clicked", self.on_construct_clicked)
        button_box.pack_start(construct_button, True, True, 0)

        quit_button = Gtk.Button(label="Close Window")
        quit_button.connect("clicked", lambda w: self.destroy())
        button_box.pack_start(quit_button, True, True, 0)

    def on_construct_clicked(self, button, recv_callback):
        # Read the fields
        dst_mac = self.dst_entry.get_text()
        src_mac = self.src_entry.get_text()
        ethertype_str = self.ethertype_entry.get_text()

        # Convert the EtherType from hex string if it starts with "0x" or "0X",
        # or decimal if provided that way, or handle errors
        try:
            if ethertype_str.lower().startswith("0x"):
                ethertype = int(ethertype_str, 16)
            else:
                ethertype = int(ethertype_str)  # decimal
        except ValueError:
            print(f"Invalid EtherType format '{ethertype_str}'. Defaulting to 0x0800.")
            ethertype = 0x0800

        buf = self.payload_textview.get_buffer()
        start_iter, end_iter = buf.get_bounds()
        payload = buf.get_text(start_iter, end_iter, False)

        # Print out chosen values
        print("[Ethernet] Destination MAC:", dst_mac)
        print("[Ethernet] Source MAC:", src_mac)
        print(f"[Ethernet] EtherType: 0x{ethertype:04x}")
        print("[Ethernet] Payload:", payload)

        if has_scapy:
            # Construct the Ethernet frame
            ether_frame = Ether(dst=dst_mac, src=src_mac, type=ethertype)
            response = sr1(ether_frame, timeout=TIMEOUT_SECONDS, verbose=False) 
            recv_callback(response)
            
            
            
            
        else:
            print("Scapy not available; install with 'pip install scapy' to construct frames.")


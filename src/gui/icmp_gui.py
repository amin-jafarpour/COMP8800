import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

# --- Attempt to import Scapy ---
try:
    from scapy.all import ICMP
    has_scapy = True
except ImportError:
    has_scapy = False
    
    
# ------------------- ICMP Packet Window -------------------
class ICMPPacketWindow(Gtk.Window):
    def __init__(self):
        super().__init__(title="ICMP Packet Constructor")
        self.set_border_width(10)
        self.set_default_size(600, 400)

        main_vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.add(main_vbox)

        grid = Gtk.Grid(column_spacing=10, row_spacing=10)
        main_vbox.pack_start(grid, True, True, 0)

        # Type
        type_label = Gtk.Label(label="Type")
        grid.attach(type_label, 0, 0, 1, 1)
        self.type_spin = Gtk.SpinButton()
        self.type_spin.set_adjustment(Gtk.Adjustment(8, 0, 255, 1, 10, 0))
        grid.attach(self.type_spin, 1, 0, 1, 1)

        # Code
        code_label = Gtk.Label(label="Code")
        grid.attach(code_label, 0, 1, 1, 1)
        self.code_spin = Gtk.SpinButton()
        self.code_spin.set_adjustment(Gtk.Adjustment(0, 0, 255, 1, 10, 0))
        grid.attach(self.code_spin, 1, 1, 1, 1)

        # Checksum
        checksum_label = Gtk.Label(label="Checksum (0 for auto)")
        grid.attach(checksum_label, 0, 2, 1, 1)
        self.checksum_spin = Gtk.SpinButton()
        self.checksum_spin.set_adjustment(Gtk.Adjustment(0, 0, 65535, 1, 100, 0))
        grid.attach(self.checksum_spin, 1, 2, 1, 1)

        # Identifier
        id_label = Gtk.Label(label="Identifier (ID)")
        grid.attach(id_label, 0, 3, 1, 1)
        self.id_spin = Gtk.SpinButton()
        self.id_spin.set_adjustment(Gtk.Adjustment(1, 0, 65535, 1, 100, 0))
        grid.attach(self.id_spin, 1, 3, 1, 1)

        # Sequence Number
        seq_label = Gtk.Label(label="Sequence Number")
        grid.attach(seq_label, 0, 4, 1, 1)
        self.seq_spin = Gtk.SpinButton()
        self.seq_spin.set_adjustment(Gtk.Adjustment(1, 0, 65535, 1, 100, 0))
        grid.attach(self.seq_spin, 1, 4, 1, 1)

        # Payload
        payload_label = Gtk.Label(label="Payload (ASCII / Hex)")
        grid.attach(payload_label, 0, 5, 1, 1)
        self.payload_textview = Gtk.TextView()
        self.payload_textview.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        payload_scrolled = Gtk.ScrolledWindow()
        payload_scrolled.set_hexpand(True)
        payload_scrolled.set_vexpand(True)
        payload_scrolled.add(self.payload_textview)
        grid.attach(payload_scrolled, 1, 5, 1, 1)

        # Buttons
        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        main_vbox.pack_start(button_box, False, False, 0)

        construct_button = Gtk.Button(label="Construct ICMP Packet")
        construct_button.connect("clicked", self.on_construct_clicked)
        button_box.pack_start(construct_button, True, True, 0)

        quit_button = Gtk.Button(label="Close Window")
        quit_button.connect("clicked", lambda w: self.destroy())
        button_box.pack_start(quit_button, True, True, 0)

    def on_construct_clicked(self, button):
        icmp_type = self.type_spin.get_value_as_int()
        icmp_code = self.code_spin.get_value_as_int()
        checksum = self.checksum_spin.get_value_as_int()
        icmp_id = self.id_spin.get_value_as_int()
        icmp_seq = self.seq_spin.get_value_as_int()

        buf = self.payload_textview.get_buffer()
        start_iter, end_iter = buf.get_bounds()
        payload = buf.get_text(start_iter, end_iter, False)

        print("[ICMP] Type:", icmp_type)
        print("[ICMP] Code:", icmp_code)
        print("[ICMP] Checksum:", checksum)
        print("[ICMP] ID:", icmp_id)
        print("[ICMP] Sequence:", icmp_seq)
        print("[ICMP] Payload:", payload)

        if has_scapy:
            icmp_pkt = ICMP(
                type=icmp_type,
                code=icmp_code,
                chksum=checksum if checksum != 0 else None,
                id=icmp_id,
                seq=icmp_seq
            )
            print(f"Constructed ICMP Packet: {icmp_pkt.summary()}")
        else:
            print("Scapy not available; install with 'pip install scapy' to construct packets.")





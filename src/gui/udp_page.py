#!/usr/bin/env python3

# This example creates a PyGObject (GTK+ 3) GUI for specifying
# the main fields of a UDP packet. If Scapy is installed
# (via "pip install scapy"), clicking "Construct UDP Packet"
# will build the packet and print a summary. Otherwise, it will
# simply display the chosen parameters.

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

try:
    from scapy.all import UDP
    has_scapy = True
except ImportError:
    has_scapy = False

class UDPPacketWindow(Gtk.Window):
    def __init__(self):
        super().__init__(title="UDP Packet Constructor")
        self.set_border_width(10)
        self.set_default_size(600, 400)

        main_vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.add(main_vbox)

        grid = Gtk.Grid(column_spacing=10, row_spacing=10)
        main_vbox.pack_start(grid, True, True, 0)

        # 1. Source Port
        srcport_label = Gtk.Label(label="Source Port")
        grid.attach(srcport_label, 0, 0, 1, 1)
        self.srcport_spin = Gtk.SpinButton()
        self.srcport_spin.set_adjustment(Gtk.Adjustment(1234, 0, 65535, 1, 100, 0))
        grid.attach(self.srcport_spin, 1, 0, 1, 1)

        # 2. Destination Port
        dstport_label = Gtk.Label(label="Destination Port")
        grid.attach(dstport_label, 0, 1, 1, 1)
        self.dstport_spin = Gtk.SpinButton()
        self.dstport_spin.set_adjustment(Gtk.Adjustment(80, 0, 65535, 1, 100, 0))
        grid.attach(self.dstport_spin, 1, 1, 1, 1)

        # 3. Length
        length_label = Gtk.Label(label="Length (0 for auto)")
        grid.attach(length_label, 0, 2, 1, 1)
        self.len_spin = Gtk.SpinButton()
        self.len_spin.set_adjustment(Gtk.Adjustment(0, 0, 65535, 1, 100, 0))
        grid.attach(self.len_spin, 1, 2, 1, 1)

        # 4. Checksum
        checksum_label = Gtk.Label(label="Checksum (0 for auto)")
        grid.attach(checksum_label, 0, 3, 1, 1)
        self.checksum_spin = Gtk.SpinButton()
        self.checksum_spin.set_adjustment(Gtk.Adjustment(0, 0, 65535, 1, 100, 0))
        grid.attach(self.checksum_spin, 1, 3, 1, 1)

        # 5. Payload / Data
        payload_label = Gtk.Label(label="Payload (ASCII / Hex)")
        grid.attach(payload_label, 0, 4, 1, 1)
        self.payload_textview = Gtk.TextView()
        self.payload_textview.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)

        payload_scrolled = Gtk.ScrolledWindow()
        payload_scrolled.set_hexpand(True)
        payload_scrolled.set_vexpand(True)
        payload_scrolled.add(self.payload_textview)
        grid.attach(payload_scrolled, 1, 4, 1, 1)

        # Buttons
        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        main_vbox.pack_start(button_box, False, False, 0)

        construct_button = Gtk.Button(label="Construct UDP Packet")
        construct_button.connect("clicked", self.on_construct_clicked)
        button_box.pack_start(construct_button, True, True, 0)

        quit_button = Gtk.Button(label="Quit")
        quit_button.connect("clicked", lambda w: Gtk.main_quit())
        button_box.pack_start(quit_button, True, True, 0)

    def on_construct_clicked(self, button):
        # Read the fields
        sport = self.srcport_spin.get_value_as_int()
        dport = self.dstport_spin.get_value_as_int()
        length = self.len_spin.get_value_as_int()
        chksum = self.checksum_spin.get_value_as_int()

        buf = self.payload_textview.get_buffer()
        start_iter, end_iter = buf.get_bounds()
        payload = buf.get_text(start_iter, end_iter, False)

        # Print the values
        print(f"Source Port: {sport}")
        print(f"Destination Port: {dport}")
        print(f"Length: {length}")
        print(f"Checksum: {chksum}")
        print(f"Payload: {payload}")

        # Construct the UDP packet using scapy if available
        if has_scapy:
            udp_pkt = UDP(
                sport=sport,
                dport=dport,
                len=length if length != 0 else None,  # let scapy auto-fill if 0
                chksum=chksum if chksum != 0 else None
            )
            print("Constructed UDP packet via Scapy:")
            print(udp_pkt.summary())
        else:
            print("Scapy is not installed. Install scapy (pip install scapy) to construct packets.")

def main():
    win = UDPPacketWindow()
    win.connect("destroy", Gtk.main_quit)
    win.show_all()
    Gtk.main()

if __name__ == "__main__":
    main()

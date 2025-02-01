#!/usr/bin/env python3

# This example uses PyGObject (Gtk+ 3) to create a GUI for specifying
# the fields of an IPv4 packet. On clicking "Construct Packet," it
# prints out the specified values and attempts to create a packet using Scapy.
# Install scapy via "pip install scapy" if you want to generate the packet.

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk

try:
    from scapy.all import IP
    has_scapy = True
except ImportError:
    has_scapy = False

class IPPacketWindow(Gtk.Window):
    def __init__(self):
        super().__init__(title="IP Packet Constructor")
        self.set_border_width(10)
        self.set_default_size(600, 500)

        main_vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.add(main_vbox)

        grid = Gtk.Grid(column_spacing=10, row_spacing=10)
        main_vbox.pack_start(grid, True, True, 0)

        # 1. Version
        version_label = Gtk.Label(label="Version (4 for IPv4)")
        grid.attach(version_label, 0, 0, 1, 1)
        self.version_spin = Gtk.SpinButton()
        self.version_spin.set_adjustment(Gtk.Adjustment(4, 0, 15, 1, 5, 0))
        self.version_spin.set_value(4)
        grid.attach(self.version_spin, 1, 0, 1, 1)

        # 2. IHL
        ihl_label = Gtk.Label(label="IHL (Header Length)")
        grid.attach(ihl_label, 0, 1, 1, 1)
        self.ihl_spin = Gtk.SpinButton()
        self.ihl_spin.set_adjustment(Gtk.Adjustment(5, 0, 15, 1, 5, 0))
        self.ihl_spin.set_value(5)
        grid.attach(self.ihl_spin, 1, 1, 1, 1)

        # 3. DSCP
        dscp_label = Gtk.Label(label="DSCP")
        grid.attach(dscp_label, 0, 2, 1, 1)
        self.dscp_spin = Gtk.SpinButton()
        self.dscp_spin.set_adjustment(Gtk.Adjustment(0, 0, 63, 1, 5, 0))
        self.dscp_spin.set_value(0)
        grid.attach(self.dscp_spin, 1, 2, 1, 1)

        # 4. ECN
        ecn_label = Gtk.Label(label="ECN")
        grid.attach(ecn_label, 0, 3, 1, 1)
        self.ecn_spin = Gtk.SpinButton()
        self.ecn_spin.set_adjustment(Gtk.Adjustment(0, 0, 3, 1, 2, 0))
        self.ecn_spin.set_value(0)
        grid.attach(self.ecn_spin, 1, 3, 1, 1)

        # 5. Total Length
        length_label = Gtk.Label(label="Total Length")
        grid.attach(length_label, 0, 4, 1, 1)
        self.length_spin = Gtk.SpinButton()
        self.length_spin.set_adjustment(Gtk.Adjustment(20, 0, 65535, 1, 10, 0))
        self.length_spin.set_value(20)
        grid.attach(self.length_spin, 1, 4, 1, 1)

        # 6. Identification
        identification_label = Gtk.Label(label="Identification")
        grid.attach(identification_label, 0, 5, 1, 1)
        self.ident_spin = Gtk.SpinButton()
        self.ident_spin.set_adjustment(Gtk.Adjustment(1, 0, 65535, 1, 10, 0))
        self.ident_spin.set_value(1)
        grid.attach(self.ident_spin, 1, 5, 1, 1)

        # 7. Flags (Reserved, Don't Fragment, More Fragments)
        flags_label = Gtk.Label(label="Flags")
        grid.attach(flags_label, 0, 6, 1, 1)

        flags_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        self.flag_reserved = Gtk.CheckButton(label="Reserved")
        self.flag_df = Gtk.CheckButton(label="Don't Fragment")
        self.flag_mf = Gtk.CheckButton(label="More Fragments")
        flags_box.pack_start(self.flag_reserved, False, False, 0)
        flags_box.pack_start(self.flag_df, False, False, 0)
        flags_box.pack_start(self.flag_mf, False, False, 0)
        grid.attach(flags_box, 1, 6, 1, 1)

        # 8. Fragment Offset
        frag_label = Gtk.Label(label="Fragment Offset")
        grid.attach(frag_label, 0, 7, 1, 1)
        self.frag_spin = Gtk.SpinButton()
        self.frag_spin.set_adjustment(Gtk.Adjustment(0, 0, 8191, 1, 10, 0))
        self.frag_spin.set_value(0)
        grid.attach(self.frag_spin, 1, 7, 1, 1)

        # 9. TTL
        ttl_label = Gtk.Label(label="TTL")
        grid.attach(ttl_label, 0, 8, 1, 1)
        self.ttl_spin = Gtk.SpinButton()
        self.ttl_spin.set_adjustment(Gtk.Adjustment(64, 0, 255, 1, 10, 0))
        self.ttl_spin.set_value(64)
        grid.attach(self.ttl_spin, 1, 8, 1, 1)

        # 10. Protocol
        proto_label = Gtk.Label(label="Protocol")
        grid.attach(proto_label, 0, 9, 1, 1)
        self.proto_spin = Gtk.SpinButton()
        self.proto_spin.set_adjustment(Gtk.Adjustment(6, 0, 255, 1, 10, 0))  # 6 = TCP
        self.proto_spin.set_value(6)
        grid.attach(self.proto_spin, 1, 9, 1, 1)

        # 11. Header Checksum
        checksum_label = Gtk.Label(label="Header Checksum (0 for auto)")
        grid.attach(checksum_label, 0, 10, 1, 1)
        self.checksum_spin = Gtk.SpinButton()
        self.checksum_spin.set_adjustment(Gtk.Adjustment(0, 0, 65535, 1, 10, 0))
        self.checksum_spin.set_value(0)
        grid.attach(self.checksum_spin, 1, 10, 1, 1)

        # 12. Source IP
        srcip_label = Gtk.Label(label="Source IP")
        grid.attach(srcip_label, 0, 11, 1, 1)
        self.srcip_entry = Gtk.Entry()
        self.srcip_entry.set_text("192.168.1.10")
        grid.attach(self.srcip_entry, 1, 11, 1, 1)

        # 13. Destination IP
        dstip_label = Gtk.Label(label="Destination IP")
        grid.attach(dstip_label, 0, 12, 1, 1)
        self.dstip_entry = Gtk.Entry()
        self.dstip_entry.set_text("192.168.1.20")
        grid.attach(self.dstip_entry, 1, 12, 1, 1)

        # 14. Additional Data / Payload
        payload_label = Gtk.Label(label="Payload (Hex or ASCII)")
        grid.attach(payload_label, 0, 13, 1, 1)
        self.payload_textview = Gtk.TextView()
        self.payload_textview.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        payload_scrolled = Gtk.ScrolledWindow()
        payload_scrolled.set_hexpand(True)
        payload_scrolled.set_vexpand(True)
        payload_scrolled.add(self.payload_textview)
        grid.attach(payload_scrolled, 1, 13, 1, 1)

        # Buttons
        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        main_vbox.pack_start(button_box, False, False, 0)

        construct_button = Gtk.Button(label="Construct Packet")
        construct_button.connect("clicked", self.on_construct_clicked)
        button_box.pack_start(construct_button, True, True, 0)

        quit_button = Gtk.Button(label="Quit")
        quit_button.connect("clicked", lambda w: Gtk.main_quit())
        button_box.pack_start(quit_button, True, True, 0)

    def on_construct_clicked(self, button):
        # Read the fields
        version = self.version_spin.get_value_as_int()
        ihl = self.ihl_spin.get_value_as_int()
        dscp = self.dscp_spin.get_value_as_int()
        ecn = self.ecn_spin.get_value_as_int()
        tos = (dscp << 2) + ecn  # DSCP occupies top 6 bits, ECN the bottom 2 bits
        length = self.length_spin.get_value_as_int()
        ident = self.ident_spin.get_value_as_int()
        flags_val = 0
        if self.flag_reserved.get_active():
            flags_val |= 0x04  # Reserved bit
        if self.flag_df.get_active():
            flags_val |= 0x02  # Don't Fragment
        if self.flag_mf.get_active():
            flags_val |= 0x01  # More Fragments
        frag_offset = self.frag_spin.get_value_as_int()
        ttl = self.ttl_spin.get_value_as_int()
        proto = self.proto_spin.get_value_as_int()
        checksum = self.checksum_spin.get_value_as_int()
        src_ip = self.srcip_entry.get_text()
        dst_ip = self.dstip_entry.get_text()

        buf = self.payload_textview.get_buffer()
        start_iter, end_iter = buf.get_bounds()
        payload = buf.get_text(start_iter, end_iter, False)

        # Print out the specified fields
        print(f"Version: {version}")
        print(f"IHL: {ihl}")
        print(f"DSCP: {dscp} | ECN: {ecn} | TOS: {tos}")
        print(f"Total Length: {length}")
        print(f"Identification: {ident}")
        print(f"Flags Value: {flags_val:#03b} (binary)")
        print(f"Fragment Offset: {frag_offset}")
        print(f"TTL: {ttl}")
        print(f"Protocol: {proto}")
        print(f"Header Checksum: {checksum}")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Payload: {payload}")

        # Attempt to construct packet if scapy is available
        if has_scapy:
            ip_pkt = IP(
                version=version,
                ihl=ihl,
                tos=tos,
                len=length if length != 0 else None,  # Let scapy auto-fill if 0
                id=ident,
                flags=flags_val,
                frag=frag_offset,
                ttl=ttl,
                proto=proto,
                chksum=checksum if checksum != 0 else None,
                src=src_ip,
                dst=dst_ip
            )
            print("Constructed IP packet via Scapy:")
            print(ip_pkt.summary())
        else:
            print("Scapy is not installed. Install scapy (pip install scapy) to construct packets.")

def main():
    win = IPPacketWindow()
    win.connect("destroy", Gtk.main_quit)
    win.show_all()
    Gtk.main()

if __name__ == "__main__":
    main()

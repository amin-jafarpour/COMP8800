#!/usr/bin/env python3

# This example creates a PyGObject (GTK+ 3) GUI for specifying
# many of the main fields of a TCP packet. If Scapy is installed
# (via "pip install scapy"), clicking "Construct TCP Packet"
# will build the packet and print a summary. Otherwise, it will
# simply display the chosen parameters.

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk

try:
    from scapy.all import TCP
    has_scapy = True
except ImportError:
    has_scapy = False

class TCPPacketWindow(Gtk.Window):
    def __init__(self):
        super().__init__(title="TCP Packet Constructor")
        self.set_border_width(10)
        self.set_default_size(600, 500)

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

        # 3. Sequence Number
        seq_label = Gtk.Label(label="Sequence Number")
        grid.attach(seq_label, 0, 2, 1, 1)
        self.seq_spin = Gtk.SpinButton()
        self.seq_spin.set_adjustment(Gtk.Adjustment(1, 0, 4294967295, 1, 1000, 0))
        grid.attach(self.seq_spin, 1, 2, 1, 1)

        # 4. Acknowledgment Number
        ack_label = Gtk.Label(label="Acknowledgment Number")
        grid.attach(ack_label, 0, 3, 1, 1)
        self.ack_spin = Gtk.SpinButton()
        self.ack_spin.set_adjustment(Gtk.Adjustment(0, 0, 4294967295, 1, 1000, 0))
        grid.attach(self.ack_spin, 1, 3, 1, 1)

        # 5. Data Offset
        offset_label = Gtk.Label(label="Data Offset")
        grid.attach(offset_label, 0, 4, 1, 1)
        self.offset_spin = Gtk.SpinButton()
        # Typical minimum is 5 (when there are no TCP options)
        self.offset_spin.set_adjustment(Gtk.Adjustment(5, 5, 15, 1, 1, 0))
        grid.attach(self.offset_spin, 1, 4, 1, 1)

        # 6. Reserved bits
        reserved_label = Gtk.Label(label="Reserved Bits (3 bits)")
        grid.attach(reserved_label, 0, 5, 1, 1)
        self.reserved_spin = Gtk.SpinButton()
        self.reserved_spin.set_adjustment(Gtk.Adjustment(0, 0, 7, 1, 1, 0))
        grid.attach(self.reserved_spin, 1, 5, 1, 1)

        # 7. Control Flags (CWR, ECE, URG, ACK, PSH, RST, SYN, FIN)
        flags_label = Gtk.Label(label="Flags")
        grid.attach(flags_label, 0, 6, 1, 1)

        flags_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)

        self.flag_cwr = Gtk.CheckButton(label="CWR")
        self.flag_ece = Gtk.CheckButton(label="ECE")
        self.flag_urg = Gtk.CheckButton(label="URG")
        self.flag_ack = Gtk.CheckButton(label="ACK")
        self.flag_psh = Gtk.CheckButton(label="PSH")
        self.flag_rst = Gtk.CheckButton(label="RST")
        self.flag_syn = Gtk.CheckButton(label="SYN")
        self.flag_fin = Gtk.CheckButton(label="FIN")

        flags_box.pack_start(self.flag_cwr, False, False, 0)
        flags_box.pack_start(self.flag_ece, False, False, 0)
        flags_box.pack_start(self.flag_urg, False, False, 0)
        flags_box.pack_start(self.flag_ack, False, False, 0)
        flags_box.pack_start(self.flag_psh, False, False, 0)
        flags_box.pack_start(self.flag_rst, False, False, 0)
        flags_box.pack_start(self.flag_syn, False, False, 0)
        flags_box.pack_start(self.flag_fin, False, False, 0)
        grid.attach(flags_box, 1, 6, 1, 1)

        # 8. Window Size
        win_label = Gtk.Label(label="Window Size")
        grid.attach(win_label, 0, 7, 1, 1)
        self.window_spin = Gtk.SpinButton()
        self.window_spin.set_adjustment(Gtk.Adjustment(8192, 0, 65535, 1, 1000, 0))
        grid.attach(self.window_spin, 1, 7, 1, 1)

        # 9. Checksum
        checksum_label = Gtk.Label(label="Checksum (0 for auto)")
        grid.attach(checksum_label, 0, 8, 1, 1)
        self.checksum_spin = Gtk.SpinButton()
        self.checksum_spin.set_adjustment(Gtk.Adjustment(0, 0, 65535, 1, 1000, 0))
        grid.attach(self.checksum_spin, 1, 8, 1, 1)

        # 10. Urgent Pointer
        urp_label = Gtk.Label(label="Urgent Pointer")
        grid.attach(urp_label, 0, 9, 1, 1)
        self.urp_spin = Gtk.SpinButton()
        self.urp_spin.set_adjustment(Gtk.Adjustment(0, 0, 65535, 1, 1000, 0))
        grid.attach(self.urp_spin, 1, 9, 1, 1)

        # 11. Payload / Data
        payload_label = Gtk.Label(label="Payload (ASCII / Hex)")
        grid.attach(payload_label, 0, 10, 1, 1)
        self.payload_textview = Gtk.TextView()
        self.payload_textview.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)

        payload_scrolled = Gtk.ScrolledWindow()
        payload_scrolled.set_hexpand(True)
        payload_scrolled.set_vexpand(True)
        payload_scrolled.add(self.payload_textview)
        grid.attach(payload_scrolled, 1, 10, 1, 1)

        # Buttons
        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        main_vbox.pack_start(button_box, False, False, 0)

        construct_button = Gtk.Button(label="Construct TCP Packet")
        construct_button.connect("clicked", self.on_construct_clicked)
        button_box.pack_start(construct_button, True, True, 0)

        quit_button = Gtk.Button(label="Quit")
        quit_button.connect("clicked", lambda w: Gtk.main_quit())
        button_box.pack_start(quit_button, True, True, 0)

    def on_construct_clicked(self, button):
        # Read the fields
        sport = self.srcport_spin.get_value_as_int()
        dport = self.dstport_spin.get_value_as_int()
        seq = self.seq_spin.get_value_as_int()
        ack = self.ack_spin.get_value_as_int()
        dataofs = self.offset_spin.get_value_as_int()
        reserved = self.reserved_spin.get_value_as_int()

        # Build the flags string for scapy or compute the bits ourselves.
        # Typically, scapy uses "flags=" with a string like "S" or "FA",
        # but we can compute the integer value or we can build the string.
        # Here, let's build a string that scapy recognizes:
        flag_str = ""
        if self.flag_cwr.get_active():
            flag_str += "C"
        if self.flag_ece.get_active():
            flag_str += "E"
        if self.flag_urg.get_active():
            flag_str += "U"
        if self.flag_ack.get_active():
            flag_str += "A"
        if self.flag_psh.get_active():
            flag_str += "P"
        if self.flag_rst.get_active():
            flag_str += "R"
        if self.flag_syn.get_active():
            flag_str += "S"
        if self.flag_fin.get_active():
            flag_str += "F"

        window_size = self.window_spin.get_value_as_int()
        chksum = self.checksum_spin.get_value_as_int()
        urp = self.urp_spin.get_value_as_int()

        buf = self.payload_textview.get_buffer()
        start_iter, end_iter = buf.get_bounds()
        payload = buf.get_text(start_iter, end_iter, False)

        # Print the values
        print(f"Source Port: {sport}")
        print(f"Destination Port: {dport}")
        print(f"Sequence Number: {seq}")
        print(f"Acknowledgment Number: {ack}")
        print(f"Data Offset: {dataofs}")
        print(f"Reserved Bits: {reserved:#05b}")
        print(f"Flags String: {flag_str}")
        print(f"Window Size: {window_size}")
        print(f"Checksum: {chksum}")
        print(f"Urgent Pointer: {urp}")
        print(f"Payload: {payload}")

        if has_scapy:
            # scapy's TCP constructor
            tcp_pkt = TCP(
                sport=sport,
                dport=dport,
                seq=seq,
                ack=ack,
                dataofs=dataofs,
                reserved=reserved,
                flags=flag_str,
                window=window_size,
                chksum=chksum if chksum != 0 else None,
                urgptr=urp
            )
            print("Constructed TCP packet via Scapy:")
            print(tcp_pkt.summary())
        else:
            print("Scapy is not installed. Install scapy (pip install scapy) to construct packets.")

def main():
    win = TCPPacketWindow()
    win.connect("destroy", Gtk.main_quit)
    win.show_all()
    Gtk.main()

if __name__ == "__main__":
    main()

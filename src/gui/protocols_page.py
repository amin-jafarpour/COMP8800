#!/usr/bin/env python3

# This example creates a main window (MainWindow) with four buttons:
# - IP
# - TCP
# - UDP
# - ICMP
#
# Clicking each button will open a new window specialized for constructing
# that particular protocol (using Scapy, if installed).

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

# --- Attempt to import Scapy ---
try:
    from scapy.all import IP, TCP, UDP, ICMP
    has_scapy = True
except ImportError:
    has_scapy = False

# ------------------- IP Packet Window -------------------
class IPPacketWindow(Gtk.Window):
    def __init__(self):
        super().__init__(title="IP Packet Constructor")
        self.set_border_width(10)
        self.set_default_size(600, 500)

        main_vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.add(main_vbox)

        grid = Gtk.Grid(column_spacing=10, row_spacing=10)
        main_vbox.pack_start(grid, True, True, 0)

        # Version
        version_label = Gtk.Label(label="Version (4 for IPv4)")
        grid.attach(version_label, 0, 0, 1, 1)
        self.version_spin = Gtk.SpinButton()
        self.version_spin.set_adjustment(Gtk.Adjustment(4, 0, 15, 1, 5, 0))
        self.version_spin.set_value(4)
        grid.attach(self.version_spin, 1, 0, 1, 1)

        # IHL
        ihl_label = Gtk.Label(label="IHL (Header Length)")
        grid.attach(ihl_label, 0, 1, 1, 1)
        self.ihl_spin = Gtk.SpinButton()
        self.ihl_spin.set_adjustment(Gtk.Adjustment(5, 0, 15, 1, 5, 0))
        self.ihl_spin.set_value(5)
        grid.attach(self.ihl_spin, 1, 1, 1, 1)

        # DSCP
        dscp_label = Gtk.Label(label="DSCP")
        grid.attach(dscp_label, 0, 2, 1, 1)
        self.dscp_spin = Gtk.SpinButton()
        self.dscp_spin.set_adjustment(Gtk.Adjustment(0, 0, 63, 1, 5, 0))
        self.dscp_spin.set_value(0)
        grid.attach(self.dscp_spin, 1, 2, 1, 1)

        # ECN
        ecn_label = Gtk.Label(label="ECN")
        grid.attach(ecn_label, 0, 3, 1, 1)
        self.ecn_spin = Gtk.SpinButton()
        self.ecn_spin.set_adjustment(Gtk.Adjustment(0, 0, 3, 1, 2, 0))
        self.ecn_spin.set_value(0)
        grid.attach(self.ecn_spin, 1, 3, 1, 1)

        # Total Length
        length_label = Gtk.Label(label="Total Length")
        grid.attach(length_label, 0, 4, 1, 1)
        self.length_spin = Gtk.SpinButton()
        self.length_spin.set_adjustment(Gtk.Adjustment(20, 0, 65535, 1, 10, 0))
        self.length_spin.set_value(20)
        grid.attach(self.length_spin, 1, 4, 1, 1)

        # Identification
        identification_label = Gtk.Label(label="Identification")
        grid.attach(identification_label, 0, 5, 1, 1)
        self.ident_spin = Gtk.SpinButton()
        self.ident_spin.set_adjustment(Gtk.Adjustment(1, 0, 65535, 1, 10, 0))
        self.ident_spin.set_value(1)
        grid.attach(self.ident_spin, 1, 5, 1, 1)

        # Flags
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

        # Fragment Offset
        frag_label = Gtk.Label(label="Fragment Offset")
        grid.attach(frag_label, 0, 7, 1, 1)
        self.frag_spin = Gtk.SpinButton()
        self.frag_spin.set_adjustment(Gtk.Adjustment(0, 0, 8191, 1, 10, 0))
        self.frag_spin.set_value(0)
        grid.attach(self.frag_spin, 1, 7, 1, 1)

        # TTL
        ttl_label = Gtk.Label(label="TTL")
        grid.attach(ttl_label, 0, 8, 1, 1)
        self.ttl_spin = Gtk.SpinButton()
        self.ttl_spin.set_adjustment(Gtk.Adjustment(64, 0, 255, 1, 10, 0))
        self.ttl_spin.set_value(64)
        grid.attach(self.ttl_spin, 1, 8, 1, 1)

        # Protocol
        proto_label = Gtk.Label(label="Protocol")
        grid.attach(proto_label, 0, 9, 1, 1)
        self.proto_spin = Gtk.SpinButton()
        self.proto_spin.set_adjustment(Gtk.Adjustment(6, 0, 255, 1, 10, 0)) # 6=TCP
        self.proto_spin.set_value(6)
        grid.attach(self.proto_spin, 1, 9, 1, 1)

        # Header Checksum
        checksum_label = Gtk.Label(label="Header Checksum (0 for auto)")
        grid.attach(checksum_label, 0, 10, 1, 1)
        self.checksum_spin = Gtk.SpinButton()
        self.checksum_spin.set_adjustment(Gtk.Adjustment(0, 0, 65535, 1, 10, 0))
        self.checksum_spin.set_value(0)
        grid.attach(self.checksum_spin, 1, 10, 1, 1)

        # Source IP
        srcip_label = Gtk.Label(label="Source IP")
        grid.attach(srcip_label, 0, 11, 1, 1)
        self.srcip_entry = Gtk.Entry()
        self.srcip_entry.set_text("192.168.1.10")
        grid.attach(self.srcip_entry, 1, 11, 1, 1)

        # Destination IP
        dstip_label = Gtk.Label(label="Destination IP")
        grid.attach(dstip_label, 0, 12, 1, 1)
        self.dstip_entry = Gtk.Entry()
        self.dstip_entry.set_text("192.168.1.20")
        grid.attach(self.dstip_entry, 1, 12, 1, 1)

        # Payload
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

        construct_button = Gtk.Button(label="Construct IP Packet")
        construct_button.connect("clicked", self.on_construct_clicked)
        button_box.pack_start(construct_button, True, True, 0)

        quit_button = Gtk.Button(label="Close Window")
        quit_button.connect("clicked", lambda w: self.destroy())
        button_box.pack_start(quit_button, True, True, 0)

    def on_construct_clicked(self, button):
        version = self.version_spin.get_value_as_int()
        ihl = self.ihl_spin.get_value_as_int()
        dscp = self.dscp_spin.get_value_as_int()
        ecn = self.ecn_spin.get_value_as_int()
        tos = (dscp << 2) + ecn
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

        print(f"[IP] Version: {version}, IHL: {ihl}, TOS: {tos}, Length: {length}, ID: {ident}")
        print(f"[IP] Flags: {flags_val:#03b}, Fragment Offset: {frag_offset}, TTL: {ttl}, Protocol: {proto}")
        print(f"[IP] Checksum: {checksum}, Source IP: {src_ip}, Dest IP: {dst_ip}")
        print(f"[IP] Payload: {payload}")

        if has_scapy:
            ip_pkt = IP(
                version=version,
                ihl=ihl,
                tos=tos,
                len=length if length != 0 else None,
                id=ident,
                flags=flags_val,
                frag=frag_offset,
                ttl=ttl,
                proto=proto,
                chksum=checksum if checksum != 0 else None,
                src=src_ip,
                dst=dst_ip
            )
            print(f"Constructed IP Packet: {ip_pkt.summary()}")
        else:
            print("Scapy not available; install with 'pip install scapy' to construct packets.")


# ------------------- TCP Packet Window -------------------
class TCPPacketWindow(Gtk.Window):
    def __init__(self):
        super().__init__(title="TCP Packet Constructor")
        self.set_border_width(10)
        self.set_default_size(600, 500)

        main_vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.add(main_vbox)

        grid = Gtk.Grid(column_spacing=10, row_spacing=10)
        main_vbox.pack_start(grid, True, True, 0)

        # Source Port
        srcport_label = Gtk.Label(label="Source Port")
        grid.attach(srcport_label, 0, 0, 1, 1)
        self.srcport_spin = Gtk.SpinButton()
        self.srcport_spin.set_adjustment(Gtk.Adjustment(1234, 0, 65535, 1, 100, 0))
        grid.attach(self.srcport_spin, 1, 0, 1, 1)

        # Destination Port
        dstport_label = Gtk.Label(label="Destination Port")
        grid.attach(dstport_label, 0, 1, 1, 1)
        self.dstport_spin = Gtk.SpinButton()
        self.dstport_spin.set_adjustment(Gtk.Adjustment(80, 0, 65535, 1, 100, 0))
        grid.attach(self.dstport_spin, 1, 1, 1, 1)

        # Sequence Number
        seq_label = Gtk.Label(label="Sequence Number")
        grid.attach(seq_label, 0, 2, 1, 1)
        self.seq_spin = Gtk.SpinButton()
        self.seq_spin.set_adjustment(Gtk.Adjustment(1, 0, 4294967295, 1, 1000, 0))
        grid.attach(self.seq_spin, 1, 2, 1, 1)

        # Acknowledgment Number
        ack_label = Gtk.Label(label="Acknowledgment Number")
        grid.attach(ack_label, 0, 3, 1, 1)
        self.ack_spin = Gtk.SpinButton()
        self.ack_spin.set_adjustment(Gtk.Adjustment(0, 0, 4294967295, 1, 1000, 0))
        grid.attach(self.ack_spin, 1, 3, 1, 1)

        # Data Offset
        offset_label = Gtk.Label(label="Data Offset")
        grid.attach(offset_label, 0, 4, 1, 1)
        self.offset_spin = Gtk.SpinButton()
        self.offset_spin.set_adjustment(Gtk.Adjustment(5, 5, 15, 1, 1, 0))
        grid.attach(self.offset_spin, 1, 4, 1, 1)

        # Reserved bits
        reserved_label = Gtk.Label(label="Reserved Bits (3 bits)")
        grid.attach(reserved_label, 0, 5, 1, 1)
        self.reserved_spin = Gtk.SpinButton()
        self.reserved_spin.set_adjustment(Gtk.Adjustment(0, 0, 7, 1, 1, 0))
        grid.attach(self.reserved_spin, 1, 5, 1, 1)

        # Flags
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

        # Window Size
        win_label = Gtk.Label(label="Window Size")
        grid.attach(win_label, 0, 7, 1, 1)
        self.window_spin = Gtk.SpinButton()
        self.window_spin.set_adjustment(Gtk.Adjustment(8192, 0, 65535, 1, 1000, 0))
        grid.attach(self.window_spin, 1, 7, 1, 1)

        # Checksum
        checksum_label = Gtk.Label(label="Checksum (0 for auto)")
        grid.attach(checksum_label, 0, 8, 1, 1)
        self.checksum_spin = Gtk.SpinButton()
        self.checksum_spin.set_adjustment(Gtk.Adjustment(0, 0, 65535, 1, 1000, 0))
        grid.attach(self.checksum_spin, 1, 8, 1, 1)

        # Urgent Pointer
        urp_label = Gtk.Label(label="Urgent Pointer")
        grid.attach(urp_label, 0, 9, 1, 1)
        self.urp_spin = Gtk.SpinButton()
        self.urp_spin.set_adjustment(Gtk.Adjustment(0, 0, 65535, 1, 1000, 0))
        grid.attach(self.urp_spin, 1, 9, 1, 1)

        # Payload
        payload_label = Gtk.Label(label="Payload (ASCII/Hex)")
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

        quit_button = Gtk.Button(label="Close Window")
        quit_button.connect("clicked", lambda w: self.destroy())
        button_box.pack_start(quit_button, True, True, 0)

    def on_construct_clicked(self, button):
        sport = self.srcport_spin.get_value_as_int()
        dport = self.dstport_spin.get_value_as_int()
        seq = self.seq_spin.get_value_as_int()
        ack = self.ack_spin.get_value_as_int()
        dataofs = self.offset_spin.get_value_as_int()
        reserved = self.reserved_spin.get_value_as_int()

        # Construct the flags string
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

        print("[TCP] Source Port:", sport)
        print("[TCP] Destination Port:", dport)
        print("[TCP] Sequence:", seq)
        print("[TCP] Acknowledgment:", ack)
        print("[TCP] Data Offset:", dataofs)
        print("[TCP] Reserved:", reserved)
        print("[TCP] Flags:", flag_str)
        print("[TCP] Window:", window_size)
        print("[TCP] Checksum:", chksum)
        print("[TCP] Urgent Pointer:", urp)
        print("[TCP] Payload:", payload)

        if has_scapy:
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
            print(f"Constructed TCP Packet: {tcp_pkt.summary()}")
        else:
            print("Scapy not available; install with 'pip install scapy' to construct packets.")


# ------------------- UDP Packet Window -------------------
class UDPPacketWindow(Gtk.Window):
    def __init__(self):
        super().__init__(title="UDP Packet Constructor")
        self.set_border_width(10)
        self.set_default_size(600, 400)

        main_vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.add(main_vbox)

        grid = Gtk.Grid(column_spacing=10, row_spacing=10)
        main_vbox.pack_start(grid, True, True, 0)

        # Source Port
        srcport_label = Gtk.Label(label="Source Port")
        grid.attach(srcport_label, 0, 0, 1, 1)
        self.srcport_spin = Gtk.SpinButton()
        self.srcport_spin.set_adjustment(Gtk.Adjustment(1234, 0, 65535, 1, 100, 0))
        grid.attach(self.srcport_spin, 1, 0, 1, 1)

        # Destination Port
        dstport_label = Gtk.Label(label="Destination Port")
        grid.attach(dstport_label, 0, 1, 1, 1)
        self.dstport_spin = Gtk.SpinButton()
        self.dstport_spin.set_adjustment(Gtk.Adjustment(80, 0, 65535, 1, 100, 0))
        grid.attach(self.dstport_spin, 1, 1, 1, 1)

        # Length
        length_label = Gtk.Label(label="Length (0 for auto)")
        grid.attach(length_label, 0, 2, 1, 1)
        self.len_spin = Gtk.SpinButton()
        self.len_spin.set_adjustment(Gtk.Adjustment(0, 0, 65535, 1, 100, 0))
        grid.attach(self.len_spin, 1, 2, 1, 1)

        # Checksum
        checksum_label = Gtk.Label(label="Checksum (0 for auto)")
        grid.attach(checksum_label, 0, 3, 1, 1)
        self.checksum_spin = Gtk.SpinButton()
        self.checksum_spin.set_adjustment(Gtk.Adjustment(0, 0, 65535, 1, 100, 0))
        grid.attach(self.checksum_spin, 1, 3, 1, 1)

        # Payload
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

        quit_button = Gtk.Button(label="Close Window")
        quit_button.connect("clicked", lambda w: self.destroy())
        button_box.pack_start(quit_button, True, True, 0)

    def on_construct_clicked(self, button):
        sport = self.srcport_spin.get_value_as_int()
        dport = self.dstport_spin.get_value_as_int()
        length = self.len_spin.get_value_as_int()
        chksum = self.checksum_spin.get_value_as_int()

        buf = self.payload_textview.get_buffer()
        start_iter, end_iter = buf.get_bounds()
        payload = buf.get_text(start_iter, end_iter, False)

        print("[UDP] Source Port:", sport)
        print("[UDP] Destination Port:", dport)
        print("[UDP] Length:", length)
        print("[UDP] Checksum:", chksum)
        print("[UDP] Payload:", payload)

        if has_scapy:
            udp_pkt = UDP(
                sport=sport,
                dport=dport,
                len=length if length != 0 else None,
                chksum=chksum if chksum != 0 else None
            )
            print(f"Constructed UDP Packet: {udp_pkt.summary()}")
        else:
            print("Scapy not available; install with 'pip install scapy' to construct packets.")


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

    def on_construct_clicked(self, button):
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
            print(f"Constructed Ethernet Frame: {ether_frame.summary()}")
        else:
            print("Scapy not available; install with 'pip install scapy' to construct frames.")



# ------------------- Main Window with Buttons -------------------
class MainWindow(Gtk.Window):
    def __init__(self):
        super().__init__(title="Protocol Packet Constructor")
        self.set_border_width(10)
        self.set_default_size(300, 200)

        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.add(vbox)

        label = Gtk.Label(label="Choose a protocol to construct:")
        vbox.pack_start(label, False, False, 0)

        ip_button = Gtk.Button(label="IP")
        ip_button.connect("clicked", self.on_ip_clicked)
        vbox.pack_start(ip_button, True, True, 0)

        tcp_button = Gtk.Button(label="TCP")
        tcp_button.connect("clicked", self.on_tcp_clicked)
        vbox.pack_start(tcp_button, True, True, 0)

        udp_button = Gtk.Button(label="UDP")
        udp_button.connect("clicked", self.on_udp_clicked)
        vbox.pack_start(udp_button, True, True, 0)

        icmp_button = Gtk.Button(label="ICMP")
        icmp_button.connect("clicked", self.on_icmp_clicked)
        vbox.pack_start(icmp_button, True, True, 0)



        ether_button = Gtk.Button(label="Ether")
        ether_button.connect("clicked", self.on_ether_clicked)
        vbox.pack_start(ether_button, True, True, 0)


        quit_button = Gtk.Button(label="Quit")
        quit_button.connect("clicked", lambda w: Gtk.main_quit())
        vbox.pack_start(quit_button, True, True, 0)

    def on_ip_clicked(self, button):
        ip_window = IPPacketWindow()
        ip_window.show_all()

    def on_tcp_clicked(self, button):
        tcp_window = TCPPacketWindow()
        tcp_window.show_all()

    def on_udp_clicked(self, button):
        udp_window = UDPPacketWindow()
        udp_window.show_all()

    def on_icmp_clicked(self, button):
        icmp_window = ICMPPacketWindow()
        icmp_window.show_all()

    def on_ether_clicked(self, button):
        ether_window = EthernetWindow()
        ether_window.show_all()


def main():
    win = MainWindow()
    win.connect("destroy", Gtk.main_quit)
    win.show_all()
    Gtk.main()

if __name__ == "__main__":
    main()

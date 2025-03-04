#!/usr/bin/env python3

# This example creates a main window (MainWindow) with four buttons:
# - IP
# - TCP
# - UDP
# - ICMP
# - Ether
# Clicking each button will open a new window specialized for constructing
# that particular protocol (using Scapy, if installed).

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

# # --- Attempt to import Scapy ---
# try:
#     from scapy.all import IP, TCP, UDP, ICMP, Ether
#     has_scapy = True
# except ImportError:
#     has_scapy = False


from old_gui.ether_gui import EthernetWindow
from old_gui.tcp_gui import TCPPacketWindow
from old_gui.udp_gui import UDPPacketWindow
from old_gui.ip_gui import IPPacketWindow
from old_gui.icmp_gui import ICMPPacketWindow






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

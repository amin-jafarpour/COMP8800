#!/usr/bin/env python3

# This example expands our previous multi-protocol GUI to include a
# "Data Link Layer" page for constructing basic Ethernet frames.
#
# If Scapy is installed (pip install scapy), clicking "Construct Ethernet Frame"
# will build the Ether frame and print a summary. Otherwise, it will just print
# the fields. This class is called EthernetWindow, and we'll add a corresponding
# button in the MainWindow to open it.

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

# --- Attempt to import Scapy ---
try:
    from scapy.all import Ether
    has_scapy = True
except ImportError:
    has_scapy = False



# ------------------- Example of integrating with an existing MainWindow -------------------
# If you already have a main window with other protocol buttons, you can add a button for the
# Data Link layer and connect it to create an instance of EthernetWindow:
#
# class MainWindow(Gtk.Window):
#     def __init__(self):
#         super().__init__(title="Protocol Packet Constructor")
#         self.set_border_width(10)
#         self.set_default_size(300, 200)
#
#         vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
#         self.add(vbox)
#
#         label = Gtk.Label(label="Choose a protocol to construct:")
#         vbox.pack_start(label, False, False, 0)
#
#         datalink_button = Gtk.Button(label="Data Link (Ethernet)")
#         datalink_button.connect("clicked", self.on_ethernet_clicked)
#         vbox.pack_start(datalink_button, True, True, 0)
#
#         quit_button = Gtk.Button(label="Quit")
#         quit_button.connect("clicked", lambda w: Gtk.main_quit())
#         vbox.pack_start(quit_button, True, True, 0)
#
#     def on_ethernet_clicked(self, button):
#         ether_window = EthernetWindow()
#         ether_window.show_all()
#
# def main():
#     win = MainWindow()
#     win.connect("destroy", Gtk.main_quit)
#     win.show_all()
#     Gtk.main()
#
# if __name__ == "__main__":
#     main()

def main():
    # Simple demo: if you only want to run the Ethernet frame constructor by itself:
    win = EthernetWindow()
    win.connect("destroy", Gtk.main_quit)
    win.show_all()
    Gtk.main()

if __name__ == "__main__":
    main()

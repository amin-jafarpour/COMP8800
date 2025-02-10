import gi
import math
import random
import sys

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk


from network_scan import get_network_lst

class RadarWindow(Gtk.Window, iface: str, pkt_count: int):
    def __init__(self):
        super().__init__(title="Network Detector")
        self.set_default_size(1000, 500)
        self.set_resizable(True)
        self.connect("destroy", Gtk.main_quit)
        
        self.targets = self.network_targets(get_network_lst(iface, pkt_count)) # $ popualte with networks
        
        self.drawing_area = Gtk.DrawingArea()
        self.drawing_area.set_size_request(1000, 500) # $ change to current window size
        self.drawing_area.connect("draw", self.on_draw)
        self.drawing_area.add_events(Gdk.EventMask.BUTTON_PRESS_MASK)
        self.drawing_area.connect("button-press-event", self.on_click)
        
        self.add(self.drawing_area)

    def network_targets(self, network_lst):
        targets = []
        for network in network_lst:
            value = network['dBm_AntSignal']
            angle = random.uniform(0, 2 * math.pi)
            distance = (100 + value) * 2  # Scale to fit radar
            x = 500 + distance * math.cos(angle)
            y = 250 + distance * math.sin(angle)
            targets.append({"x": x, "y": y, "value": value, "network": network})
        return targets
    
    def on_draw(self, _, cr):
        # Draw Radar Circles
        cr.set_source_rgb(0, 0.5, 0)
        cr.paint()
        
        cr.set_source_rgb(0, 1, 0)
        for i in range(1, 5):
            cr.arc(500, 250, i * 50, 0, 2 * math.pi) # 250
            cr.stroke()
        
        # Draw Lines
        for angle in range(0, 360, 45):
            rad = math.radians(angle)
            cr.move_to(500, 250)
            cr.line_to(500 + 200 * math.cos(rad), 250 + 200 * math.sin(rad))
            cr.stroke()
        
        # Draw Targets
        for target in self.targets:
            cr.set_source_rgb(1, 0, 0)
            cr.arc(target["x"], target["y"], 5, 0, 2 * math.pi)
            cr.fill()
    
    def on_click(self, _, event):
        for target in self.targets:
            if math.hypot(event.x - target["x"], event.y - target["y"]) < 5:
                TargetInfoWindow(target)
                break

class TargetInfoWindow(Gtk.Window):
    def __init__(self, target):
        super().__init__(title="Network Information")
        self.set_default_size(200, 100)
        label = Gtk.Label(label=str(target['network']))
        self.add(label)
        self.show_all()



def main():
    win = RadarWindow(sys.argv[1], int(sys.argv[2]))
    win.show_all()
    Gtk.main()



if __name__ '__main__':
    if len(sys.argv) < 3:
        print('Error: Missing comamnd line arguments.')
        print(f'{sys.argv[0]} <Interface> <PacketCount>')
        sys.exit(1)
    


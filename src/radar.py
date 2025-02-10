import gi
import math
import random

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk

class RadarWindow(Gtk.Window):
    def __init__(self):
        super().__init__(title="Network Detector")
        self.set_default_size(500, 500)
        self.set_resizable(False)
        self.connect("destroy", Gtk.main_quit)
        
        self.targets = self.generate_targets(10)
        
        self.drawing_area = Gtk.DrawingArea()
        self.drawing_area.set_size_request(500, 500)
        self.drawing_area.connect("draw", self.on_draw)
        self.drawing_area.add_events(Gdk.EventMask.BUTTON_PRESS_MASK)
        self.drawing_area.connect("button-press-event", self.on_click)
        
        self.add(self.drawing_area)

    def generate_targets(self, num_targets):
        targets = []
        for _ in range(num_targets):
            value = random.uniform(0, 100)
            angle = random.uniform(0, 2 * math.pi)
            distance = (100 - value) * 2  # Scale to fit radar
            x = 250 + distance * math.cos(angle)
            y = 250 + distance * math.sin(angle)
            targets.append({"x": x, "y": y, "value": value})
        return targets
    
    def on_draw(self, widget, cr):
        # Draw Radar Circles
        cr.set_source_rgb(0, 0.5, 0)
        cr.paint()
        
        cr.set_source_rgb(0, 1, 0)
        for i in range(1, 5):
            cr.arc(250, 250, i * 50, 0, 2 * math.pi)
            cr.stroke()
        
        # Draw Lines
        for angle in range(0, 360, 45):
            rad = math.radians(angle)
            cr.move_to(250, 250)
            cr.line_to(250 + 200 * math.cos(rad), 250 + 200 * math.sin(rad))
            cr.stroke()
        
        # Draw Targets
        for target in self.targets:
            cr.set_source_rgb(1, 0, 0)
            cr.arc(target["x"], target["y"], 5, 0, 2 * math.pi)
            cr.fill()
    
    def on_click(self, widget, event):
        for target in self.targets:
            if math.hypot(event.x - target["x"], event.y - target["y"]) < 5:
                TargetInfoWindow(target)
                break

class TargetInfoWindow(Gtk.Window):
    def __init__(self, target):
        super().__init__(title="Target Information")
        self.set_default_size(200, 100)
        
        label = Gtk.Label(label=f"Target Value: {target['value']:.2f}")
        self.add(label)
        
        self.show_all()

if __name__ == "__main__":
    win = RadarWindow()
    win.show_all()
    Gtk.main()


#!/usr/bin/env python3

# If you're using GTK 3+ in Python, you'll typically use PyGObject rather than the older PyGTK.
# The following code demonstrates how to build a simple form-like interface with a variety
# of input fields (string, numeric, boolean, etc.) using PyGObject.

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk

class DataEntryWindow(Gtk.Window):
    def __init__(self):
        super().__init__(title="Data Entry Example")
        self.set_default_size(400, 300)
        self.set_border_width(10)

        # Create a main vertical box
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.add(vbox)

        # Use a grid for placing labels and input widgets side by side
        grid = Gtk.Grid()
        grid.set_column_spacing(10)
        grid.set_row_spacing(10)
        vbox.pack_start(grid, True, True, 0)

        # Apply some background color or style to make it look more appealing
        css_provider = Gtk.CssProvider()
        css_provider.load_from_data(b"""
            #data-grid {
                background-color: #f0f0f0;
                border-radius: 8px;
                padding: 10px;
            }
            .title-label {
                font-weight: bold;
            }
            .entry-box {
                background-color: #ffffff;
                border-radius: 4px;
                padding: 2px;
            }
        """)
        grid.set_name("data-grid")

        style_context = grid.get_style_context()
        style_context.add_provider(css_provider, Gtk.STYLE_PROVIDER_PRIORITY_USER)

        # Name (string)
        name_label = Gtk.Label(label="Name:")
        name_label.get_style_context().add_class("title-label")
        grid.attach(name_label, 0, 0, 1, 1)

        self.name_entry = Gtk.Entry()
        self.name_entry.get_style_context().add_class("entry-box")
        grid.attach(self.name_entry, 1, 0, 1, 1)

        # Age (integer) - use a spin button for clarity
        age_label = Gtk.Label(label="Age:")
        age_label.get_style_context().add_class("title-label")
        grid.attach(age_label, 0, 1, 1, 1)

        adjustment = Gtk.Adjustment(value=18, lower=0, upper=120, step_increment=1, page_increment=10)
        self.age_spin = Gtk.SpinButton(adjustment=adjustment, climb_rate=1, digits=0)
        self.age_spin.get_style_context().add_class("entry-box")
        grid.attach(self.age_spin, 1, 1, 1, 1)

        # Score (float) - another spin button but allowing decimal
        score_label = Gtk.Label(label="Score:")
        score_label.get_style_context().add_class("title-label")
        grid.attach(score_label, 0, 2, 1, 1)

        score_adjustment = Gtk.Adjustment(value=0.0, lower=0.0, upper=100.0, step_increment=0.5, page_increment=10)
        self.score_spin = Gtk.SpinButton(adjustment=score_adjustment, climb_rate=1, digits=1)
        self.score_spin.get_style_context().add_class("entry-box")
        grid.attach(self.score_spin, 1, 2, 1, 1)

        # Boolean (check button)
        accept_label = Gtk.Label(label="Accept Terms:")
        accept_label.get_style_context().add_class("title-label")
        grid.attach(accept_label, 0, 3, 1, 1)

        self.accept_check = Gtk.CheckButton()
        grid.attach(self.accept_check, 1, 3, 1, 1)

        # Dropdown (combo box) example
        combo_label = Gtk.Label(label="Choose an Option:")
        combo_label.get_style_context().add_class("title-label")
        grid.attach(combo_label, 0, 4, 1, 1)

        self.combo_store = Gtk.ListStore(str)
        for item in ["Option A", "Option B", "Option C"]:
            self.combo_store.append([item])

        self.combo_box = Gtk.ComboBox.new_with_model(self.combo_store)
        renderer_text = Gtk.CellRendererText()
        self.combo_box.pack_start(renderer_text, True)
        self.combo_box.add_attribute(renderer_text, "text", 0)
        grid.attach(self.combo_box, 1, 4, 1, 1)

        # Buttons
        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        vbox.pack_start(button_box, False, False, 0)

        submit_button = Gtk.Button(label="Submit")
        submit_button.connect("clicked", self.on_submit_clicked)
        button_box.pack_start(submit_button, True, True, 0)

        cancel_button = Gtk.Button(label="Cancel")
        cancel_button.connect("clicked", self.on_cancel_clicked)
        button_box.pack_start(cancel_button, True, True, 0)

    def on_submit_clicked(self, widget):
        name = self.name_entry.get_text()
        age = self.age_spin.get_value_as_int()
        score = self.score_spin.get_value()
        accepted_terms = self.accept_check.get_active()

        tree_iter = self.combo_box.get_active_iter()
        dropdown_selection = self.combo_store[tree_iter][0] if tree_iter else None

        print(f"Name: {name}")
        print(f"Age: {age}")
        print(f"Score: {score}")
        print(f"Accepted Terms? {accepted_terms}")
        print(f"Dropdown Selection: {dropdown_selection}")

    def on_cancel_clicked(self, widget):
        Gtk.main_quit()

def main():
    win = DataEntryWindow()
    win.connect("destroy", Gtk.main_quit)
    win.show_all()
    Gtk.main()

if __name__ == "__main__":
    main()


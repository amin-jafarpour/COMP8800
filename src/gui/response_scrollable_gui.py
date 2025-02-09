import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk


class ResponseScrollableWindow(Gtk.Window):
    def __init__(self, display_text=""):
        super().__init__(title="Scrollable Text Viewer")
        self.set_default_size(400, 300)  # Window size

        # Create a scrolled window
        scrolled_window = Gtk.ScrolledWindow()
        scrolled_window.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.ALWAYS)  # Always show vertical scrollbar

        # Create a TextView inside the scrolled window
        text_view = Gtk.TextView()
        text_view.set_editable(False)  # Read-only
        text_view.set_wrap_mode(Gtk.WrapMode.WORD)  # Wrap long lines

        # Add sample text
        buffer = text_view.get_buffer()
        # sample_text = "\n".join([f"Line {i}" for i in range(1, 101)])  # 100 lines of text
        buffer.set_text(display_text)

        # Add TextView to ScrolledWindow
        scrolled_window.add(text_view)

        # Add ScrolledWindow to Window
        self.add(scrolled_window)

        # Close event
        self.connect("destroy", Gtk.main_quit)


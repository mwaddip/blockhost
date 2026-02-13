#!/usr/bin/env python3
"""Systray toggle for BlockHost CI ramdisk (/mnt/ramdisk)."""

import subprocess
import os
import signal
import gi
gi.require_version('Gtk', '3.0')
gi.require_version('AyatanaAppIndicator3', '0.1')
from gi.repository import Gtk, AyatanaAppIndicator3, GLib

MOUNT_POINT = "/mnt/ramdisk"
SIZE = "16G"
POLL_INTERVAL = 5000  # ms


def is_mounted():
    return os.path.ismount(MOUNT_POINT)


def mount():
    subprocess.run(["sudo", "mkdir", "-p", MOUNT_POINT], check=True)
    subprocess.run(
        ["sudo", "mount", "-t", "tmpfs", "-o", f"size={SIZE}", "tmpfs", MOUNT_POINT],
        check=True
    )


def unmount():
    subprocess.run(["sudo", "umount", MOUNT_POINT], check=True)


def get_usage():
    if not is_mounted():
        return None
    result = subprocess.run(
        ["df", "-h", MOUNT_POINT],
        capture_output=True, text=True
    )
    parts = result.stdout.strip().split('\n')[-1].split()
    return f"{parts[2]}/{parts[1]} ({parts[4]})"


def update_indicator(indicator, menu_items):
    mounted = is_mounted()
    indicator.set_icon_full(
        "ramdisk-on" if mounted else "ramdisk-off",
        "BlockHost Ramdisk"
    )

    if mounted:
        usage = get_usage()
        indicator.set_label(f" {usage}" if usage else "", "")
        menu_items['toggle'].set_label("Unmount Ramdisk")
        menu_items['status'].set_label(f"Mounted: {MOUNT_POINT} ({SIZE})")
    else:
        indicator.set_label("", "")
        menu_items['toggle'].set_label("Mount Ramdisk")
        menu_items['status'].set_label("Not mounted")

    return True


def on_toggle(_):
    try:
        if is_mounted():
            unmount()
        else:
            mount()
    except subprocess.CalledProcessError as e:
        dialog = Gtk.MessageDialog(
            message_type=Gtk.MessageType.ERROR,
            buttons=Gtk.ButtonsType.OK,
            text=f"Failed: {e}"
        )
        dialog.run()
        dialog.destroy()


def main():
    icon_dir = os.path.expanduser("~/.local/share/blockhost-icons")
    indicator = AyatanaAppIndicator3.Indicator.new(
        "blockhost-ramdisk",
        "ramdisk-off",
        AyatanaAppIndicator3.IndicatorCategory.SYSTEM_SERVICES
    )
    indicator.set_icon_theme_path(icon_dir)
    indicator.set_status(AyatanaAppIndicator3.IndicatorStatus.ACTIVE)
    indicator.set_title("BlockHost Ramdisk")

    menu = Gtk.Menu()

    status_item = Gtk.MenuItem(label="")
    status_item.set_sensitive(False)
    menu.append(status_item)

    menu.append(Gtk.SeparatorMenuItem())

    toggle_item = Gtk.MenuItem(label="Toggle")
    toggle_item.connect("activate", on_toggle)
    menu.append(toggle_item)

    menu.append(Gtk.SeparatorMenuItem())

    quit_item = Gtk.MenuItem(label="Quit")
    quit_item.connect("activate", lambda _: Gtk.main_quit())
    menu.append(quit_item)

    menu.show_all()
    indicator.set_menu(menu)
    indicator.set_secondary_activate_target(toggle_item)

    menu_items = {'toggle': toggle_item, 'status': status_item}
    update_indicator(indicator, menu_items)
    GLib.timeout_add(POLL_INTERVAL, update_indicator, indicator, menu_items)

    signal.signal(signal.SIGINT, signal.SIG_DFL)
    Gtk.main()


if __name__ == "__main__":
    main()

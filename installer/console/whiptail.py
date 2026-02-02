"""
Whiptail wrapper for console-based UI.

Provides a Python interface to whiptail (or dialog as fallback)
for ncurses-style user interfaces.
"""

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass
class DialogResult:
    """Result from a dialog."""
    returncode: int
    value: str

    @property
    def ok(self) -> bool:
        """User selected OK/Yes."""
        return self.returncode == 0

    @property
    def cancelled(self) -> bool:
        """User cancelled."""
        return self.returncode == 1


class Whiptail:
    """Wrapper for whiptail/dialog commands."""

    def __init__(self, title: str = "BlockHost Installer",
                 width: int = 70, height: int = 20):
        """
        Initialize whiptail wrapper.

        Args:
            title: Default dialog title
            width: Default dialog width
            height: Default dialog height
        """
        self.title = title
        self.width = width
        self.height = height
        self._backend = self._detect_backend()

    def _detect_backend(self) -> str:
        """Detect available dialog backend."""
        if shutil.which('whiptail'):
            return 'whiptail'
        if shutil.which('dialog'):
            return 'dialog'
        raise RuntimeError("Neither whiptail nor dialog found")

    def _run(self, args: list[str], input_text: Optional[str] = None) -> DialogResult:
        """
        Run dialog command.

        Args:
            args: Command arguments
            input_text: Optional input to send to stdin

        Returns:
            DialogResult with returncode and output
        """
        cmd = [self._backend, '--title', self.title] + args

        # Dialog output goes to stderr
        result = subprocess.run(
            cmd,
            input=input_text.encode() if input_text else None,
            capture_output=True,
            env={**os.environ, 'TERM': os.environ.get('TERM', 'linux')},
        )

        return DialogResult(
            returncode=result.returncode,
            value=result.stderr.decode().strip()
        )

    def msgbox(self, text: str, height: Optional[int] = None,
               width: Optional[int] = None) -> DialogResult:
        """
        Display a message box with OK button.

        Args:
            text: Message to display
            height: Dialog height (default: auto)
            width: Dialog width (default: auto)
        """
        h = height or min(len(text.split('\n')) + 7, 25)
        w = width or self.width
        return self._run(['--msgbox', text, str(h), str(w)])

    def yesno(self, text: str, height: Optional[int] = None,
              width: Optional[int] = None, default_no: bool = False) -> DialogResult:
        """
        Display a yes/no dialog.

        Args:
            text: Question to ask
            height: Dialog height
            width: Dialog width
            default_no: Default to No button
        """
        h = height or min(len(text.split('\n')) + 7, 20)
        w = width or self.width
        args = ['--yesno', text, str(h), str(w)]
        if default_no:
            args.insert(0, '--defaultno')
        return self._run(args)

    def inputbox(self, text: str, default: str = "",
                 height: Optional[int] = None,
                 width: Optional[int] = None) -> DialogResult:
        """
        Display an input box.

        Args:
            text: Prompt text
            default: Default value
            height: Dialog height
            width: Dialog width
        """
        h = height or 10
        w = width or self.width
        return self._run(['--inputbox', text, str(h), str(w), default])

    def passwordbox(self, text: str, height: Optional[int] = None,
                    width: Optional[int] = None) -> DialogResult:
        """
        Display a password input box (hidden input).

        Args:
            text: Prompt text
            height: Dialog height
            width: Dialog width
        """
        h = height or 10
        w = width or self.width
        return self._run(['--passwordbox', text, str(h), str(w)])

    def menu(self, text: str, choices: list[tuple[str, str]],
             height: Optional[int] = None,
             width: Optional[int] = None,
             menu_height: Optional[int] = None) -> DialogResult:
        """
        Display a menu.

        Args:
            text: Menu title/description
            choices: List of (tag, description) tuples
            height: Dialog height
            width: Dialog width
            menu_height: Number of menu items to show
        """
        h = height or min(len(choices) + 10, 25)
        w = width or self.width
        mh = menu_height or min(len(choices), 15)

        args = ['--menu', text, str(h), str(w), str(mh)]
        for tag, desc in choices:
            args.extend([tag, desc])

        return self._run(args)

    def checklist(self, text: str, choices: list[tuple[str, str, bool]],
                  height: Optional[int] = None,
                  width: Optional[int] = None) -> DialogResult:
        """
        Display a checklist (multiple selection).

        Args:
            text: Prompt text
            choices: List of (tag, description, selected) tuples
            height: Dialog height
            width: Dialog width
        """
        h = height or min(len(choices) + 10, 25)
        w = width or self.width
        lh = min(len(choices), 15)

        args = ['--checklist', text, str(h), str(w), str(lh)]
        for tag, desc, selected in choices:
            args.extend([tag, desc, 'ON' if selected else 'OFF'])

        return self._run(args)

    def radiolist(self, text: str, choices: list[tuple[str, str, bool]],
                  height: Optional[int] = None,
                  width: Optional[int] = None) -> DialogResult:
        """
        Display a radiolist (single selection).

        Args:
            text: Prompt text
            choices: List of (tag, description, selected) tuples
            height: Dialog height
            width: Dialog width
        """
        h = height or min(len(choices) + 10, 25)
        w = width or self.width
        lh = min(len(choices), 15)

        args = ['--radiolist', text, str(h), str(w), str(lh)]
        for tag, desc, selected in choices:
            args.extend([tag, desc, 'ON' if selected else 'OFF'])

        return self._run(args)

    def gauge(self, text: str, percent: int,
              height: Optional[int] = None,
              width: Optional[int] = None) -> None:
        """
        Display a progress gauge (non-blocking, call repeatedly).

        Note: This is for simple one-shot display. For animated
        progress, use gauge_start/gauge_update/gauge_stop.

        Args:
            text: Progress text
            percent: Percentage complete (0-100)
            height: Dialog height
            width: Dialog width
        """
        h = height or 7
        w = width or self.width

        # Gauge reads from stdin and exits on EOF
        subprocess.run(
            [self._backend, '--gauge', text, str(h), str(w), str(percent)],
            input=b'',
            capture_output=True,
        )

    def infobox(self, text: str, height: Optional[int] = None,
                width: Optional[int] = None) -> None:
        """
        Display an info box (no buttons, returns immediately).

        Useful for displaying status while doing background work.

        Args:
            text: Message to display
            height: Dialog height
            width: Dialog width
        """
        h = height or min(len(text.split('\n')) + 4, 20)
        w = width or self.width

        subprocess.run(
            [self._backend, '--infobox', text, str(h), str(w)],
            capture_output=True,
        )

    def textbox(self, filepath: str, height: Optional[int] = None,
                width: Optional[int] = None) -> DialogResult:
        """
        Display file contents in a scrollable box.

        Args:
            filepath: Path to file to display
            height: Dialog height
            width: Dialog width
        """
        h = height or 20
        w = width or self.width
        return self._run(['--textbox', filepath, str(h), str(w)])


if __name__ == '__main__':
    # Demo/test
    wt = Whiptail(title="Whiptail Test")

    wt.msgbox("Welcome to the whiptail wrapper test!")

    result = wt.yesno("Do you want to continue?")
    if not result.ok:
        print("Cancelled")
        exit(0)

    result = wt.inputbox("Enter your name:", "User")
    if result.ok:
        name = result.value
        print(f"Name: {name}")

    result = wt.menu(
        "Select an option:",
        [
            ("1", "Option One"),
            ("2", "Option Two"),
            ("3", "Option Three"),
        ]
    )
    if result.ok:
        print(f"Selected: {result.value}")

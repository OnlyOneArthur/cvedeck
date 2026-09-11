"""Native keyboard navigation and read-only preview screens."""
from __future__ import annotations

from dataclasses import dataclass
from time import monotonic
from typing import ClassVar

from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import DataTable, Static


class VimTable(DataTable[Text]):
    _last_g = 0.0

    async def on_key(self, event: events.Key) -> None:
        key = event.key
        if key not in {"j", "k", "g", "G"}:
            self._last_g = 0.0
            return
        event.stop()
        event.prevent_default()
        if key == "j":
            self.action_cursor_down()
        elif key == "k":
            self.action_cursor_up()
        elif key == "G":
            self.move_cursor(row=max(0, self.row_count - 1))
        elif monotonic() - self._last_g < 0.7:
            self.move_cursor(row=0)
            self._last_g = 0.0
            return
        self._last_g = monotonic() if key == "g" else 0.0


class VimScroll(VerticalScroll):
    _last_g = 0.0

    async def on_key(self, event: events.Key) -> None:
        if event.key not in {"j", "k", "g", "G"}:
            self._last_g = 0.0
            return
        event.stop()
        event.prevent_default()
        if event.key == "j":
            self.scroll_down(animate=False)
        elif event.key == "k":
            self.scroll_up(animate=False)
        elif event.key == "G":
            self.scroll_end(animate=False)
        elif monotonic() - self._last_g < 0.7:
            self.scroll_home(animate=False)
            self._last_g = 0.0
            return
        self._last_g = monotonic() if event.key == "g" else 0.0


@dataclass(frozen=True)
class RecordPreview:
    record_id: str
    url: str
    body: str


class PreviewScreen(ModalScreen[None]):
    DEFAULT_CSS = """
    PreviewScreen { align: center middle; background: $background 70%; }
    PreviewScreen > VimScroll { width: 85%; height: 85%; border: round $accent; padding: 1 2; }
    PreviewScreen Static { height: auto; }
    """
    BINDINGS: ClassVar = [
        ("escape", "dismiss", "Close"), ("q", "app.quit", "Quit"),
        ("question_mark", "app.help", "Help"), ("o", "app.open_url", "Open"),
        ("y", "app.copy_url", "Copy URL"), ("e", "app.export", "Export"),
    ]

    def __init__(self, record: RecordPreview | None, body: str = "") -> None:
        super().__init__()
        self.record = record
        self.body = record.body if record else body

    def compose(self) -> ComposeResult:
        with VimScroll():
            yield Static(Text(self.body), id="preview-body")
            yield Static("Esc close · q quit · ? help" + (" · o open · y copy · e export" if self.record else ""))

    def on_mount(self) -> None:
        self.query_one(VimScroll).focus()

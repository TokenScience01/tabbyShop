"""Capture the GUI stack automatically when its event loop stops responding."""
from datetime import datetime
import os
from pathlib import Path
import sys
import threading
import time
import traceback

from PySide6.QtCore import QTimer


class UiWatchdog:
    def __init__(self, parent):
        self.last_beat = time.monotonic()
        self.main_thread = threading.get_ident()
        self.stopped = threading.Event()
        base = Path(os.environ.get('LOCALAPPDATA') or Path.home())
        self.path = base / 'TabbyDesktop' / 'logs' / 'ui-freeze.log'
        self.timer = QTimer(parent)
        self.timer.setInterval(250)
        self.timer.timeout.connect(self.beat)
        self.timer.start()
        threading.Thread(target=self.watch, name='ui-watchdog', daemon=True).start()

    def beat(self):
        self.last_beat = time.monotonic()

    def stop(self):
        self.timer.stop()
        self.stopped.set()

    def watch(self):
        reported = 0.0
        while not self.stopped.wait(1):
            now = time.monotonic()
            if now - self.last_beat < 2.5 or now - reported < 10:
                continue
            frame = sys._current_frames().get(self.main_thread)
            if frame is None:
                continue
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                if self.path.exists() and self.path.stat().st_size > 2_000_000:
                    self.path.replace(self.path.with_suffix('.previous.log'))
                with self.path.open('a', encoding='utf-8') as output:
                    output.write(f'\n{datetime.now().isoformat()} GUI stalled {now-self.last_beat:.1f}s\n')
                    output.writelines(traceback.format_stack(frame))
                reported = now
            except OSError:
                pass

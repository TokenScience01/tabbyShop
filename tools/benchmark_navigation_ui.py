"""Offline nine-account routing load with a Qt event-loop heartbeat."""
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'game_client'))


def main():
    from PySide6.QtCore import QCoreApplication, QTimer
    from navigation_service import submit_map_path, shutdown_navigation

    app = QCoreApplication([])
    gaps = []
    last = time.perf_counter()

    def heartbeat():
        nonlocal last
        now = time.perf_counter()
        gaps.append(now - last)
        last = now

    timer = QTimer()
    timer.setInterval(20)
    timer.timeout.connect(heartbeat)
    timer.start()
    started = time.perf_counter()
    jobs = [submit_map_path(1, (1039.25 + i, 1238.24), (-544, 928)) for i in range(9)]
    poll = QTimer()
    poll.setInterval(20)
    poll.timeout.connect(lambda: app.quit() if all(job.done() for job in jobs) else None)
    poll.start()
    QTimer.singleShot(30000, app.quit)
    app.exec()
    routes = [job.result(timeout=1) for job in jobs]
    shutdown_navigation()
    assert all(routes), 'Missing route'
    assert gaps, 'No Qt heartbeat'
    print(f'jobs={len(jobs)} elapsed={time.perf_counter()-started:.3f}s '
          f'max_qt_heartbeat_gap={max(gaps)*1000:.1f}ms')
    assert max(gaps) < 0.5, 'GUI event loop stalled for over 500ms'


if __name__ == '__main__':
    import multiprocessing
    multiprocessing.freeze_support()
    main()

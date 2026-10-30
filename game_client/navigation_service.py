"""Bound CPU-bound routing across all accounts without competing for the GUI GIL."""
from concurrent.futures import ProcessPoolExecutor
import atexit
import multiprocessing
import threading

from town_navigation import find_map_path, find_map_sweep_path

_pool = None
_pool_lock = threading.Lock()


def submit_map_path(map_id, start, goal):
    global _pool
    with _pool_lock:
        if _pool is None:
            _pool = ProcessPoolExecutor(max_workers=2,
                                       mp_context=multiprocessing.get_context('spawn'))
        if isinstance(goal, dict) and 'sweep' in goal:
            return _pool.submit(find_map_sweep_path, map_id, start, goal['sweep'])
        return _pool.submit(find_map_path, map_id, start, goal)


def shutdown_navigation():
    global _pool
    with _pool_lock:
        pool, _pool = _pool, None
    if pool is not None:
        pool.shutdown(wait=False, cancel_futures=True)


atexit.register(shutdown_navigation)

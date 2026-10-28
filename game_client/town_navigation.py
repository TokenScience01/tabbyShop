"""Offline path planning from the recovered Tabby Island scene."""

from __future__ import annotations

import heapq
import json
import math
from functools import lru_cache
from pathlib import Path


PLAYER_CLEARANCE = 16
MAP_FILES = {1: "town_navigation.json", 2: "snowfield_navigation.json", 7: "treasure_navigation.json"}


@lru_cache(maxsize=3)
def _map_data(map_id: int = 1) -> tuple[set[tuple[int, int]], list[dict]]:
    data = json.loads(Path(__file__).with_name(MAP_FILES[map_id]).read_text())
    return {tuple(cell) for cell in data["cells"]}, data["obstacles"]


@lru_cache(maxsize=3)
def _obstacle_bins(map_id: int) -> dict:
    """Index expanded collision bounds; retain the original ellipse test."""
    bins = {}
    for obstacle in _map_data(map_id)[1]:
        rx = obstacle['rx'] + PLAYER_CLEARANCE
        ry = obstacle['ry'] + PLAYER_CLEARANCE
        for bx in range(math.floor((obstacle['x'] - rx) / 128),
                        math.floor((obstacle['x'] + rx) / 128) + 1):
            for by in range(math.floor((obstacle['y'] - ry) / 128),
                            math.floor((obstacle['y'] + ry) / 128) + 1):
                bins.setdefault((bx, by), []).append(obstacle)
    return bins


@lru_cache(maxsize=65536)
def _walkable(x: float, y: float, map_id: int = 1) -> bool:
    cells, obstacles = _map_data(map_id)
    if (math.floor(x / 64), math.floor(y / 64)) not in cells:
        return False
    for obstacle in _obstacle_bins(map_id).get((math.floor(x / 128), math.floor(y / 128)), ()):
        rx = obstacle["rx"] + PLAYER_CLEARANCE
        ry = obstacle["ry"] + PLAYER_CLEARANCE
        dx, dy = x - obstacle["x"], y - obstacle["y"]
        if abs(dx) < rx and abs(dy) < ry and (dx / rx) ** 2 + (dy / ry) ** 2 < 1:
            return False
    return True


def _clear(start: tuple[float, float], end: tuple[float, float], map_id: int = 1) -> bool:
    distance = math.dist(start, end)
    steps = max(1, math.ceil(distance / 4))
    return all(_walkable(start[0] + (end[0] - start[0]) * i / steps,
                         start[1] + (end[1] - start[1]) * i / steps, map_id)
               for i in range(steps + 1))


def _nearest_grid(point: tuple[float, float], map_id: int, grid_step: int) -> tuple[int, int] | None:
    gx, gy = round(point[0] / grid_step), round(point[1] / grid_step)
    candidates = ((gx + dx, gy + dy) for radius in range(5)
                  for dx in range(-radius, radius + 1)
                  for dy in range(-radius, radius + 1)
                  if max(abs(dx), abs(dy)) == radius)
    for node in candidates:
        if _walkable(node[0] * grid_step, node[1] * grid_step, map_id) and _clear(
            point, (node[0] * grid_step, node[1] * grid_step), map_id
        ):
            return node
    return None


def find_map_path(map_id: int, start: tuple[float, float], goal: tuple[float, float],
                  max_distance: float | None = None) -> list[tuple[float, float]]:
    """Return walkable waypoints, excluding start and including goal."""
    if map_id not in MAP_FILES or (max_distance is not None and math.dist(start, goal) > max_distance):
        return []
    if not _walkable(*start, map_id) or not _walkable(*goal, map_id):
        return []
    if _clear(start, goal, map_id):
        return [goal]
    grid_step = 16 if map_id == 1 else 32
    first, last = _nearest_grid(start, map_id, grid_step), _nearest_grid(goal, map_id, grid_step)
    if first is None or last is None:
        return []
    frontier = [(0.0, first)]
    costs = {first: 0.0}
    parents = {first: None}
    directions = [(dx, dy) for dx in (-1, 0, 1) for dy in (-1, 0, 1) if dx or dy]
    while frontier:
        _, current = heapq.heappop(frontier)
        if current == last:
            break
        for dx, dy in directions:
            neighbor = current[0] + dx, current[1] + dy
            if max_distance is not None and math.dist((neighbor[0] * grid_step, neighbor[1] * grid_step), start) > max_distance + 150:
                continue
            if not _clear((current[0] * grid_step, current[1] * grid_step),
                          (neighbor[0] * grid_step, neighbor[1] * grid_step), map_id):
                continue
            cost = costs[current] + math.hypot(dx, dy)
            if cost >= costs.get(neighbor, math.inf):
                continue
            costs[neighbor] = cost
            parents[neighbor] = current
            heuristic = math.dist(neighbor, last)
            heapq.heappush(frontier, (cost + heuristic, neighbor))
    if last not in parents:
        return []
    nodes = []
    node = last
    while node is not None:
        nodes.append((node[0] * grid_step, node[1] * grid_step))
        node = parents[node]
    nodes.reverse()
    points = [start, *nodes, goal]
    result = []
    index = 0
    while index < len(points) - 1:
        farthest = index + 1
        for candidate in range(len(points) - 1, farthest, -1):
            if _clear(points[index], points[candidate], map_id):
                farthest = candidate
                break
        result.append(points[farthest])
        index = farthest
    return result


def find_town_path(start: tuple[float, float], goal: tuple[float, float]) -> list[tuple[float, float]]:
    return find_map_path(1, start, goal)

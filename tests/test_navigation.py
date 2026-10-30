"""Preserve collision geometry while indexing and caching navigation queries."""
import math
import random
import unittest

from game_client import town_navigation as nav


class NavigationTests(unittest.TestCase):
    def test_indexed_collision_matches_original_geometry(self):
        rng = random.Random(117)
        for map_id in nav.MAP_FILES:
            cells, obstacles = nav._map_data(map_id)
            points = [(cx * 64 + rng.uniform(0, 64), cy * 64 + rng.uniform(0, 64))
                      for cx, cy in rng.choices(sorted(cells), k=2000)]
            for obstacle in obstacles:
                rx, ry = obstacle['rx'] + nav.PLAYER_CLEARANCE, obstacle['ry'] + nav.PLAYER_CLEARANCE
                for scale in (0, 0.999, 1, 1.001):
                    points.extend(((obstacle['x'] + rx * scale, obstacle['y']),
                                   (obstacle['x'], obstacle['y'] - ry * scale)))
            for x, y in points:
                expected = (math.floor(x / 64), math.floor(y / 64)) in cells
                if expected:
                    for obstacle in obstacles:
                        rx = obstacle['rx'] + nav.PLAYER_CLEARANCE
                        ry = obstacle['ry'] + nav.PLAYER_CLEARANCE
                        dx, dy = x - obstacle['x'], y - obstacle['y']
                        if abs(dx) < rx and abs(dy) < ry and (dx / rx) ** 2 + (dy / ry) ** 2 < 1:
                            expected = False
                            break
                self.assertEqual(nav._walkable(x, y, map_id), expected, (map_id, x, y))


if __name__ == '__main__':
    unittest.main()

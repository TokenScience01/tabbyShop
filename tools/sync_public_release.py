"""Synchronize verified public item names and Treasure Land collision data."""
import base64
import json
from pathlib import Path
import re
import struct
import sys

root = Path(__file__).resolve().parents[1]
source = Path(sys.argv[1])
catalog_path = root / 'game_client/assets/item_names_zh.json'
catalog = json.loads(catalog_path.read_text(encoding='utf-8'))
by_code = {row['itemCode']: row for row in catalog}
names = (source / 'resources/localization/names_zh.gd').read_text(encoding='utf-8')
for code, name in re.findall(r'"item\.([^"]+)":\s*"([^"]+)"', names):
    code = code.upper()
    row = by_code.setdefault(code, {'itemCode': code})
    row['nameZh'] = name
catalog_path.write_text(json.dumps(list(by_code.values()), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

def vector(node, key, default):
    match = re.search(r'^' + re.escape(key) + r' = Vector2\(([^,]+), ([^)]+)\)', node, re.M)
    return tuple(map(float, match.groups())) if match else default


def extract_navigation(scene_name, filename):
    scene = (source / 'scenes' / (scene_name + '.tscn')).read_text(encoding='utf-8')
    assert 'metadata/authored_collision = true' not in scene, 'Authored collision needs a shape-aware extractor'
    nodes = re.split(r'(?=\[node )', scene)
    ground = next(node for node in nodes if node.startswith('[node name="Ground"'))
    packed = base64.b64decode(re.search(r'tile_map_data = PackedByteArray\("([^"]+)"', ground).group(1))
    assert len(packed) % 12 == 2, 'Unrecognized TileMapLayer encoding'
    cells = [struct.unpack_from('<hh', packed, offset) for offset in range(2, len(packed), 12)]
    assert cells and len(cells) == len(set(cells))
    for node_name in ('WorldMap', 'Decorations', 'Ground'):
        node = next(node for node in nodes if node.startswith(f'[node name="{node_name}"'))
        assert vector(node, 'position', (0, 0)) == (0, 0)
        assert vector(node, 'scale', (1, 1)) == (1, 1)
        assert not re.search(r'^rotation =', node, re.M)
    obstacles = []
    for node in nodes:
        if 'metadata/obstacle_radius' not in node:
            continue
        assert not re.search(r'^rotation =', node, re.M)
        assert 'parent="Decorations"' in node and 'metadata/collision_world_units = true' in node
        x, y = vector(node, 'position', (0, 0))
        sx, sy = vector(node, 'scale', (1, 1))
        rx, ry = vector(node, 'metadata/obstacle_radius', (0, 0))
        ox, oy = vector(node, 'metadata/obstacle_offset', (0, 0))
        obstacles.append(dict(name=re.search(r'name="([^"]+)"', node).group(1),
                              x=x+ox*sx, y=y+oy*sy, rx=rx*abs(sx), ry=ry*abs(sy)))
    output = root / 'game_client' / filename
    output.write_text(json.dumps(dict(cell_size=64, cells=cells, obstacles=obstacles), separators=(',', ':')), encoding='utf-8')
    print(f'{scene_name}: {len(cells)} cells, {len(obstacles)} obstacles')


for scene_name, filename in [('treasure_land', 'treasure_navigation.json'),
                             ('underground_cave', 'cave_navigation.json'),
                             ('desert_oasis', 'oasis_navigation.json'),
                             ('frozen_cavern', 'frozen_navigation.json')]:
    extract_navigation(scene_name, filename)
print(f'Updated {len(by_code)} item names')

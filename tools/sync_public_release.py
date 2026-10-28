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

scene = (source / 'scenes/treasure_land.tscn').read_text(encoding='utf-8')
nodes = re.split(r'(?=\[node )', scene)
ground = next(node for node in nodes if node.startswith('[node name="Ground"'))
packed = base64.b64decode(re.search(r'tile_map_data = PackedByteArray\("([^"]+)"', ground).group(1))
assert len(packed) % 12 == 2, 'Unrecognized TileMapLayer encoding'
cells = [struct.unpack_from('<hh', packed, offset) for offset in range(2, len(packed), 12)]
assert len(set(cells)) == 14400 and all(0 <= x < 120 and 0 <= y < 120 for x, y in cells)

def vector(node, key, default):
    match = re.search(r'^' + re.escape(key) + r' = Vector2\(([^,]+), ([^)]+)\)', node, re.M)
    return tuple(map(float, match.groups())) if match else default

for node_name in ('WorldMap', 'Decorations', 'Ground'):
    node = next(node for node in nodes if node.startswith(f'[node name="{node_name}"'))
    assert vector(node, 'position', (0, 0)) == (0, 0)
    assert vector(node, 'scale', (1, 1)) == (1, 1)
    assert not re.search(r'^rotation =', node, re.M), 'Unexpected parent transform'

obstacles = []
for node in nodes:
    if not node.startswith('[node name="Tree'):
        continue
    assert not re.search(r'^rotation =', node, re.M), 'Unexpected rotated tree'
    assert 'parent="Decorations"' in node and 'metadata/collision_world_units = true' in node
    x, y = vector(node, 'position', (0, 0))
    sx, sy = vector(node, 'scale', (1, 1))
    rx, ry = vector(node, 'metadata/obstacle_radius', (0, 0))
    ox, oy = vector(node, 'metadata/obstacle_offset', (0, 0))
    obstacles.append(dict(name=re.search(r'name="([^"]+)"', node).group(1),
                          x=x+ox*sx, y=y+oy*sy, rx=rx*abs(sx), ry=ry*abs(sy)))
assert obstacles
output = root / 'game_client/treasure_navigation.json'
output.write_text(json.dumps(dict(cell_size=64, cells=cells, obstacles=obstacles), separators=(',', ':')), encoding='utf-8')
print(f'Updated {len(by_code)} item names; Treasure Land: {len(cells)} cells, {len(obstacles)} obstacles')

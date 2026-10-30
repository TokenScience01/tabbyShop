"""Read-only tactical map rendered from server state and recovered terrain."""
import json
from functools import lru_cache
from pathlib import Path
from town_navigation import MAP_FILES
from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QWidget


@lru_cache(maxsize=6)
def terrain_path(filename):
    """Share immutable map geometry across account dashboards."""
    cells = json.loads(Path(__file__).with_name(filename).read_text())['cells']
    path = QPainterPath()
    for x, y in cells:
        path.addRect(x * 64, y * 64, 64, 64)
    return path


def peer_map_position(peer, current_map=None):
    """Return (map_id, x, y) for supported nearby-player snapshot shapes."""
    if not isinstance(peer, dict):
        return None
    position = peer.get('position')
    position = position if isinstance(position, dict) else peer
    map_id = peer.get('mapId', peer.get('map', position.get('mapId', position.get('map', current_map))))
    x, y = position.get('x'), position.get('y')
    try:
        if map_id is None or x is None or y is None:
            return None
        return int(map_id), float(x), float(y)
    except (TypeError, ValueError):
        return None


class TacticalMap(QWidget):
    def __init__(self, owner, portals):
        super().__init__(owner)
        self.owner = owner
        self.portals = portals
        self.terrain = {}
        self.setMinimumHeight(320)
        for map_id, filename in MAP_FILES.items():
            try:
                self.terrain[map_id] = terrain_path(filename)
            except (OSError, KeyError, ValueError):
                pass

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), QColor('#FAF8F3'))
        o = self.owner
        p.setPen(QColor('#E5E0D6'))
        for x in range(0, self.width(), 32):
            p.drawLine(x, 0, x, self.height())
        for y in range(0, self.height(), 32):
            p.drawLine(0, y, self.width(), y)
        if o.current_map is None or o.world_x is None or o.world_y is None:
            p.setPen(QColor('#77776E'))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, '连接后显示实时地图')
            return
        monsters = [m for m in o.monsters.values() if m.get('mapId') == o.current_map
                    and m.get('health', 0) > 0 and 'x' in m and 'y' in m]
        peers = []
        for peer in getattr(o, 'last_peers', []):
            location = peer_map_position(peer, o.current_map)
            if location is None or location[0] != o.current_map:
                continue
            peer_id = peer.get('id', peer.get('playerId'))
            if o.player_id is not None and str(peer_id) == str(o.player_id):
                continue
            peers.append((peer, location[1], location[2]))
        portals = [(dest, point) for (source, dest), point in self.portals.items() if source == o.current_map]
        terrain = self.terrain.get(o.current_map)
        if terrain is not None:
            bounds = terrain.boundingRect()
        else:
            points = [(o.world_x, o.world_y), *[(m['x'], m['y']) for m in monsters],
                      *[(x, y) for _, x, y in peers], *[point for _, point in portals]]
            xs, ys = zip(*points)
            bounds = QRectF(min(xs)-256, min(ys)-256, max(1024, max(xs)-min(xs)+512), max(1024, max(ys)-min(ys)+512))
        # Include authoritative position even when it is outside known terrain.
        bounds = bounds.united(QRectF(o.world_x-64, o.world_y-64, 128, 128))
        for _, peer_x, peer_y in peers:
            bounds = bounds.united(QRectF(peer_x-48, peer_y-48, 96, 96))
        # Fit the whole map without the old 32px padding on each edge.
        sx = (self.width()-12)/max(1,bounds.width())
        sy = (self.height()-12)/max(1,bounds.height())
        ox = 6
        oy = 6
        def point(x, y):
            return QPointF(ox+(x-bounds.left())*sx, oy+(y-bounds.top())*sy)
        # Keep terrain for map bounds, but leave the playfield transparent so
        # the same grid remains visible beneath every position marker.
        route = o.chase_route or o.route_points
        if route:
            path = QPainterPath(point(o.world_x,o.world_y))
            for x,y in route:
                path.lineTo(point(x,y))
            p.setPen(QPen(QColor('#8BA779'), 2, Qt.PenStyle.DashLine))
            p.drawPath(path)
        for dest,(x,y) in portals:
            pos = point(x,y)
            p.setPen(QPen(QColor('#9A7844'),2));p.setBrush(QColor('#F3EFE6'))
            p.drawRoundedRect(QRectF(pos.x()-5,pos.y()-5,10,10),2,2)
            # Keep labels inside the canvas even for portals on its edges.
            tx = min(self.width()-18, max(4, pos.x()+8))
            ty = min(self.height()-5, max(14, pos.y()-7))
            p.drawText(QPointF(tx,ty),str(dest))
        for m in monsters:
            elite = str(m.get('monsterRank','')).upper() == 'ELITE'
            p.setPen(Qt.PenStyle.NoPen);p.setBrush(QColor('#e8ba67' if elite else '#e47782'))
            p.drawEllipse(point(m['x'],m['y']),4 if elite else 2.8,4 if elite else 2.8)
        for peer, x, y in peers:
            peer_pos = point(x, y)
            p.setPen(QPen(QColor('#D7F5FF'), 1.2))
            p.setBrush(QColor('#45B9D0'))
            p.drawEllipse(peer_pos, 4.2, 4.2)
            name = str(peer.get('playerName', peer.get('name', '玩家'))).strip() or '玩家'
            if len(name) > 8:
                name = name[:7] + '…'
            p.setPen(QColor('#D7F5FF'))
            p.drawText(peer_pos + QPointF(7, -5), name)
        pos=point(o.world_x,o.world_y)
        p.setPen(Qt.PenStyle.NoPen);p.setBrush(QColor('#43583E'));p.drawEllipse(pos,12,12)
        p.setBrush(QColor('#A4C486' if not o.server_dead else '#e47782'));p.drawEllipse(pos,5,5)
        p.setPen(QColor('#E8ECEB'));p.drawText(pos+QPointF(12,-10),'你*' if o.position_estimated else '你')

"""Archive the public Godot web release and unpack unencrypted PCK entries."""
import concurrent.futures
import datetime
import hashlib
import json
import pathlib
import re
import struct
import sys
import urllib.request

BASE = 'https://game.tabby.meme/'
ROOT = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parents[1] / 'exports' / datetime.datetime.now().strftime('game.tabby.meme-%Y%m%d-%H%M%S')
WEB = ROOT / 'web'
WEB.mkdir(parents=True, exist_ok=True)
records = []

def download(path):
    target = WEB / path
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and len(sys.argv) > 1:
        data = target.read_bytes()
        records.append(dict(path=path, bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), reused=True))
        return target
    with urllib.request.urlopen(BASE + path, timeout=180) as response:
        headers = dict(response.headers)
        digest = hashlib.sha256()
        size = 0
        with target.open('wb') as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
                digest.update(chunk)
                size += len(chunk)
    records.append(dict(path=path, bytes=size, sha256=digest.hexdigest(), headers=headers))
    print(f'Downloaded {path}: {size:,} bytes', flush=True)
    return target

html = download('index.html').read_text(encoding='utf-8', errors='replace')
config = json.loads(re.search(r'const GODOT_CONFIG = (\{.*?\});', html).group(1))
paths = set(config['fileSizes'])
paths.update(re.findall(r'(?:src|href)="([^"#]+)"', html))
paths.add('index.service.worker.js')
paths.update(config['executable'] + suffix for suffix in ('.audio.worklet.js', '.audio.position.worklet.js'))
paths = {p for p in paths if not p.startswith(('data:', 'http:', 'https:'))}
errors = []
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
    futures = {pool.submit(download, path): path for path in paths}
    for future, path in futures.items():
        try:
            future.result()
        except Exception as error:
            errors.append(dict(path=path, error=str(error)))

# Manifest icons are additional public release dependencies.
manifest = WEB / 'index.manifest.json'
if manifest.exists():
    for icon in json.loads(manifest.read_text(encoding='utf-8')).get('icons', []):
        path = icon['src']
        if not (WEB / path).exists() and not path.startswith(('http', 'data:', '/')):
            try:
                download(path)
            except Exception as error:
                errors.append(dict(path=path, error=str(error)))

entries = []
pack_info = {}
for pack in WEB.rglob('*.pck'):
    with pack.open('rb') as stream:
        def read(fmt):
            return struct.unpack(fmt, stream.read(struct.calcsize(fmt)))
        magic, version, major, minor, patch = read('<5I')
        if magic != 0x43504447:
            raise ValueError('Invalid Godot PCK magic')
        if version not in (2, 3, 4):
            raise ValueError(f'Unsupported PCK version {version}; archive preserved')
        flags, base = read('<IQ')
        if version in (3, 4):
            directory_offset, = read('<Q')
            stream.seek(directory_offset)
        else:
            stream.read(64)
        count, = read('<I')
        pack_info = dict(format=version, engine=f'{major}.{minor}.{patch}', flags=flags, base=base, count=count)
        if flags & 1:
            raise ValueError('Encrypted directory; archive preserved')
        for _ in range(count):
            length, = read('<I')
            name = stream.read(length).rstrip(b'\0').decode('utf-8')
            offset, size = read('<QQ')
            md5 = stream.read(16).hex()
            file_flags, = read('<I')
            entries.append(dict(path=name, offset=offset, bytes=size, md5=md5, flags=file_flags))
        dest = ROOT / 'recovered'
        for entry in entries:
            relative = entry['path'].removeprefix('res://')
            target = (dest / relative).resolve()
            if not target.is_relative_to(dest.resolve()):
                raise ValueError('Unsafe pack path')
            if entry['flags'] & 1:
                entry['status'] = 'encrypted'
                continue
            stream.seek(base + entry['offset'])
            data = stream.read(entry['bytes'])
            if len(data) != entry['bytes'] or hashlib.md5(data).hexdigest() != entry['md5']:
                raise ValueError(f'Integrity mismatch: {relative}')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            entry['status'] = 'verified'
        print(f'Extracted and verified {len(entries)} entries; Godot {pack_info["engine"]}', flush=True)

(ROOT / 'archive-manifest.json').write_text(json.dumps(dict(source=BASE, fetched_at=datetime.datetime.now(datetime.timezone.utc).isoformat(), files=records, errors=errors, pack=pack_info), ensure_ascii=False, indent=2), encoding='utf-8')
(ROOT / 'pck-index.json').write_text(json.dumps(entries, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'EXPORT_ROOT={ROOT}', flush=True)

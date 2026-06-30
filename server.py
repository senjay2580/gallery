#!/usr/bin/env python3
# 图库后端：stdlib，无依赖。存图到 /srv/gallery/images，元数据到 /srv/gallery/data/items.json。
# 监听 127.0.0.1:8090，由 Caddy 反代 /api/*。
# 看图公开；上传/编辑/删除需登录（POST /api/login 拿 token，写操作带 Authorization: Bearer <token>）。
# 密码以 PBKDF2-SHA256 加盐哈希存于 env（明文不落地）。
import json, os, base64, time, uuid, hmac, hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE   = os.environ.get('GALLERY_BASE', '/srv/gallery')
IMGDIR = os.path.join(BASE, 'images')
DATA   = os.path.join(BASE, 'data', 'items.json')
USER   = os.environ.get('GALLERY_USER', 'senjay')
PHASH  = os.environ.get('GALLERY_PASS_HASH', '')        # pbkdf2_sha256$iters$salt_hex$hash_hex
SECRET = bytes.fromhex(os.environ.get('GALLERY_SECRET', '')) if os.environ.get('GALLERY_SECRET') else os.urandom(32)
MAX    = 12 * 1024 * 1024
CAP    = int(os.environ.get('TOTAL_CAP_GB', '3')) * 1024**3
TTL    = 14 * 86400
EXT    = {'image/jpeg':'.jpg','image/jpg':'.jpg','image/png':'.png',
          'image/webp':'.webp','image/gif':'.gif','image/avif':'.avif'}

os.makedirs(IMGDIR, exist_ok=True)
os.makedirs(os.path.dirname(DATA), exist_ok=True)

def load():
    try:
        with open(DATA, encoding='utf-8') as f: return json.load(f)
    except Exception: return []
def store(items):
    tmp = DATA + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f: json.dump(items, f, ensure_ascii=False)
    os.replace(tmp, DATA)
def dirsize():
    try: return sum(e.stat().st_size for e in os.scandir(IMGDIR) if e.is_file())
    except Exception: return 0

def verify_pass(pw):
    try:
        algo, iters, salt, h = PHASH.split('$')
        if algo != 'pbkdf2_sha256': return False
        dk = hashlib.pbkdf2_hmac('sha256', pw.encode(), bytes.fromhex(salt), int(iters))
        return hmac.compare_digest(dk.hex(), h)
    except Exception: return False
def make_token(user):
    payload = ('%s:%d' % (user, int(time.time()) + TTL)).encode()
    sig = hmac.new(SECRET, payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(payload + b'.' + sig).decode()
def check_token(tok):
    try:
        raw = base64.urlsafe_b64decode(tok.encode())
        payload, sig = raw.rsplit(b'.', 1)
        if not hmac.compare_digest(hmac.new(SECRET, payload, hashlib.sha256).digest(), sig): return False
        user, exp = payload.decode().split(':')
        return int(exp) > time.time()
    except Exception: return False

class H(BaseHTTPRequestHandler):
    def _send(self, code, obj=None):
        body = json.dumps(obj, ensure_ascii=False).encode() if obj is not None else b''
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if body: self.wfile.write(body)
    def _authed(self):
        h = self.headers.get('Authorization', '')
        return h.startswith('Bearer ') and check_token(h[7:])
    def _json(self):
        n = int(self.headers.get('Content-Length', 0) or 0)
        if n > 20 * 1024 * 1024: raise ValueError('too big')
        return json.loads(self.rfile.read(n) or b'{}')
    def _id(self): return self.path.rstrip('/').rsplit('/', 1)[-1]
    def do_OPTIONS(self): self._send(204)
    def do_GET(self):
        if self.path.rstrip('/') == '/api/items': self._send(200, load())
        else: self._send(404, {'error': 'not found'})
    def do_POST(self):
        p = self.path.rstrip('/')
        if p == '/api/login':
            try: d = self._json()
            except Exception: return self._send(400, {'error': 'bad json'})
            if d.get('user') == USER and verify_pass(d.get('pass') or ''):
                return self._send(200, {'token': make_token(USER)})
            return self._send(401, {'error': '账号或密码错误'})
        if p == '/api/upload':
            if not self._authed(): return self._send(401, {'error': 'unauthorized'})
            try: d = self._json()
            except Exception: return self._send(400, {'error': 'bad json'})
            src = d.get('dataURL') or ''
            if not src.startswith('data:image/') or ',' not in src:
                return self._send(400, {'error': 'need image dataURL'})
            head, b64 = src.split(',', 1)
            ext = EXT.get(head[5:].split(';')[0].lower())
            if not ext: return self._send(415, {'error': 'unsupported type'})
            try: raw = base64.b64decode(b64)
            except Exception: return self._send(400, {'error': 'bad base64'})
            if len(raw) > MAX: return self._send(413, {'error': 'image too large (>12MB)'})
            if dirsize() + len(raw) > CAP: return self._send(507, {'error': 'storage full'})
            iid = uuid.uuid4().hex[:12]; fn = iid + ext
            path = os.path.join(IMGDIR, fn)
            with open(path, 'wb') as f: f.write(raw)
            os.chmod(path, 0o644)
            item = {'id': iid, 'src': '/images/' + fn, 'w': d.get('w'), 'h': d.get('h'),
                    'title': (d.get('title') or '')[:200], 'cat': (d.get('cat') or '')[:60],
                    'keywords': (d.get('keywords') or '')[:300], 't': int(time.time())}
            its = load(); its.insert(0, item); store(its)
            return self._send(200, item)
        self._send(404, {'error': 'not found'})
    def do_PUT(self):
        if not self.path.startswith('/api/items/'): return self._send(404, {'error': 'not found'})
        if not self._authed(): return self._send(401, {'error': 'unauthorized'})
        try: d = self._json()
        except Exception: return self._send(400, {'error': 'bad json'})
        iid = self._id(); its = load(); found = None
        for it in its:
            if it['id'] == iid:
                for k in ('title', 'cat', 'keywords'):
                    if k in d: it[k] = (d[k] or '')[:300]
                found = it; break
        if not found: return self._send(404, {'error': 'not found'})
        store(its); self._send(200, found)
    def do_DELETE(self):
        if not self.path.startswith('/api/items/'): return self._send(404, {'error': 'not found'})
        if not self._authed(): return self._send(401, {'error': 'unauthorized'})
        iid = self._id(); its = load(); keep = []; removed = None
        for it in its:
            if it['id'] == iid: removed = it
            else: keep.append(it)
        if removed:
            try: os.remove(os.path.join(IMGDIR, os.path.basename(removed['src'])))
            except Exception: pass
            store(keep)
        self._send(200, {'ok': True})
    def log_message(self, *a): pass

if __name__ == '__main__':
    ThreadingHTTPServer(('127.0.0.1', 8090), H).serve_forever()

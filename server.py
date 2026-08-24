#!/usr/bin/env python3
# 图库后端：stdlib，无依赖。存图到 /srv/gallery/images，元数据到 /srv/gallery/data/items.json。
# 监听 127.0.0.1:8090，由 Caddy 反代 /api/*。
# 看图公开；上传/编辑/删除需登录（POST /api/login 拿 token，写操作带 Authorization: Bearer <token>）。
# 密码以 PBKDF2-SHA256 加盐哈希存于 env（明文不落地）。
#
# AI 生图（/api/ai/*，全部需登录）：本服务代理转发到任意 OpenAI 兼容网关。
# 之所以由后端代理而不是浏览器直连上游：① 中转站基本不发 CORS 头；② 出图 URL 常是裸 IP 的
# http://（如 qkmss），HTTPS 页面会被 mixed-content 拦死。后端代拉后转 dataURL 返回，
# 顺带复用 /api/upload 既有的 dataURL 契约，入库路径零改动。
import json, os, base64, time, uuid, hmac, hashlib, urllib.request, urllib.error, threading, socket
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

# ── AI 默认配置（前端留空即用这些；前端填了就整组覆盖）──────────────────────
# AI_API_KEY 支持逗号分隔多 key（斑马 6 key），每次请求 round-robin，单 key 失败顺延下一个。
AI_BASE    = os.environ.get('AI_BASE_URL', '').rstrip('/')
AI_KEYS    = [k.strip() for k in os.environ.get('AI_API_KEY', '').split(',') if k.strip()]
AI_IMG_M   = [m.strip() for m in os.environ.get('AI_IMAGE_MODELS', '').split(',') if m.strip()]
AI_VIS_M   = os.environ.get('AI_VISION_MODEL', '')
AI_TIMEOUT = int(os.environ.get('AI_TIMEOUT', '300'))
AI_MAX_IMG = 12 * 1024 * 1024        # 上游出图超过这个大小就拒绝，和 MAX 保持一致
# AI 白名单：只有名单内的账号能看见 AI 面板并调用 /api/ai/*（烧的是自己的 key）。默认仅站主。
AI_USERS   = [u.strip() for u in os.environ.get('AI_USERS', USER).split(',') if u.strip()]
COOKIE_NAME = 'gsess'
# 生产是 HTTPS，Cookie 必须带 Secure；本地 http 调试时置 COOKIE_SECURE=0 才能生效
COOKIE_SECURE = os.environ.get('COOKIE_SECURE', '1') != '0'

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
    """校验通过返回用户名，否则 None。返回用户名而非 bool——AI 白名单要按人判定。"""
    try:
        raw = base64.urlsafe_b64decode(tok.encode())
        payload, sig = raw.rsplit(b'.', 1)
        if not hmac.compare_digest(hmac.new(SECRET, payload, hashlib.sha256).digest(), sig): return None
        user, exp = payload.decode().split(':')
        return user if int(exp) > time.time() else None
    except Exception: return None
def session_cookie(tok, clear=False):
    bits = ['%s=%s' % (COOKIE_NAME, '' if clear else tok), 'Path=/', 'HttpOnly', 'SameSite=Lax',
            'Max-Age=%d' % (0 if clear else TTL)]
    if COOKIE_SECURE: bits.append('Secure')
    return '; '.join(bits)

# ── AI 转发 ────────────────────────────────────────────────────────────────
_rr = {'n': 0}
_rr_lock = threading.Lock()
# ponytail: 全局单锁 —— 本站是单账号图库，生图串行足够；真要多人并发再换成 per-user 锁
gen_lock = threading.Lock()

def ai_cfg(d):
    """请求体里的 {baseUrl, apiKey} 覆盖服务端默认；三者留空则回落 env。
    apiKey 逗号分隔 = 多 key 轮转池。"""
    base = (d.get('baseUrl') or AI_BASE or '').strip().rstrip('/')
    keys = [k.strip() for k in (d.get('apiKey') or '').split(',') if k.strip()] or AI_KEYS
    return base, keys

# 只有这些状态码能证明「上游明确拒绝、根本没开始干活」，换个 key 重来才不会重复计费。
# 402=余额不足 401/403=鉴权 429=限流。5xx 一律不换：上游可能已经开始生成并扣了费。
REJECT_CODES = (401, 402, 403, 429)

def ai_post(base, keys, path, payload, timeout=AI_TIMEOUT, idempotent=True):
    """POST 到上游，多 key round-robin。

    idempotent=False（生图）时严格限制顺延条件：生图非幂等、单次 200+ 秒、按次计费，
    超时/5xx 都意味着上游可能已经在出图并已扣费，这时换 key 重试 = 重复烧额度
    （6 个 key 最坏烧 6 次）。所以只在明确被拒（REJECT_CODES）或压根没连上时才换。
    idempotent=True（打标/列表）便宜且快，可放心顺延。
    全部失败抛最后一个错误——不静默吞，原样带给前端。"""
    if not base: raise ValueError('未配置 AI 接口地址')
    if not keys: raise ValueError('未配置 API Key')
    with _rr_lock:
        start = _rr['n']; _rr['n'] = start + 1
    body = json.dumps(payload).encode()
    last = None
    for i in range(len(keys)):
        key = keys[(start + i) % len(keys)]
        req = urllib.request.Request(base + path, data=body, method='POST')
        req.add_header('Authorization', 'Bearer ' + key)
        req.add_header('Content-Type', 'application/json')
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            detail = e.read(500).decode('utf-8', 'replace')
            last = Exception('上游 %d：%s' % (e.code, detail[:300]))
            if not idempotent and e.code not in REJECT_CODES:
                raise last          # 可能已扣费，绝不换 key 重来
        except (TimeoutError, socket.timeout) as e:
            last = Exception('上游超时（%ss）：请求可能已在上游执行，未自动重试以免重复计费' % timeout)
            if not idempotent: raise last
        except urllib.error.URLError as e:
            # 连接层失败（DNS/拒绝连接/TLS）= 请求没送达，换 key 安全
            last = Exception('URLError：%s' % e.reason)
        except Exception as e:
            last = Exception('%s：%s' % (type(e).__name__, e))
            if not idempotent: raise last
    raise last

def ai_get(base, keys, path, timeout=60):
    if not base: raise ValueError('未配置 AI 接口地址')
    if not keys: raise ValueError('未配置 API Key')
    last = None
    for key in keys[:3]:                     # 只读列表，试前 3 个 key 足够
        req = urllib.request.Request(base + path)
        req.add_header('Authorization', 'Bearer ' + key)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            last = Exception('上游 %d：%s' % (e.code, e.read(300).decode('utf-8', 'replace')[:200]))
        except Exception as e:
            last = Exception('%s：%s' % (type(e).__name__, e))
    raise last

def to_dataurl(raw, ctype):
    ext = EXT.get((ctype or '').split(';')[0].strip().lower())
    if not ext: ext, ctype = '.png', 'image/png'      # 上游常不给 content-type，按 PNG 兜
    return 'data:%s;base64,%s' % (ctype.split(';')[0].strip(), base64.b64encode(raw).decode())

def fetch_image(url):
    """把上游出图 URL 拉成 dataURL。上游可能是 http 裸 IP，由服务端拉才不受浏览器
    mixed-content / CORS 限制。"""
    req = urllib.request.Request(url, headers={'User-Agent': 'gallery-api/1.0'})
    with urllib.request.urlopen(req, timeout=AI_TIMEOUT) as r:
        raw = r.read(AI_MAX_IMG + 1)
        if len(raw) > AI_MAX_IMG: raise ValueError('上游图片超过 12MB')
        return to_dataurl(raw, r.headers.get('Content-Type', ''))

def parse_tag(text):
    """模型可能把 JSON 裹在 ```json 里或前后带解释，取第一个 {...} 块。
    解析失败就抛错，不静默返回空标签——否则会得到一堆无标题图。"""
    s = text.strip()
    i, j = s.find('{'), s.rfind('}')
    if i < 0 or j <= i: raise ValueError('模型未返回 JSON：' + s[:120])
    d = json.loads(s[i:j + 1])
    return {'title': str(d.get('title') or '')[:200],
            'cat': str(d.get('cat') or '')[:60],
            'keywords': str(d.get('keywords') or '')[:300]}

TAG_SYS = ('你是图库管理助手。观察图片后只输出一个 JSON 对象，不要任何解释或代码块标记：'
           '{"title":"简短中文标题(不超过20字)","cat":"单个中文分类词(如 摄影/插画/动物/风景/设计/人物)",'
           '"keywords":"5-10个中文关键词，逗号分隔"}')


class H(BaseHTTPRequestHandler):
    def _send(self, code, obj=None, cookie=None):
        body = json.dumps(obj, ensure_ascii=False).encode() if obj is not None else b''
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        # 图库整体私有：不再允许任意站点跨域读取，只认同源
        self.send_header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        if cookie: self.send_header('Set-Cookie', cookie)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if body: self.wfile.write(body)
    def _user(self):
        """当前请求的登录用户名，未登录返回 None。
        API 走 Bearer；<img> 标签发不了自定义头，所以同时认 HttpOnly Cookie。"""
        h = self.headers.get('Authorization', '')
        if h.startswith('Bearer '):
            u = check_token(h[7:])
            if u: return u
        for part in (self.headers.get('Cookie') or '').split(';'):
            k, _, v = part.strip().partition('=')
            if k == COOKIE_NAME and v:
                u = check_token(v)
                if u: return u
        return None
    def _authed(self): return self._user() is not None
    def _json(self):
        n = int(self.headers.get('Content-Length', 0) or 0)
        if n > 20 * 1024 * 1024: raise ValueError('too big')
        return json.loads(self.rfile.read(n) or b'{}')
    def _id(self): return self.path.rstrip('/').rsplit('/', 1)[-1]
    def do_OPTIONS(self): self._send(204)
    def do_GET(self):
        p = self.path.rstrip('/')
        if p == '/api/items':
            # 图库整体私有：未登录连列表都拿不到
            if not self._authed(): return self._send(401, {'error': 'unauthorized'})
            # 出口改写 src：库里存的仍是 /images/xx.png（老数据不迁移），对外只暴露需鉴权的 /api/img/
            return self._send(200, [dict(it, src='/api/img/' + os.path.basename(it.get('src', '')))
                                    for it in load()])
        if p == '/api/me':
            u = self._user()
            if not u: return self._send(401, {'error': 'unauthorized'})
            return self._send(200, {'user': u, 'ai': u in AI_USERS})
        if p == '/api/ai/config':
            # 只报服务端默认的形状，绝不回传 key 本身
            u = self._user()
            if not u: return self._send(401, {'error': 'unauthorized'})
            if u not in AI_USERS: return self._send(403, {'error': '该账号无 AI 权限'})
            return self._send(200, {'baseUrl': AI_BASE, 'keyCount': len(AI_KEYS),
                                    'imageModels': AI_IMG_M, 'visionModel': AI_VIS_M})
        if self.path.startswith('/api/img/'):
            return self._send_image()
        self._send(404, {'error': 'not found'})

    def _send_image(self):
        """出图：必须登录。文件名只取 basename 并强制回到 IMGDIR 内，杜绝 ../ 穿越。"""
        if not self._authed(): return self._send(401, {'error': 'unauthorized'})
        name = os.path.basename(self.path.split('?', 1)[0].rstrip('/'))
        path = os.path.realpath(os.path.join(IMGDIR, name))
        if not path.startswith(os.path.realpath(IMGDIR) + os.sep) or not os.path.isfile(path):
            return self._send(404, {'error': 'not found'})
        ctype = next((c for c, e in EXT.items() if e == os.path.splitext(path)[1]), 'application/octet-stream')
        raw = open(path, 'rb').read()
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'private, max-age=86400')
        self.end_headers()
        self.wfile.write(raw)
    def do_POST(self):
        p = self.path.rstrip('/')
        if p == '/api/login':
            try: d = self._json()
            except Exception: return self._send(400, {'error': 'bad json'})
            if d.get('user') == USER and verify_pass(d.get('pass') or ''):
                tok = make_token(USER)
                # 同时下发 HttpOnly Cookie：<img> 带不了 Authorization 头，图片鉴权只能靠它
                return self._send(200, {'token': tok, 'user': USER, 'ai': USER in AI_USERS},
                                  cookie=session_cookie(tok))
            return self._send(401, {'error': '账号或密码错误'})
        if p == '/api/logout':
            # HttpOnly Cookie 前端 JS 删不掉，必须由服务端清
            return self._send(200, {'ok': True}, cookie=session_cookie('', clear=True))
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
            return self._send(200, dict(item, src='/api/img/' + fn))

        # ── AI：需登录 且 在 AI 白名单内。烧的是站主自己的 key，非白名单账号一律 403 ──
        if p.startswith('/api/ai/'):
            u = self._user()
            if not u: return self._send(401, {'error': 'unauthorized'})
            if u not in AI_USERS: return self._send(403, {'error': '该账号无 AI 权限'})
            try: d = self._json()
            except Exception: return self._send(400, {'error': 'bad json'})
            base, keys = ai_cfg(d)
            try:
                if p == '/api/ai/models':            # 拉上游模型列表，供前端下拉选择
                    r = ai_get(base, keys, '/v1/models')
                    ids = sorted(m.get('id', '') for m in (r.get('data') or []) if m.get('id'))
                    return self._send(200, {'models': ids})

                if p == '/api/ai/image':             # 生图 → 统一返回 dataURL
                    prompt = (d.get('prompt') or '').strip()
                    model = (d.get('model') or '').strip() or (AI_IMG_M[0] if AI_IMG_M else '')
                    if not prompt: return self._send(400, {'error': '请填写画面描述'})
                    if not model: return self._send(400, {'error': '未选择生图模型'})
                    payload = {'model': model, 'prompt': prompt, 'n': 1}
                    if d.get('size'): payload['size'] = d['size']
                    # 同一账号同时只允许一个生图在飞：前端连点/多开标签页都不会变成多次计费
                    if not gen_lock.acquire(blocking=False):
                        return self._send(429, {'error': '已有一张图在生成中，请等它完成（避免重复计费）'})
                    try:
                        r = ai_post(base, keys, '/v1/images/generations', payload, idempotent=False)
                    finally:
                        gen_lock.release()
                    out = (r.get('data') or [{}])[0]
                    if out.get('b64_json'):
                        src = to_dataurl(base64.b64decode(out['b64_json']), 'image/png')
                    elif out.get('url'):
                        src = fetch_image(out['url'])
                    else:
                        return self._send(502, {'error': '上游未返回图片：' + json.dumps(r)[:200]})
                    return self._send(200, {'dataURL': src, 'model': model,
                                            'revised_prompt': out.get('revised_prompt') or ''})

                if p == '/api/ai/tag':               # 视觉小模型看图 → 标题/分类/关键词
                    src = d.get('dataURL') or ''
                    model = (d.get('model') or '').strip() or AI_VIS_M
                    if not src.startswith('data:image/'): return self._send(400, {'error': 'need image dataURL'})
                    if not model: return self._send(400, {'error': '未配置视觉模型'})
                    hint = (d.get('cats') or '')[:300]
                    ask = '为这张图生成图库元数据。' + (('已有分类：' + hint + '，能复用就复用，不合适再新建。') if hint else '')
                    r = ai_post(base, keys, '/v1/chat/completions', {
                        'model': model, 'max_tokens': 400,
                        'messages': [{'role': 'system', 'content': TAG_SYS},
                                     {'role': 'user', 'content': [
                                         {'type': 'text', 'text': ask},
                                         {'type': 'image_url', 'image_url': {'url': src}}]}]}, timeout=180)
                    return self._send(200, parse_tag(r['choices'][0]['message']['content']))
            except Exception as e:
                return self._send(502, {'error': str(e)[:400]})
            return self._send(404, {'error': 'not found'})

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

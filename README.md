# The Thing · 图库

一个瀑布流图床（cosmos 风格）：前端单文件 + 轻量 Python 后端，图片存服务器，登录后管理。

## 功能
- 瀑布流（CSS columns，紧凑间距、方角）
- 分类筛选（分类由数据动态生成）、标题/分类/关键词搜索
- 上传图片，填标题 / 分类 / 关键词
- 图片详情：查看大图、下载、编辑文字、删除
- 浅色 / 夜间模式
- **看图公开；上传 / 编辑 / 删除需登录**（服务端强制，无 token 一律 401）

## 组成
| 文件 | 作用 |
|---|---|
| `index.html` | 前端单文件（读写 `/api`，无构建） |
| `server.py` | 后端：Python stdlib，无依赖。存图到 `/srv/gallery/images`，元数据 `data/items.json` |
| `gallery-api.service` | systemd 服务单元（以 www-data 运行，监听 `127.0.0.1:8090`） |

## 接口
- `GET  /api/items` — 列表（公开）
- `POST /api/login` `{user,pass}` — 登录，返回 token
- `POST /api/upload` — 上传（需 `Authorization: Bearer <token>`）
- `PUT  /api/items/:id` — 改文字（需登录）
- `DELETE /api/items/:id` — 删除（需登录）

## 部署
1. `server.py` → `/opt/gallery-api/`，`gallery-api.service` → `/etc/systemd/system/`
2. 建 `/opt/gallery-api/.env`（**不入库**）：
   ```
   GALLERY_USER=你的账号
   GALLERY_PASS_HASH=pbkdf2_sha256$200000$<salt_hex>$<hash_hex>   # 见下
   GALLERY_SECRET=<openssl rand -hex 32>
   TOTAL_CAP_GB=3
   ```
   生成密码哈希：
   ```python
   python3 -c 'import hashlib,os;s=os.urandom(16);print("pbkdf2_sha256$200000$"+s.hex()+"$"+hashlib.pbkdf2_hmac("sha256",b"你的密码",s,200000).hex())'
   ```
3. `systemctl enable --now gallery-api`
4. 反代：Web 服务器把 `/api/*` 转给 `127.0.0.1:8090`，其余静态托管 `/srv/gallery`（`/images/*` 直接出图）。

> 安全：密码 PBKDF2-SHA256 加盐哈希，明文不落地；token 由服务端 HMAC 签发并校验。

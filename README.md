# The Thing · 图库

一个私有瀑布流图床：前端单文件 + 轻量 Python 后端，图片存服务器，**登录后才可见**。
站主账号还能在侧栏用 AI 生图，并让小模型自动打标后入库。

## 功能
- 瀑布流（CSS columns，紧凑间距、方角）
- 分类筛选（分类由数据动态生成）、标题/分类/关键词搜索
- 上传图片，填标题 / 分类 / 关键词
- 图片详情：查看大图、下载、编辑文字、删除
- 浅色 / 夜间模式
- **整站私有：不登录看不到列表、也取不到任何一张图**（服务端强制）
- **AI 生图侧栏**（仅 AI 白名单账号可见），与主内容同层「挤压」而非遮盖，左边缘可拖拽调宽：
  - **对话式生成**：说一句画一张，出图后接着说「背景换成夜晚」，带着上一张图和上下文继续改
  - **提示词优化 + 模板路由**：小模型先从 22 个工业级模板里挑一个（按用户意图），
    再按该模板的写作要点把口语化输入扩写成完整提示词
  - **多会话**：加号新开会话，会话之间互相隔离，历史可切换/删除
  - **提示词库**：增删改查 + 复制，输入 `/` 在对话框里直接调用
  - **后台生成**：收起面板、切标签页、刷新页面都不中断，回来能接上
  - 接口地址 / API Key / 生图模型都能在网页里配置，可配多个模型下拉切换；
    视觉模型固定走服务器线路（它只负责读图和写提示词，不消耗你的生图额度）
  - 出图后由视觉小模型自动生成标题 / 分类 / 关键词，可手改后一键入库

## 组成
| 文件 | 作用 |
|---|---|
| `index.html` | 前端单文件（读写 `/api`，无构建） |
| `server.py` | 后端：Python stdlib，无依赖。存图到 `/srv/gallery/images`，元数据 `data/items.json` |
| `gallery-api.service` | systemd 服务单元（以 www-data 运行，监听 `127.0.0.1:8090`） |
| `styles.json` | 22 个生图模板（何时用 / 写作要点 / 常见坑），供运行时路由 |
| `deploy.ps1` | 部署脚本。只覆盖代码与 Caddy 配置，**不碰图片与元数据** |

## 接口
公开：仅 `POST /api/login`。其余全部需要登录。

| 接口 | 说明 |
|---|---|
| `POST /api/login` | `{user,pass}` → 返回 token，并下发 HttpOnly Cookie |
| `POST /api/logout` | 清除 Cookie（HttpOnly，前端 JS 删不掉） |
| `GET  /api/me` | 当前用户及是否有 AI 权限 |
| `GET  /api/items` | 列表；`src` 出口改写为 `/api/img/<file>` |
| `GET  /api/img/<file>` | 出图，需登录（`<img>` 靠 Cookie 鉴权） |
| `POST /api/upload` | 上传 |
| `PUT/DELETE /api/items/:id` | 改文字 / 删除 |
| `GET  /api/ai/config` | 服务端默认 AI 配置的**形状**（不含 Key） |
| `POST /api/ai/models` | 拉上游模型列表 |
| `POST /api/ai/image` | **启动**后台生图，立刻返回 202 + `job` |
| `GET  /api/ai/state` | 生图进度；`job` 是本次任务的唯一 id |
| `GET  /api/ai/result` | 取生成结果（dataURL） |
| `POST /api/ai/prompt` | 模板路由 + 提示词优化 → `{prompt, template}` |
| `POST /api/ai/tag` | 视觉模型看图 → `{title,cat,keywords}` |
| `POST /api/thumb/:id` | 给老图补缩略图（前端一次性迁移用） |

`/api/ai/*` 额外要求账号在 `AI_USERS` 白名单内，否则 403。

### 为什么 AI 请求要绕后端转发
① 中转站基本不发 CORS 头；② 出图 URL 常是裸 IP 的 `http://`，HTTPS 页面会被 mixed-content
拦死。后端代拉后转成 dataURL 返回，顺带复用 `/api/upload` 既有的 dataURL 契约。

### 额度保护（生图按次计费，改这段前先读）
- 生图请求 **不会**因超时或 5xx 换 Key 重试：那两种情况上游可能已经在出图并已扣费，
  重试等于重复付钱。只有明确被拒（401/402/403/429）或根本没连上才顺延下一个 Key。
- 同一时刻只允许一个生图在飞，多余请求直接 429，前端按钮同时置灰。
- 打标 / 拉模型是幂等且便宜的，才允许试满整个 Key 池。
- 你自己配的接口失败时会回落服务器默认线路，**同样只在「明确被拒 / 没连上」时才回落**——
  否则等于两条线路都扣一次。
- 前端只认领**自己这次发起的** `job`（记在 localStorage）。不这么做的话，登录时会把
  很久以前那次的 done 结果又认领一遍，凭空多出一张旧图。

### 为什么生图要跑在后台
一次生图 1–4 分钟。放在请求里同步等，收起面板没事，但**刷新页面就断**——额度已经扣了，
图却拿不回来；这么长的连接也容易被中间层掐掉。改成后台线程 + 轮询状态后，关面板、
切页、刷新都能把那张图接回来。

### 图片加载
列表只加载缩略图（前端 canvas 压的，长边 320）。卡片宽约 300px 却下 2MB 原图是首屏慢的
主因；实测缩略图 13KB vs 原图 1337KB。原图只在点开详情时取，并带 ETag 走 304。
服务端是零依赖 stdlib，压不了图，所以由浏览器出力：上传/入库时顺带生成，
老图在登录后后台逐张补齐（`/api/thumb/:id`）。若某张图压出来反而更大（图标、纯色块），
就不存缩略图，直接走原图。

### 生图模板路由
`styles.json` 来自 [awesome-gpt-image-2](https://github.com/freestylefly/awesome-gpt-image-2)（MIT），
22 个模板各带「何时用 / 写作要点 / 常见坑」。每次优化提示词时，小模型先按用户意图选一个模板，
再把该模板的要点注入写作环节——比一句通用的「写详细点」有效得多。接着改同一张图时沿用上一轮
选中的模板，不中途换风格体系。

## 部署
1. `pwsh D:\Desktop\gallery\deploy.ps1`（传代码 + 配 Caddy + 重启 + 自检）
2. 首次需建 `/opt/gallery-api/.env`（**不入库**）：
   ```
   GALLERY_USER=你的账号
   GALLERY_PASS_HASH=pbkdf2_sha256$200000$<salt_hex>$<hash_hex>   # 见下
   GALLERY_SECRET=<openssl rand -hex 32>
   TOTAL_CAP_GB=3

   # AI（可选，留空则网页里必须自己填）
   AI_BASE_URL=https://你的网关
   AI_API_KEY=sk-1,sk-2,sk-3        # 逗号分隔即多 Key 轮转
   AI_IMAGE_MODELS=gpt-image-2,gpt-image-1.5,gpt-image-2-2k
   AI_VISION_MODEL=gpt-5.4-mini
   AI_USERS=senjay                  # 能用 AI 的账号，默认等于 GALLERY_USER
   ```
   生成密码哈希：
   ```python
   python3 -c 'import hashlib,os;s=os.urandom(16);print("pbkdf2_sha256$200000$"+s.hex()+"$"+hashlib.pbkdf2_hmac("sha256",b"你的密码",s,200000).hex())'
   ```
3. `systemctl enable --now gallery-api`

> Caddy 站点块里的 `handle /images/*` 与 `handle /data/*` 两条 `respond 404` **不能删**。
> 少了它们，图片和 `items.json` 会被 `file_server` 静态直出，登录拦截形同虚设。

> 安全：密码 PBKDF2-SHA256 加盐哈希，明文不落地；token 由服务端 HMAC 签发并校验；
> 会话 Cookie 为 HttpOnly + SameSite=Lax + Secure（本地 http 调试置 `COOKIE_SECURE=0`）。

# 图库 · Atlas

一个干净的单文件瀑布流图库（cosmos 风格）。纯前端，零依赖，单个 `index.html` 即可运行/部署。

## 功能
- 瀑布流（CSS columns，紧凑间距、方角）
- 分类筛选（分类由数据动态生成）
- 标题 / 分类 / 关键词搜索
- 上传图片，可填标题 / 分类 / 关键词（用于搜索）
- 图片详情：查看大图、下载、编辑文字、删除
- 浅色 / 夜间模式（自动记忆）
- 数据持久化在浏览器 `localStorage`

## 运行
直接用浏览器打开 `index.html`，或丢到任意静态托管（Cloudflare Pages / VPS + Caddy / Nginx）。

## 接后端（让图存到服务器、跨设备共享）
当前上传的图存在浏览器本地（`localStorage`，单设备、约 5MB 上限）。
要变成真正的图床，把代码里的两处接上后端即可：
- 上传：`fileInput.onchange` 里把 `dataURL` 改成 POST 到上传接口，存图后用返回的 URL；
- 读取：`items` 改成 `fetch('/api/items')`。

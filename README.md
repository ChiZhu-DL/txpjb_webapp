# TXPJB WebApp — 糖心Vlog（Titan）第三方网页端

`txpjb_webapp` · 端口 **8521**

基于 `txpjlog` 抓包（全量解密）逆向实现的网页端：
协议解密 + 三级分类 + 热门标签 + 搜索 + 直链播放 + 金币购买 + 邀请奖励领取。

> 仅供协议学习与安全研究，请勿用于任何违反服务条款或法律的用途。

---

## 功能一览

- **三级分类浏览**：大分类 → 小分类 → 三级标签，12 种 mediaType 自动路由接口
- **热门标签 / 搜索 / 4 种排序**（最新 / 最热 / 收藏 / 权重）
- **详情弹层**：封面、时长、播放/收藏数、金币价、标签、简介、线路选择
- **直链播放**：点播放 → 当前窗口**新标签页直接打开 m3u8 直链**（浏览器直连 CDN，
  本服务零视频/图片流量）
- **金币视频购买**：详情页一键购买（`/front/media/purchase`），成功后自动换完整直链；
  余额不足会提示走邀请奖励 / 获取VIP
- **邀请奖励**：显示已邀人数、可领奖励、10 档奖励表，一键领取并刷新账号状态
  （邀 1 人=15金币、2人=3天VIP、5人=8天VIP、20人=45天VIP、50人=80天VIP、100人=180天VIP…）
- **账号状态徽章**：VIP·剩N天 / 非VIP + 金币余额，实时刷新
- **获取VIP**：新标签打开 [bkmh.alwaysdata.net](https://bkmh.alwaysdata.net/)
- **免配置游客号**：首启动自动建号；「换号」一键换新 mac = 全新账号

---

## 快速开始

```bash
pip install -r requirements.txt
python txpjb_player.py
```

打开 `http://127.0.0.1:8521`（手机同 Wi-Fi 可访问 `http://<局域网IP>:8521`）。
无需任何账号配置：首启动自动建游客号并写入 `config.json`。

---

## 公网穿透（GitHub Actions + Cloudflare Tunnel）

`.github/workflows/tunnel.yml`：GitHub Actions 里跑服务 + **Cloudflare Quick Tunnel**
（免 Cloudflare 账号），公网地址随机 `*.trycloudflare.com`：

1. 把本目录推到 GitHub 仓库（`config.json` 已被 `.gitignore` 排除，**不会泄露 token**）
2. Actions 页手动 **Run workflow**（或 push 自动触发）
3. Job Summary 里点公网地址即达；单次运行 ~5.5 小时，到期重新 Run 续期

> 隧道只承载页面与 JSON 接口；视频（m3u8/TS）与封面图由访客浏览器**直连 CDN**，
> 隧道带宽压力可忽略。Quick Tunnel 地址每次重跑会变，需固定域名请自配 Named Tunnel。
>
> ⚠️ 公网暴露后 `/api/settings`、`/api/newguest` 无鉴权，任何人可改配置/换号。

---

## 文件

```
txpjb_webapp/
├── txpjb_player.py       # Flask 服务 + AES 解密 + 账号 + 购买/邀请奖励接口
├── txpjb_player.html     # 主页面（三级分类 / 标签 / 网格 / 详情弹层 / 邀请奖励弹层）
├── gold_probe.py         # 只读探测：游客视角下金币/VIP/免费视频的地址与 m3u8 内容
├── requirements.txt      # flask / requests / pycryptodome / urllib3
├── config.json           # 运行时自动生成（gitignore）：mac、token、api_host
├── rsa_public_key.pem    # 登录用 RSA-1024 公钥（从 apk 提取）
├── .github/workflows/tunnel.yml  # GitHub Actions + Cloudflare Tunnel 公网穿透
└── .gitignore
```

### 使用流程

1. 顶部搜索，或点**大分类 → 小分类 → 三级标签**筛选；`🏷️ 热门标签`可叠加筛选
2. 点卡片 → 弹详情 → **选线路** → 「▶ 播放（新标签打开直链）」
   （直链可在新标签复制给 VLC / PotPlayer）
3. 金币视频：详情页显示金币价与余额，点**购买完整版** → 自动换完整直链再播
4. 右上角：账号 VIP 徽章 + 金币余额 · 🎁 邀请奖励（领取后自动刷新）· 获取VIP · 换号

---

## 协议逆向结论（全部实机验证）

### 1. 响应解密：AES-256-ECB

响应体是 JSON 字符串（外层带引号、内容 base64），固定 key 解密：

```
key = b"GcgzsKdDZTumABNz7uujrCfPIk9TQ355"     # 32 字节，硬编码于 libapp.so
明文 = {"code":0,"msg":"success","data":{...}}
```

### 2. 游客登录（免抓包，自动建号）

```
POST /front/cluser/c/user/mac/login
body = {"encrypt": RSA1024_PKCS1v15(明文)}
明文 = {"mac":"<16位hex>","agentCode":"base",
        "tips":MD5("sf42" + mac + "1"),"os":"1","trace_id":""}
→ {"data":{"token":"...","infoPo":{"userAcct":"...","vipFlag":false}}}
```

**mac 即账号唯一锚点**：同一 mac 重复登录永远是同一个号（幂等）。
点「换号」= 换新 mac = 全新账号。`tips` 必须与 mac 成对计算。

### 3. 分类树（三级）与 mediaType 路由

`POST /front/media/category/listAllCategory` `{}` → 12 大分类（隐藏导航/社交后 10）/ 38 小分类 / 179 三级。

三级节点自带 `mediaType`，**每个分支不一样**，接口必须跟着走：

| mediaType | 含义 | 列表接口 |
|---|---|---|
| 1 / 2 / 16 | 视频 / Vlog / AI | `/front/media/listMediaBySearchType` |
| 8 / 9 / 10 | 漫画 / 动漫短剧 / 小说 | `/front/comic/listMediaByPageAndSortType` |

用错接口是**静默返回 0 条**（code=0, total=0），不是报错，极易误判「没内容」。
「全部 / 推荐 / 综合推荐」是占位节点：选中必空，前端不渲染、永不自动选中。

### 4. 内容列表

`POST /front/media/listMediaBySearchType`，关键参数：

| 参数 | 说明 |
|---|---|
| `categoryId` | 三级任一级都能直接传，自动下钻 |
| `orderType` | `SORT_PUBLISH` / `SORT_VIEW_COUNT` / `SORT_FAVOR` / `SORT_PUBLISH_WEIGHT` |
| `searchKeyword` | 标题关键词 |
| `tags` | **必须是数组** `["id"]`；传字符串服务端返回空 |

### 5. 付费类型与「完整地址」下发规则（实测）

| payType | 含义 | 游客拿到的 |
|---|---|---|
| 1 | 免费（绿标） | `videoUrl` 即**完整版 m3u8**（无 `_preview` 后缀，hash 独立） |
| 2 | 金币（橙标，`goldPayUnit`=价格） | `videoUrl == videoPreviewUrl`，仅 **8~10s 试看** |
| 4 | VIP（橙标） | 同金币，仅试看 |

- 完整版与试看版是**两份不同 hash 的文件**，路径互相不可推导
- **权限按（账号，视频）绑定**：有权限 → 详情接口 `preview=false` + 完整 m3u8
  （实测 94 分片 / 938s 全量）；无权限 → 恒试看
- **`hasBuy` 字段不可靠**（有权限也返回 false），**`preview` 字段才是有效信号**
- `purchase` 严格校验余额（不足返回 `5100 余额不足，请充值`）；
  已购视频重复购买幂等成功、不重复扣款
- CDN 强鉴权：m3u8 去签名参数 → 401；`auth_key` 时间戳型短时效（分钟~小时级）；
  TS 分片为绝对地址 + 独立 `token`；AES-128 key 亦需 `auth_key`
  （旁路打法——路径改写/裸链/自签/JWT 泄露——在本站均不可行，
  详见仓库外 `../金币视频完整播放分析.md` 与 `../金币视频抓包分析.md`）

### 6. 金币购买与邀请奖励

```
POST /front/media/purchase                {mediaId, mediaType} → 购买，余额不足 5100
POST /front/activity/getAvailableRecord   {} → {invitedNum, shouldGetNum, giveType}
POST /front/activity/receiveRightNow      {} → 领取（data 内再包一层 code/msg）
POST /front/activity/userGetInviteConfig  {} → 10 档奖励表
```

### 7. 播放线路

`POST /front/system/cdnline/getCdnLineByMerAcct` → 5 条 CDN（播放线路06/09/10 + 国际线路03/04）。
`videoUrl` 是**相对路径**，5 条线路**共用同一路径与签名**，换域名即换线路（实测 5/5 全通）。

### 8. 封面：不用解密

抓包里封面带 `.bnc`，实测**去掉 `.bnc` 后缀就是明文 JPEG**（加 `.jpg` 反而 404）。
CDN 带 `Access-Control-Allow-Origin: *`，浏览器直连，服务端零图片流量。

---

## HTTP 接口

| 路径 | 说明 |
|---|---|
| `GET /api/categories` | 三级分类树（缓存 30 分钟，`?refresh=1` 强刷） |
| `GET /api/list` | 内容列表：`categoryId` / `mediaType` / `pageNo` / `pageSize` / `orderType` / `keyword` / `tags` |
| `GET /api/tags` | 热门标签 |
| `GET /api/cdn` | 播放线路列表 |
| `GET /api/media` | 单视频详情（getMediaById）：`preview=false` 即有完整版权限 |
| `POST /api/purchase` | 金币购买 `{mediaId, mediaType}`，返回购买后账号状态 |
| `GET /api/invite/info` | 邀请奖励：可领数 + 档位表 + 账号状态 |
| `POST /api/invite/claim` | 领取邀请奖励，返回领取后最新账号状态 |
| `GET /api/me` | 当前账号信息（vipFlag / coinBalance） |
| `GET /api/health` | 端口 / 协议 / 登录状态 |
| `POST /api/newguest` | 换新游客号 |
| `POST /api/settings` | 改 api_host / macct / token / listen_host |

---

## config.json

| 字段 | 说明 |
|---|---|
| `mac` | 设备标识 **兼账号锚点**，留空自动生成；持久化后不再变 |
| `token` | 留空 = 自动游客号；也可手填抓包里的 token 用自己的会员/已购账号 |
| `api_host` | API 线路，默认 `https://13.229.32.61`（裸 IP，证书自签） |
| `app_version` / `ver` | 请求头版本号，默认 `1.2.2` |
| `macct` | 商家账号，默认 `sf42`（参与 `tips` 计算，换了要一起改） |
| `listen_host` | 监听地址，默认 `0.0.0.0`；只允许本机改 `127.0.0.1` |

---

## 实现踩坑（两处会直接让人以为"接口挂了"）

1. **锁自死锁**：`guest_login` 持有 `_cfg_lock` 时调用 `save_config`，后者再次取同一把锁。
   `threading.Lock` 不可重入 → 启动时永久卡在登录。必须用 `threading.RLock`。
2. **启动不能阻塞在网络请求上**：登录/分类预热放后台线程，
   否则上游慢/不通时端口一直不监听，表现为"服务没起来"。

另：本机/公司网设了按主机放行的代理，直连裸 IP 必须 `session.trust_env = False`。

---

## 免责声明

本项目仅为学习 Android App 协议逆向的技术验证，数据均来自自行抓包分析。
请勿用于商业用途或任何违反当地法律法规的用途，后果由使用者自行承担。

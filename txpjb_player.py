#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
TXPJB WebApp — 糖心Vlog(Titan) 第三方网页端
================================================
Flask 服务 + AES-256-ECB 协议解密 + 大/小分类 + 更多标签 + 在线播放

逆向结论（全部来自 txpjlog/txpjb流程抓包 实测解密验证）：
  1. 响应解密：AES-256-ECB / PKCS7，key = b"GcgzsKdDZTumABNz7uujrCfPIk9TQ355"
     响应体是 JSON 字符串（外层带引号的 base64），解出来是 {"code":0,"data":...}
  2. 游客登录：POST /front/cluser/c/user/mac/login
     请求体 {"encrypt": RSA1024_PKCS1v15(明文)}，明文 = {"mac","agentCode":"base",
     "tips":MD5("sf42"+mac+"1"),"os":"1","trace_id":""}
     → 同一 mac 永远对应同一账号（幂等）
  3. 分类树：GET/POST /front/media/category/listAllCategory  {}  → 三级分类
     level1 firstCategoryName / level2 secondCategoryName / level3 thirdCategoryName
  4. 内容列表：POST /front/media/listMediaBySearchType
     支持 categoryId(可传三级任一级) / mediaType / orderType / searchKeyword / tags / 分页
     返回 data.dataList[]，每项含 video(封面/时长/m3u8) + tagList(标签)
  5. 更多标签：POST /front/media/hotTag {"mediaType":1,"merchantAcct":null} → 59 个热门标签
  6. 播放线路：POST /front/system/cdnline/getCdnLineByMerAcct → 5 条 CDN 线路
  7. 封面：video.videoCoverImg 是 /image/... 无扩展名，
     **去掉 .bnc 后缀直接就是明文 JPEG**（CDN 带 ACAO:*，前端可直连，零服务器流量）
  8. 视频：video.videoUrl 是相对 m3u8，拼 CDN 线路即可；
     CDN 同样带 ACAO:* → hls.js 可直接播

免责声明：仅供协议学习与安全研究，请勿用于任何违反服务条款或法律的用途。
"""
import base64
import hashlib
import json
import os
import random
import re
import socket
import string
import threading
import time

import requests
import urllib3
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from flask import Flask, jsonify, request, send_file

urllib3.disable_warnings()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
RSA_PEM = os.path.join(BASE_DIR, "rsa_public_key.pem")

AES_KEY = b"GcgzsKdDZTumABNz7uujrCfPIk9TQ355"
PORT = 8521

DEFAULT_CONFIG = {
    "token": "",
    "mac": "",
    "api_host": "https://13.229.32.61",
    "app_version": "1.2.2",
    "ver": "1.2.2",
    "os": "1",
    "macct": "sf42",
    "device_id": "",
    "device_fingerprint": "",
    "sid": "",
    "listen_host": "0.0.0.0",
}

# 抓包里的真实设备指纹/机型，仅用于补齐服务端可能校验的请求头
CAPTURED_HEADERS = {
    "user-agent": "Dart/3.4 (dart:io)",
    "device_model": "V2307A",
    "device_brand": "vivo",
    "system_name": "Android",
    "system_version": "10",
    "device": "Android",
    "user_agent": "",
    "attribution_flag": "0",
    "fp_version": "3.0.0",
    "sdk_version": "1.3.0",
    "accept": "application/json,*/*",
    "accept-encoding": "gzip",
}

app = Flask(__name__, static_folder=None)
# 必须是RLock：save_config() 会在持有锁的情况下再次取锁（guest_login/api_settings 里嵌套调用），
# 用普通 Lock 会直接自死锁（表现为启动时卡在登录、端口永远不监听）
_cfg_lock = threading.RLock()


# ────────────────────────────── 配置 ──────────────────────────────
def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg.update(json.load(f))
        except Exception:
            pass
    if not cfg.get("mac"):
        # mac 既是设备标识也是账号唯一锚点：随机生成后持久化
        cfg["mac"] = "".join(random.choice("0123456789abcdef") for _ in range(16))
    if not cfg.get("device_id"):
        cfg["device_id"] = "".join(random.choice("0123456789abcdef") for _ in range(16))
    if not cfg.get("device_fingerprint"):
        cfg["device_fingerprint"] = hashlib.sha256(
            (cfg["mac"] + str(time.time())).encode()).hexdigest()
    if not cfg.get("sid"):
        cfg["sid"] = "".join(random.choice("0123456789abcdef") for _ in range(32))
    save_config(cfg)
    return cfg


def save_config(cfg):
    with _cfg_lock:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)


CONFIG = load_config()

# 会话级缓存
_cache = {"categories": None, "categories_ts": 0, "cdn": None}
_cache_lock = threading.Lock()


def new_session():
    s = requests.Session()
    # 关键：本机沙箱/公司网设了按主机放行的代理，直连 IP 必须绕过环境代理
    s.trust_env = False
    return s


SESSION = new_session()


# ────────────────────────────── 加解密 ──────────────────────────────
def aes_decrypt(b64_text):
    """AES-256-ECB 解密 + PKCS7 去padding，返回 bytes"""
    ct = base64.b64decode(b64_text)
    pt = AES.new(AES_KEY, AES.MODE_ECB).decrypt(ct)
    pad = pt[-1]
    if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad:
        pt = pt[:-pad]
    return pt


def parse_response(text):
    """服务端把响应体包成 JSON 字符串；解不开就当明文 JSON 处理"""
    text = (text or "").strip()
    if not text:
        return {}
    try:
        val = json.loads(text)
    except Exception:
        return {}
    if isinstance(val, str):
        try:
            return json.loads(aes_decrypt(val).decode("utf-8"))
        except Exception:
            return {"code": -1, "msg": "decrypt failed"}
    if isinstance(val, dict):
        return val
    return {}


def load_rsa_pub():
    if not os.path.exists(RSA_PEM):
        return None
    with open(RSA_PEM, "rb") as f:
        return RSA.import_key(f.read())


def rsa_encrypt(obj):
    key = load_rsa_pub()
    if key is None:
        raise RuntimeError("缺少 rsa_public_key.pem")
    plain = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ct = PKCS1_v1_5.new(key).encrypt(plain)
    return base64.b64encode(ct).decode()


# ────────────────────────────── 账号 ──────────────────────────────
def build_headers(need_token=True):
    cfg = CONFIG
    h = dict(CAPTURED_HEADERS)
    h.update({
        "content-type": "application/json; charset=UTF-8",
        "ver": cfg["ver"],
        "app_version": cfg["app_version"],
        "os": cfg["os"],
        "macct": cfg["macct"],
        "sid": cfg["sid"],
        "device_id": cfg["device_id"],
        "device_fingerprint": cfg["device_fingerprint"],
        "client_ts": str(int(time.time())),
    })
    if need_token and cfg.get("token"):
        h["token"] = cfg["token"]
    return h


def guest_login(force=False):
    """游客登录：mac + MD5("sf42"+mac+"1") → RSA 加密 → 换 token。
    同一 mac 幂等，永远拿回同一个账号。"""
    global CONFIG
    if CONFIG.get("token") and not force:
        return CONFIG["token"]
    cfg = CONFIG
    payload = {
        "mac": cfg["mac"],
        "agentCode": "base",
        "tips": hashlib.md5((cfg["macct"] + cfg["mac"] + cfg["os"]).encode()).hexdigest(),
        "os": cfg["os"],
        "trace_id": "",
    }
    body = json.dumps({"encrypt": rsa_encrypt(payload)})
    with _cfg_lock:
        CONFIG["token"] = ""
        save_config(cfg)
    r = SESSION.post(cfg["api_host"] + "/front/cluser/c/user/mac/login",
                     headers=build_headers(need_token=False),
                     data=body, timeout=30, verify=False)
    res = parse_response(r.text)
    if res.get("code") != 0:
        raise RuntimeError("登录失败: %s" % (res.get("msg") or r.text[:200]))
    tok = (res.get("data") or {}).get("token", "")
    with _cfg_lock:
        cfg["token"] = tok
        save_config(cfg)
    return tok


def api_call(path, body=None, method="POST", retries=3):
    """统一请求：自动解密 + 登录重试"""
    last_err = None
    for attempt in range(retries):
        try:
            guest_login()
            url = CONFIG["api_host"] + path
            if method == "POST":
                r = SESSION.post(url, headers=build_headers(),
                                 data=json.dumps(body or {}), timeout=45, verify=False)
            else:
                r = SESSION.get(url, headers=build_headers(), timeout=45, verify=False)
            res = parse_response(r.text)
            if res.get("code") == 0:
                return res
            # 会话失效 → 换新游客号重试
            if res.get("code") in (2002, 401, 403) and attempt < retries - 1:
                guest_login(force=True)
                continue
            return res
        except Exception as e:
            last_err = e
            if attempt < retries - 1:
                try:
                    guest_login(force=True)
                except Exception:
                    pass
                time.sleep(1.5 + attempt * 2)
    return {"code": -1, "msg": "请求失败: %s" % last_err, "data": None}


# ────────────────────────────── 数据整形 ──────────────────────────────
# 这两个大分类不是视频内容：导航是入口页/工具，社交是关注/动态/私信
HIDE_L1 = {"导航", "社交"}


def get_categories(force=False):
    with _cache_lock:
        if (not force and _cache["categories"]
                and time.time() - _cache["categories_ts"] < 1800):
            return _cache["categories"]
    res = api_call("/front/media/category/listAllCategory", {})
    if res.get("code") != 0:
        return []
    data = res.get("data") or []
    tree = []
    for l1 in data:
        name1 = l1.get("firstCategoryName") or l1.get("secondCategoryName")
        if name1 in HIDE_L1:
            continue
        node = {
            "id": l1.get("categoryId"),
            "name": name1,
            "level": 1,
            "position": l1.get("position"),
            "children": [],
        }
        for l2 in (l1.get("child") or []):
            n2 = {
                "id": l2.get("categoryId"),
                "name": l2.get("secondCategoryName"),
                "level": 2,
                "children": [],
            }
            for l3 in (l2.get("child") or []):
                n3name = l3.get("thirdCategoryName")
                n2["children"].append({
                    "id": l3.get("categoryId"),
                    "name": n3name,
                    "level": 3,
                    "mediaType": l3.get("mediaType"),
                    # 「全部」是分类占位节点，本身没有内容：选中它必然空列表。
                    # 标记出来让前端跳过，不自动选中。见 issue: AI 大分类下只有 ai 有内容。
                    "placeholder": (n3name or "").strip() in ("全部", "推荐", "综合推荐"),
                })
            node["children"].append(n2)
        tree.append(node)
    tree.sort(key=lambda x: (x.get("position") or 999))
    with _cache_lock:
        _cache["categories"] = tree
        _cache["categories_ts"] = time.time()
    return tree


def get_cdn_lines():
    with _cache_lock:
        if _cache["cdn"]:
            return _cache["cdn"]
    res = api_call("/front/system/cdnline/getCdnLineByMerAcct", {})
    lines = []
    if res.get("code") == 0:
        for c in (res.get("data") or []):
            lines.append({"name": c.get("cdnName"), "url": c.get("cdnLine")})
    if not lines:
        lines = [{"name": "默认线路", "url": "https://mysf2bf09.hzlld56.com"}]
    with _cache_lock:
        _cache["cdn"] = lines
    return lines


def shape_media(m, cdn_base=None):
    """把一条 media 整成前端要的形状；封面拼成CDN 明文直链。
    三种载体：video(视频) / article(文章) / comicVo(漫画·小说·短剧)。"""
    v = m.get("video") or {}
    art = m.get("article") or {}
    comic = m.get("comicVo") or {}
    cover = (v.get("videoCoverImg") or art.get("articleCoverImg")
             or comic.get("comicCover") or comic.get("chapterCover") or "")
    # 关键：抓包里封面请求都带 .bnc，但实测 **去掉 .bnc 后缀、且不加任何扩展名
    # 就是明文 JPEG**（加 .jpg 反而 404），且 CDN 返回 ACAO:*，
    # 所以拼上 CDN 域名让浏览器直连，服务器不转发任何图片流量。
    if cover.endswith(".bnc"):
        cover = cover[:-4]
    if cover and cover.startswith("/") and cdn_base:
        cover = cdn_base.rstrip("/") + cover
    vurl = v.get("videoUrl") or ""
    preview = v.get("videoPreviewUrl") or ""
    title = (v.get("videoTitle") or art.get("articleTitle")
             or comic.get("comicName") or "(无标题)")
    desc = (v.get("videoDescription") or art.get("articleDescription")
            or comic.get("comicDesc") or "")
    pay_type = m.get("payType")
    # payType: 1=免费  2=金币（goldPayUnit = 所需金币数）  4=VIP
    # 实测 payType=2 的 goldPayUnit 才有意义（1~30 不等），payType=1/4 基本是 None/0
    gold = m.get("goldPayUnit")
    out = {
        "id": m.get("mediaId"),
        "title": title,
        "desc": desc,
        "cover": cover,
        "duration": v.get("videoDuration") or 0,
        "videoPath": vurl,
        "previewPath": preview,
        "payType": pay_type,
        "goldPayUnit": gold if (pay_type == 2 and gold) else None,
        "userLevel": m.get("userLevel"),
        "mediaType": m.get("mediaType"),
        "categoryId": m.get("categoryId"),
        "categoryName": m.get("categoryName"),
        "publishTime": m.get("publishTime"),
        "viewCount": m.get("viewCount"),
        "fakeViewCount": m.get("fakeViewCount"),
        "favorCount": m.get("favorCount"),
        "tags": [{"id": t.get("tagId"), "name": t.get("tagName")}
                 for t in (m.get("tagList") or []) if t.get("tagName")],
    }
    if comic:
        # 漫画/小说/短剧：没有视频地址，改为展示章节信息
        out.update({
            "kind": "comic",
            "comicAuthor": comic.get("comicAuthor"),
            "chapterCurrentTitle": comic.get("chapterCurrentTitle"),
            "chapterCurrentSeq": comic.get("chapterCurrentSeq"),
            "chapterTotal": comic.get("chapterTotal"),
            "chapterId": comic.get("chapterCurrentId"),
            "chapterOver": comic.get("chapterOver"),
        })
    else:
        out["kind"] = "media"
    return out


def flatten(data_list, cdn_base=None):
    """dataList 的每一项可能自带 mediaList（按分类分组），也可能就是 media 本身"""
    out = []
    for item in (data_list or []):
        if not isinstance(item, dict):
            continue
        if item.get("mediaId"):
            out.append(shape_media(item, cdn_base))
        elif item.get("mediaList"):
            for m in item["mediaList"]:
                s = shape_media(m, cdn_base)
                s["groupName"] = item.get("categoryName")
                out.append(s)
    return out


# ────────────────────────────── 路由 ──────────────────────────────
@app.route("/")
def index():
    return send_file(os.path.join(BASE_DIR, "txpjb_player.html"))


@app.route("/favicon.ico")
def favicon():
    return ("", 204)


@app.route("/api/categories")
def api_categories():
    tree = get_categories(force=request.args.get("refresh") == "1")
    total = sum(len(c["children"]) for c in tree)
    return jsonify({"ok": True, "categories": tree,
                    "l1": len(tree), "l2": total,
                    "l3": sum(len(x["children"]) for c in tree for x in c["children"])})


@app.route("/api/list")
def api_list():
    page = max(1, int(request.args.get("pageNo", 1) or 1))
    size = min(50, max(1, int(request.args.get("pageSize", 20) or 20)))
    media_type = int(request.args.get("mediaType") or 1)
    cat_id = request.args.get("categoryId") or None
    order = request.args.get("orderType") or "SORT_PUBLISH"
    kw = request.args.get("keyword") or None
    tags = request.args.get("tags")
    tag_list = [t for t in (tags or "").split(",") if t] or None

    # ── 按 mediaType 选接口 ──────────────────────────────
    # 实测（每个分支取第一个非占位三级节点探测）：
    #   mediaType 1/2/16 (首页/Vlog/AI)  → /front/media/listMediaBySearchType
    #   mediaType 8/9/10(漫画/动漫/短剧/小说) → /front/comic/listMediaByPageAndSortType
    # 用错接口会「返回 0 条」而不是报错 —— 很容易误判成该分类没内容。
    if media_type in (8, 9, 10):
        body = {
            "thirdCategoryId": cat_id,
            "secondCategoryId": request.args.get("secondCategoryId") or None,
            "comicType": media_type,
            "pageNo": page,
            "pageSize": size,
            "chapterOver": request.args.get("chapterOver") or None,
            "payType": request.args.get("payType") or None,
            "orderType": order,
        }
        res = api_call("/front/comic/listMediaByPageAndSortType", body)
        if res.get("code") != 0:
            return jsonify({"ok": False, "msg": res.get("msg"), "items": []})
        d = res.get("data") or {}
        lines = get_cdn_lines()
        base = lines[0]["url"] if lines else ""
        return jsonify({"ok": True, "total": d.get("total", 0),
                        "page": page, "pageSize": size,
                        "kind": "comic",
                        "items": flatten(d.get("dataList"), base)})

    body = {
        "categoryId": cat_id,
        "mediaType": media_type,
        "pageNo": page,
        "pageSize": size,
        "publishStatus": 1,
        "payType": request.args.get("payType") or None,
        "searchType": request.args.get("searchType") or None,
        "orderType": order,
        "userId": None, "isLive": None, "bodyType": None, "specifics": None,
        "searchItem": None, "searchKeyword": kw, "upInfoId": None, "merchantAcct": None,
        # 实测：tags 必须是 **数组**，传字符串服务端直接返回空(code=None)
        "tags": tag_list,
    }

    res = api_call("/front/media/listMediaBySearchType", body)
    if res.get("code") != 0:
        return jsonify({"ok": False, "msg": res.get("msg"), "items": []})
    d = res.get("data") or {}
    lines = get_cdn_lines()
    base = lines[0]["url"] if lines else ""
    return jsonify({"ok": True, "total": d.get("total", 0),
                    "page": page, "pageSize": size, "kind": "media",
                    "items": flatten(d.get("dataList"), base)})


@app.route("/api/tags")
def api_tags():
    res = api_call("/front/media/hotTag",
                   {"mediaType": int(request.args.get("mediaType") or 1),
                    "merchantAcct": None})
    tags = []
    if res.get("code") == 0:
        for t in (res.get("data") or []):
            tags.append({"id": t.get("tagId"), "name": (t.get("tagName") or "").strip(),
                         "hot": t.get("hot"), "mediaType": t.get("mediaType"),
                         "group": t.get("firstTagCategoryName") or t.get("tagCategoryName")})
    tags = [t for t in tags if t["name"]]
    return jsonify({"ok": True, "tags": tags, "count": len(tags)})


@app.route("/api/cdn")
def api_cdn():
    return jsonify({"ok": True, "lines": get_cdn_lines()})


@app.route("/api/me")
def api_me():
    res = api_call("/front/cluser/c/user/info/get", {})
    info = (res.get("data") or {})
    return jsonify({"ok": res.get("code") == 0, "info": info,
                    "mac": CONFIG["mac"], "apiHost": CONFIG["api_host"]})


# ── 金币视频购买（协议：POST /front/media/purchase {mediaId, mediaType}） ──
@app.route("/api/media")
def api_media():
    """单个视频详情（getMediaById）：购买后用它重取完整 videoUrl"""
    mid = request.args.get("mediaId") or ""
    mt = int(request.args.get("mediaType") or 1)
    if not mid:
        return jsonify({"ok": False, "msg": "缺少 mediaId"})
    res = api_call("/front/media/getMediaById", {"mediaId": mid, "mediaType": mt})
    if res.get("code") != 0:
        return jsonify({"ok": False, "msg": res.get("msg")})
    d = res.get("data") or {}
    lines = get_cdn_lines()
    m = shape_media(d, lines[0]["url"] if lines else "")
    # preview=false 表示该账号对此视频有完整版权限；true = 只给试看
    return jsonify({"ok": True, "item": m, "preview": d.get("preview"),
                    "hasBuy": d.get("hasBuy"), "goldPayUnit": d.get("goldPayUnit")})


@app.route("/api/purchase", methods=["POST"])
def api_purchase():
    """金币购买：余额不足服务端返回 5100；成功(或已购幂等)后 preview=false 给完整地址"""
    data = request.get_json(silent=True) or {}
    mid = str(data.get("mediaId") or "")
    mt = int(data.get("mediaType") or 1)
    if not mid:
        return jsonify({"ok": False, "msg": "缺少 mediaId"})
    res = api_call("/front/media/purchase", {"mediaId": mid, "mediaType": mt})
    # 购买后立刻拉最新账号状态（金币余额变化）
    me = api_call("/front/cluser/c/user/info/get", {})
    return jsonify({"ok": res.get("code") == 0, "msg": res.get("msg"),
                    "info": (me.get("data") or {})})


# ── 邀请奖励（协议来自 txpjlog/领取邀请奖励 抓包） ──────────────
@app.route("/api/invite/info")
def api_invite_info():
    """可领奖励 + 档位表 + 账号状态（VIP判断在前端用 info.vipFlag）"""
    rec = api_call("/front/activity/getAvailableRecord", {})
    cfg = api_call("/front/activity/userGetInviteConfig", {})
    me = api_call("/front/cluser/c/user/info/get", {})
    return jsonify({
        "ok": rec.get("code") == 0,
        "record": rec.get("data") or {},          # {invitedNum, shouldGetNum, giveType}
        "config": cfg.get("data") or [],          # 档位: [{inviteNum, giveType, giveNum}]
        "info": (me.get("data") or {}),
    })


@app.route("/api/invite/claim", methods=["POST"])
def api_invite_claim():
    """领取邀请奖励：receiveRightNow 的 data 里还包了一层 code/msg"""
    res = api_call("/front/activity/receiveRightNow", {})
    ok = res.get("code") == 0
    msg = res.get("msg")
    inner = res.get("data")
    if isinstance(inner, dict) and inner.get("code") is not None:
        ok = ok and inner.get("code") == 0
        msg = inner.get("msg") or msg
    # 领取后立刻拉最新账号状态（VIP/金币可能变化）
    me = api_call("/front/cluser/c/user/info/get", {})
    return jsonify({"ok": ok, "msg": msg, "info": (me.get("data") or {})})


@app.route("/api/newguest", methods=["POST"])
def api_newguest():
    global CONFIG
    with _cfg_lock:
        CONFIG["mac"] = "".join(random.choice("0123456789abcdef") for _ in range(16))
        CONFIG["token"] = ""
        save_config(CONFIG)
    try:
        tok = guest_login(force=True)
        return jsonify({"ok": True, "mac": CONFIG["mac"], "token": tok[:24] + "..."})
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)})


@app.route("/api/settings", methods=["POST"])
def api_settings():
    global CONFIG
    data = request.get_json(silent=True) or {}
    with _cfg_lock:
        for k in ("api_host", "macct", "app_version", "ver", "listen_host"):
            if k in data and str(data[k]).strip():
                CONFIG[k] = str(data[k]).strip()
        if "token" in data:
            CONFIG["token"] = str(data["token"]).strip()
        save_config(CONFIG)
    with _cache_lock:
        _cache["categories"] = None
        _cache["cdn"] = None
    return jsonify({"ok": True})


@app.route("/api/health")
def api_health():
    return jsonify({"ok": True, "port": PORT, "token": bool(CONFIG.get("token"))})


def lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("223.5.5.5", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


if __name__ == "__main__":
    host = CONFIG.get("listen_host") or "0.0.0.0"

    def warmup():
        """后台预热：登录 + 分类。不阻塞端口监听，网络慢也不影响网页打开。"""
        try:
            guest_login()
            print("[账号] 游客号就绪 mac=%s" % CONFIG["mac"], flush=True)
        except Exception as e:
            print("[账号] 初始化失败（可稍后点「换号」重试）: %s" % e, flush=True)
        try:
            cats = get_categories()
            print("[分类] %d 个大分类 / %d 个小分类 / %d 个三级标签" % (
                len(cats),
                sum(len(c["children"]) for c in cats),
                sum(len(x["children"]) for c in cats for x in c["children"])), flush=True)
        except Exception as e:
            print("[分类] 拉取失败: %s" % e, flush=True)

    threading.Thread(target=warmup, daemon=True).start()

    print("=" * 56, flush=True)
    print("  TXPJB WebApp已启动")
    print("  本机:http://127.0.0.1:%d" % PORT)
    print("  手机: http://%s:%d  (同一 Wi-Fi)" % (lan_ip(), PORT))
    print("=" * 56, flush=True)
    app.run(host=host, port=PORT, threaded=True, debug=False, use_reloader=False)
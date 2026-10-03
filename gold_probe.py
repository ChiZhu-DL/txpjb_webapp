# -*- coding: utf-8 -*-
"""gold_probe.py — 只读探测：游客账号视角下，金币/VIP 视频的地址与 m3u8 内容

用途（配合《金币视频播放完整》逆向文章的对照分析）：
  1. 游客登录（复用 txpjb_player 的协议栈，不发任何写操作请求）
  2. 拉几页内容列表，收集 payType=2(金币) / 4(VIP) / 1(免费) 样本
  3. 对每个样本打印 videoUrl vs videoPreviewUrl 的差异
  4. 按第 1 条 CDN 线路 GET 两个 m3u8，统计分片数/总时长/是否加密，
     观察服务端到底返回的是「试看播放列表」还是「完整播放列表」

只做观察，不构造、不篡改任何签名参数。
用法:  python gold_probe.py [采样页数]
"""
import json
import sys
import time

import txpjb_player as T


def fetch_text(url):
    """直连 GET 一个 m3u8，返回 (status, text)"""
    try:
        r = T.SESSION.get(url, timeout=20, verify=False)
        return r.status_code, r.text
    except Exception as e:
        return 0, "%s: %s" % (type(e).__name__, e)


def parse_m3u8(text):
    """极简解析：分片数 / 总时长 / 是否加密 / 是否 master"""
    if "#EXTM3U" not in text:
        return None
    info = {
        "master": "#EXT-X-STREAM-INF" in text,
        "encrypted": "#EXT-X-KEY" in text and "METHOD=NONE" not in text,
        "segments": 0,
        "duration": 0.0,
        "endlist": "#EXT-X-ENDLIST" in text,
        "first_seg": "",
    }
    pending = 0.0
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#EXTINF:"):
            try:
                pending = float(line.split(":", 1)[1].split(",")[0])
            except ValueError:
                pending = 0.0
        elif line and not line.startswith("#"):
            info["segments"] += 1
            info["duration"] += pending
            if not info["first_seg"]:
                info["first_seg"] = line.split("?")[0]
            pending = 0.0
    return info


def main():
    pages = int(sys.argv[1]) if len(sys.argv) > 1 else 4
    T.guest_login()
    print("[账号] 游客号就绪 mac=%s vipFlag=%s" % (
        T.CONFIG["mac"],
        "见 /api/me"), flush=True)

    lines = T.get_cdn_lines()
    base = lines[0]["url"].rstrip("/")
    print("[线路] %d 条，采样用第 1 条: %s (%s)" % (len(lines), lines[0]["name"], base))

    gold, vip, free = [], [], []
    for page in range(1, pages + 1):
        res = T.api_call("/front/media/listMediaBySearchType", {
            "categoryId": None, "mediaType": 1,
            "pageNo": page, "pageSize": 50, "publishStatus": 1,
            "searchType": "RECOMMEND", "orderType": "SORT_PUBLISH",
        })
        items = T.flatten((res.get("data") or {}).get("dataList"), base)
        for m in items:
            if m.get("kind") != "media":
                continue
            pt = m.get("payType")
            if pt == 2 and len(gold) < 4:
                gold.append(m)
            elif pt == 4 and len(vip) < 2:
                vip.append(m)
            elif pt == 1 and len(free) < 1:
                free.append(m)
        if len(gold) >= 4 and len(vip) >= 2 and free:
            break
        time.sleep(0.4)

    samples = [("金币", gold), ("VIP", vip), ("免费", free)]
    for label, arr in samples:
        print("\n" + "=" * 70)
        print("样本类型: %s （%d 个）" % (label, len(arr)))
        for m in arr:
            print("-" * 70)
            print("  id=%s  时长=%ss  标题=%s" % (
                m.get("id"), m.get("duration"), (m.get("title") or "")[:24]))
            vu, pu = m.get("videoPath") or "", m.get("previewPath") or ""
            print("  videoUrl      : %s" % (vu[:110] + ("..." if len(vu) > 110 else "")))
            print("  videoPreviewUrl: %s" % (pu[:110] + ("..." if len(pu) > 110 else "")))
            print("  两者相同? %s" % (vu == pu))
            print("  videoUrl 带 _preview? %s   previewUrl 带 _preview? %s" % (
                "_preview" in vu, "_preview" in pu))
            for tag, u in (("videoUrl", vu), ("previewUrl", pu)):
                if not u:
                    print("  [%s] 无地址" % tag)
                    continue
                full = u if u.startswith("http") else base + u
                st, txt = fetch_text(full)
                info = parse_m3u8(txt) if st == 200 else None
                if info:
                    print("  [%s] HTTP %s → 分片 %d 个 / 总时长 %.0fs / 加密=%s / master=%s / ENDLIST=%s" % (
                        tag, st, info["segments"], info["duration"],
                        info["encrypted"], info["master"], info["endlist"]))
                    print("        首个分片: %s" % info["first_seg"])
                    if info["master"]:
                        print("        (master 播放列表，需再取子 m3u8)")
                else:
                    head = txt[:80].replace("\n", " ")
                    print("  [%s] HTTP %s → 非 m3u8: %s" % (tag, st, head))
                time.sleep(0.3)

    print("\n[完成] 全部为只读 GET，未构造/修改任何参数。")


if __name__ == "__main__":
    main()

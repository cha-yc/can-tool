#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WorkBuddy 自动签到 + 宠物旅行 + 成长中心（整合版，青龙面板兼容）
================================================================
整合 new.txt（88lin/workbuddy-auto-signin，MIT，签到与成长中心接口契约）
与 de.txt（环境变量多账号结构），全部接口统一走 /v2：

  签到      POST /v2/billing/meter/checkin-activity-status → daily-checkin
  旅行      GET  /v2/activity/growth/buddy/travel/status
            POST /v2/activity/growth/buddy/travel/claim|depart
            GET  /v2/activity/growth/buddy/travel/config
  成长中心  /v2/activity/growth/{tasks,streak,heatmap,makeup-cards/use,
            redeem/summary,redeem,lottery/chances,lottery/draw,
            buddy/quota,buddy/open,energy}

执行顺序：签到 → 旅行（WB_TRAVEL_ENABLE 单独控制）→ 成长中心其余模块。
接口幂等，高频运行无副作用；多账号逐个执行，单账号失败不影响其它账号。

令牌环境变量（核心格式：accessToken#refreshToken）：
  WB_ACCESS_TOKENS   多账号，逗号分隔；每项 [uid:]accessToken[#refreshToken]
  WB_ACCESS_TOKEN    单账号，格式同上（可与 TOKENS 同时存在）
  JWT 只含 A-Za-z0-9._~- 与 =，不含 # : ,，三种分隔符互不冲突。
  不带 #refreshToken 也能跑，只是 401 时无法自动刷新。
  本机获取：python get_workbuddy_token.py --env
  （自动解密桌面端加密凭据，stdout 仅一行 access#refresh，直接粘贴即可）

开关与可选环境变量：
  WB_TRAVEL_ENABLE       默认 1；设 0 整个旅行模块不查不领不派
  WB_TRAVEL_AUTO_DEPART  默认 1；设 0 只领取积分、不自动派出
  WB_TRAVEL_LOCATION     可选，派出地点 id(如 1) 或 code(如 coffee)；缺省取第一个
  WB_GROWTH_ENABLE       默认 1；设 0 跳过成长中心其余模块（任务/补登/兑换/抽奖）
                         （两个开关都设 0 = 仅签到，等同旧 de.txt 的签到脚本）
  WB_TOKEN_FILE          刷新后令牌存储路径（默认：脚本同目录 wb_tokens.json）
  WB_API_BASE          默认 https://copilot.tencent.com
  WB_PROXY             可选代理，如 http://127.0.0.1:7897；默认直连

401 自动刷新（Keycloak OIDC 标准协议）：
  任一接口 401 时用 refreshToken 调 {iss}/protocol/openid-connect/token 换新令牌，
  iss/client_id(azp) 优先取 JWT 声明。每个账号每轮最多刷新一次。
  ⚠️ Keycloak refreshToken 一次性轮换：刷新后旧值作废，新令牌立即原子落盘到
  WB_TOKEN_FILE，下轮启动按 JWT iat 择优（存储较新则用存储，环境变量更新则用
  环境变量）。该文件含长期令牌，勿提交仓库（已加 .gitignore），Linux 自动 chmod 600。
  ⚠️ 环境变量令牌来自桌面端会话副本：服务器刷新会轮换掉桌面端的 refreshToken，
  桌面端下次刷新时可能需重新登录（与 wb_token_server.py 相同的已知代价）。

退出码：0 全部成功；1 任一账号失败；2 未配置令牌。
"""

import base64
import json
import math
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import date

# 优先用 requests（青龙自带），否则回退标准库 urllib
try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False


def log(msg):
    """青龙捕获 stdout 作为任务日志/通知内容。"""
    print(msg, flush=True)


def env_flag(name, default=True):
    """开关型环境变量：未设置/空串取默认值；0/false/no/off 视为关。"""
    raw = (os.environ.get(name) or "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def decode_jwt_payload(token):
    """不校验签名，仅读 JWT payload 的 sub/iss/azp/iat/exp 等元信息。"""
    if not isinstance(token, str):
        return {}
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
API_BASE = (os.environ.get("WB_API_BASE") or "https://copilot.tencent.com").rstrip("/")
CHECKIN_STATUS_EP = API_BASE + "/v2/billing/meter/checkin-activity-status"
CHECKIN_EP = API_BASE + "/v2/billing/meter/daily-checkin"
GROWTH_BASE = API_BASE + "/v2/activity/growth"

TRAVEL_ENABLE = env_flag("WB_TRAVEL_ENABLE", True)
AUTO_DEPART = env_flag("WB_TRAVEL_AUTO_DEPART", True)
GROWTH_ENABLE = env_flag("WB_GROWTH_ENABLE", True)
LOCATION_ARG = (os.environ.get("WB_TRAVEL_LOCATION") or "").strip()

# 默认直连，避免系统 SOCKS 代理导致 requests 缺依赖崩溃（沿用 de.txt）
PROXY = (os.environ.get("WB_PROXY") or "").strip()
PROXIES = {"http": PROXY, "https": PROXY} if PROXY else {"http": None, "https": None}

TOKEN_FILE = os.environ.get("WB_TOKEN_FILE") or os.path.join(SCRIPT_DIR, "wb_tokens.json")
DEFAULT_ISS = "https://www.codebuddy.cn/auth/realms/coilot"
CLIENT_ID = "console"
# 每轮最多用掉一张补登卡（沿用 new.txt：仅依据服务端日历中明确的当月断登日期）
MAKEUP_MAX_PER_RUN = 1


# ---------------------------------------------------------------------------
# 账号解析与令牌存储
# ---------------------------------------------------------------------------
def get_accounts():
    """解析 WB_ACCESS_TOKENS / WB_ACCESS_TOKEN，返回账号 dict 列表。
    每项格式 [uid:]accessToken[#refreshToken]；uid 缺省时从 JWT sub 解析。
    """
    entries = []
    raw = (os.environ.get("WB_ACCESS_TOKENS") or "").strip()
    if raw:
        entries.extend(item.strip() for item in raw.split(",") if item.strip())
    single = (os.environ.get("WB_ACCESS_TOKEN") or "").strip()
    if single:
        entries.append(single)
    if not entries:
        log("❌ 未检测到 Token：请设置环境变量 WB_ACCESS_TOKEN 或 WB_ACCESS_TOKENS")
        log("   格式：accessToken#refreshToken（本机运行 get_workbuddy_token.py --env 获取）")
        return []
    accounts = []
    for item in entries:
        uid = ""
        # JWT 不含冒号，冒号只可能是 uid 前缀（沿用 de.txt 规则）
        if ":" in item and not item.startswith("eyJ"):
            uid, item = item.split(":", 1)
            uid, item = uid.strip(), item.strip()
        if "#" in item:
            access, refresh = item.split("#", 1)
            access, refresh = access.strip(), refresh.strip()
        else:
            access, refresh = item, ""
        if not access:
            log("⚠️ 跳过空令牌项")
            continue
        if not uid:
            uid = str(decode_jwt_payload(access).get("sub") or "")
        accounts.append({"uid": uid, "access": access, "refresh": refresh})
    return accounts


def load_store():
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        accounts = data.get("accounts") if isinstance(data, dict) else None
        return accounts if isinstance(accounts, dict) else {}
    except (OSError, ValueError):
        return {}


def merge_store(accounts):
    """本地存储保存刷新后的较新令牌，按 JWT iat 择优覆盖环境变量值。
    用户重新登录并更新环境变量后新令牌 iat 更大，不会被旧存储盖掉。
    """
    store = load_store()
    if not store:
        return
    for acc in accounts:
        entry = store.get(acc["uid"])
        if not isinstance(entry, dict) or not entry.get("accessToken"):
            continue
        env_iat = decode_jwt_payload(acc["access"]).get("iat") or 0
        store_iat = decode_jwt_payload(entry["accessToken"]).get("iat") or 0
        if store_iat >= env_iat:
            acc["access"] = entry["accessToken"]
            if entry.get("refreshToken"):
                acc["refresh"] = entry["refreshToken"]
            log(f"🔑 [{(acc['uid'] or '')[:8]}…] 使用令牌存储中的较新令牌（{os.path.basename(TOKEN_FILE)}）")


def persist_account(acc):
    """刷新成功后立即落盘：refreshToken 一次性轮换，旧值已作废，不保存新值
    下一轮刷新必然失败。临时文件 + os.replace 原子写，避免写坏 JSON。
    """
    store = load_store()
    store[acc["uid"]] = {
        "accessToken": acc["access"],
        "refreshToken": acc.get("refresh", ""),
        "updatedAt": int(time.time() * 1000),
    }
    directory = os.path.dirname(os.path.abspath(TOKEN_FILE)) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"accounts": store}, f, ensure_ascii=False, indent=2)
        os.replace(tmp, TOKEN_FILE)
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
    if os.name == "posix":
        os.chmod(TOKEN_FILE, 0o600)


def refresh_account(acc):
    """401 时用 refreshToken 走 Keycloak 标准端点换新令牌；成功则更新账号并落盘。
    iss/client_id 优先取 refreshToken JWT 的 iss/azp，比硬编码更抗迁移/客户端变更。
    """
    rt = acc.get("refresh") or ""
    if not rt:
        return False
    tag = acc.get("_tag", "账号")
    rp = decode_jwt_payload(rt)
    ap = decode_jwt_payload(acc.get("access", ""))
    iss = rp.get("iss") or ap.get("iss") or DEFAULT_ISS
    client_id = rp.get("azp") or ap.get("azp") or CLIENT_ID
    endpoint = urllib.parse.urljoin(iss + "/", "protocol/openid-connect/token")
    payload = urllib.parse.urlencode({
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": rt,
    }).encode("utf-8")
    req = urllib.request.Request(
        endpoint, data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            tokens = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:200]
        log(f"⚠️ [{tag}] 刷新失败：HTTP {e.code} {detail}（refreshToken 可能已过期或被轮换作废）")
        return False
    except Exception as e:
        log(f"⚠️ [{tag}] 刷新失败：{e}")
        return False
    if not tokens.get("access_token"):
        log(f"⚠️ [{tag}] 刷新返回缺少 access_token")
        return False
    acc["access"] = tokens["access_token"]
    if tokens.get("refresh_token"):
        acc["refresh"] = tokens["refresh_token"]
    try:
        persist_account(acc)
        log(f"🔄 [{tag}] 令牌已刷新并保存到 {TOKEN_FILE}")
    except OSError as e:
        # 落盘失败时旧 refreshToken 已作废，必须把新令牌交还给用户，否则下轮必死
        log(f"⚠️ [{tag}] 令牌已刷新但保存失败：{e}")
        log(f"🔄 [{tag}] 请用此值更新环境变量：{acc['access']}#{acc['refresh']}")
    return True


# ---------------------------------------------------------------------------
# HTTP 层
# ---------------------------------------------------------------------------
def http(method, url, acc, body=None):
    """底层请求，返回 (状态码, 响应文本)；网络异常向上抛给调用方兜底。"""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer " + acc["access"],
        "X-User-Id": acc.get("uid", ""),
        "User-Agent": "WorkBuddy",
    }
    data = None if method == "GET" else json.dumps(body if body is not None else {}).encode("utf-8")
    if HAVE_REQUESTS:
        resp = requests.request(method, url, headers=headers, data=data, timeout=20, proxies=PROXIES)
        return resp.status_code, resp.text
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "ignore")


def api(method, url, acc, body=None):
    """带 401 自动刷新的请求，返回 (状态码, 解析后的 JSON)。
    每账号每轮最多刷新一次；刷新后仍 401/403 标记 _auth_dead，主流程跳过后续模块。
    """
    code, text = http(method, url, acc, body)
    if code == 401 and not acc.get("_refresh_attempted"):
        acc["_refresh_attempted"] = True
        if refresh_account(acc):
            code, text = http(method, url, acc, body)
    if code in (401, 403):
        acc["_auth_dead"] = True
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        parsed = {"raw": str(text)[:200]}
    return code, parsed


# ---------------------------------------------------------------------------
# 响应工具（契约沿用 new.txt 实测结论）
# ---------------------------------------------------------------------------
def dig(obj, key):
    """在可能被 data/result 包裹的响应里找字段，兼容信封结构。"""
    if isinstance(obj, dict):
        if key in obj and obj[key] is not None:
            return obj[key]
        for k in ("data", "result", "resp", "response"):
            if k in obj and isinstance(obj[k], dict):
                r = dig(obj[k], key)
                if r is not None:
                    return r
    return None


def msg_of(body):
    if isinstance(body, dict):
        return str(body.get("msg") or body.get("error") or "")
    return ""


def biz_ok(code, body):
    """HTTP 2xx 且业务码为 0（或缺省）。"""
    if not 200 <= code < 300:
        return False
    bcode = body.get("code") if isinstance(body, dict) else None
    return bcode is None or (type(bcode) is int and bcode == 0)


def _is_hard_failure(code):
    """5xx 才算需要关注的失败；4xx 多为业务常态（名额用完/档位未解锁）。"""
    return code >= 500


def as_int(v, default=0):
    """安全转 int；json.loads 接受 Infinity，int(inf) 抛 OverflowError 一并捕获。"""
    try:
        return int(v)
    except (TypeError, ValueError, OverflowError):
        pass
    try:
        return int(float(v))
    except (TypeError, ValueError, OverflowError):
        return default


def fmt_credit(v):
    try:
        return int(v)
    except (TypeError, ValueError, OverflowError):
        return v


def _first_int(body, key, fallback=0):
    """优先响应实发值；列表里的 reward_credit 只是活动配置，挖不到才回落。"""
    if isinstance(body, dict):
        v = dig(body, key)
        if v is not None:
            return as_int(v)
    return as_int(fallback)


def _fmt_eta(arrive_at, server_now):
    """服务端时间戳换算"还有多久回来"；缺失/非有限值返回空串，绝不因展示信息失败。"""
    try:
        left = float(arrive_at) - float(server_now)
    except (TypeError, ValueError, OverflowError):
        return ""
    if not math.isfinite(left):
        return ""
    if left <= 0:
        return "，已到达待领取"
    minutes = int(round(left / 60.0))
    if minutes < 60:
        return "，约 %d 分钟后回" % max(1, minutes)
    return "，约 %.1f 小时后回" % (left / 3600.0)


def _client_token(prefix="u"):
    """抽奖/兑换要求的防重放 token；缺了 /lottery/draw 直接 400（new.txt 实测）。"""
    return "%s-%s" % (prefix, uuid.uuid4())


def is_already_checked(body):
    """领取接口返回是否表示"今日已签"（兼容 null 与 code10001/文案）。"""
    if body is None:
        return True
    if isinstance(body, dict):
        if body.get("code") == 10001 or "已签" in str(body.get("msg") or ""):
            return True
    return False


# ---------------------------------------------------------------------------
# 签到
# ---------------------------------------------------------------------------
def checkin_one(acc):
    """查状态→未签才领，返回 (成功, 消息)。状态接口只认 POST（GET 会 404）。"""
    code, body = api("POST", CHECKIN_STATUS_EP, acc)
    if code in (401, 403):
        return False, f"登录态失效或权限拒绝(HTTP {code})，请重新获取 Token"
    if not biz_ok(code, body):
        return False, f"状态查询失败(HTTP {code}) code={(body or {}).get('code')} msg={msg_of(body)}"
    if dig(body, "active") is False:
        return True, "签到活动未开启"
    if dig(body, "today_checked_in") in (True, 1):
        streak = dig(body, "streak_days")
        return True, f"今日已签到（连续 {streak if streak is not None else 0} 天）"

    code, body = api("POST", CHECKIN_EP, acc)
    if code in (401, 403):
        return False, f"登录态失效或权限拒绝(HTTP {code})，请重新获取 Token"
    if is_already_checked(body):
        return True, "今日已签到（接口确认）"
    credit = dig(body, "credit")
    if credit is not None:
        streak = dig(body, "streak_days")
        extra = f"（连续 {streak} 天）" if streak is not None else ""
        return True, f"签到成功 +{fmt_credit(credit)} 积分{extra}"
    return False, f"签到失败(HTTP {code}) code={(body or {}).get('code')} msg={msg_of(body)}"


# ---------------------------------------------------------------------------
# 宠物旅行（WB_TRAVEL_ENABLE 单独控制整个模块）
# ---------------------------------------------------------------------------
def pick_location(config_body):
    """按 WB_TRAVEL_LOCATION 选地点；未指定则取配置第一个。"""
    locations = dig(config_body, "locations") or []
    if not locations:
        return None
    if LOCATION_ARG:
        for loc in locations:
            if str(loc.get("id")) == LOCATION_ARG or loc.get("code") == LOCATION_ARG:
                return loc
        log(f"⚠️ 指定的地点 '{LOCATION_ARG}' 不在可选列表，回退到第一个地点")
    return locations[0]


def travel_one(acc):
    """arrived→领取（成功后视为 idle 可继续派出）；traveling→等待；idle→派出。"""
    code, body = api("GET", GROWTH_BASE + "/buddy/travel/status", acc)
    if code in (401, 403):
        return False, f"旅行状态查询被拒绝(HTTP {code})"
    if not biz_ok(code, body):
        return False, f"旅行状态查询失败(HTTP {code})：{msg_of(body)}"
    state = dig(body, "state")
    limit_reached = bool(dig(body, "daily_limit_reached"))
    parts = []

    if state == "arrived":
        record_id = dig(body, "record_id")
        claim_body = {"record_id": record_id} if record_id is not None else {}
        ccode, cbody = api("POST", GROWTH_BASE + "/buddy/travel/claim", acc, claim_body)
        if ccode in (401, 403):
            return False, f"旅行领取被拒绝(HTTP {ccode})"
        got = dig(cbody, "reward_credit")
        if got is None:
            got = dig(cbody, "credit")
        if biz_ok(ccode, cbody) and got is not None:
            parts.append(f"🎉 宠物已归来，领取积分 +{fmt_credit(got)}")
            state = "idle"  # 只有领取成功才视为空闲，避免派出覆盖未领取奖励
        elif (ccode == 400 or (isinstance(cbody, dict) and cbody.get("code") == 400)) \
                and "no unclaimed" in msg_of(cbody):
            parts.append("宠物已归来，本次无可领取奖励（可能已领取过）")
            state = "idle"
        else:
            return False, f"旅行领取失败(HTTP {ccode})：{msg_of(cbody)}"

    if state == "traveling":
        loc_name = (dig(body, "location") or {}).get("name", "")
        eta = _fmt_eta(dig(body, "arrive_at"), dig(body, "server_now"))
        parts.append(f"🚀 宠物正在探险中（{loc_name}{eta}），本轮不重复派出")
        return True, "；".join(parts)

    if state == "idle":
        if limit_reached:
            parts.append("😴 今日派出次数已达上限，明天再派")
            return True, "；".join(parts)
        if not AUTO_DEPART:
            parts.append("😴 宠物空闲（WB_TRAVEL_AUTO_DEPART=0，仅领取模式，未自动派出）")
            return True, "；".join(parts)
        ccode, cbody = api("GET", GROWTH_BASE + "/buddy/travel/config", acc)
        if ccode in (401, 403):
            return False, f"旅行配置查询被拒绝(HTTP {ccode})"
        loc = pick_location(cbody) if biz_ok(ccode, cbody) else None
        if not loc:
            return False, "未获取到可选的探险地点配置"
        dcode, dbody = api("POST", GROWTH_BASE + "/buddy/travel/depart", acc,
                           {"location_id": loc.get("id")})
        if dcode in (401, 403):
            return False, f"旅行派出被拒绝(HTTP {dcode})"
        if biz_ok(dcode, dbody):
            loc_name = (dig(dbody, "location") or {}).get("name") or loc.get("name", "")
            dur = (dig(dbody, "duration_hours")
                   or (dig(dbody, "location") or {}).get("duration_hours")
                   or loc.get("duration_hours_max") or loc.get("duration_hours_min") or "?")
            parts.append(f"🐾 已自动派出宠物前往「{loc_name}」，约 {dur} 小时后归来")
            return True, "；".join(parts)
        return False, f"旅行派出失败(HTTP {dcode})：{msg_of(dbody)}"

    if parts:
        return True, "；".join(parts)
    return True, f"宠物状态未知: {state}"


# ---------------------------------------------------------------------------
# 成长中心其余模块（任务/补登/连登兑换/盲盒/Buddy盲盒/状态展示）
# 接口契约与边界处理沿用 new.txt（88lin/workbuddy-auto-signin，MIT）实测结论
# ---------------------------------------------------------------------------
_REDEEM_REWARDS = {
    "7d":  "+2 能量 +1 补登卡 +1 次抽奖",
    "14d": "+50 积分 +3 能量 +1 补登卡 +1 次抽奖",
    "28d": "+150 积分 +5 能量 +1 补登卡 +1 次抽奖",
}
# (档位标识, /redeem/summary 状态字段前缀, 展示名, 天数)；tier 传标识字符串，
# 天数仅用于 unknown tier 时兜底重试（new.txt 实测 "7d" 才 200）
_REDEEM_TIERS = (
    ("7d",  "starter",   "入门", 7),
    ("14d", "advanced",  "进阶", 14),
    ("28d", "legendary", "巅峰", 28),
)


def _redeem_reward_desc(body, tier):
    """实发字段带 _granted 后缀；直接读 credit 恒为空会漏计。"""
    bits = []
    credit = as_int(dig(body, "credit_granted"), 0)
    energy = as_int(dig(body, "energy_granted"), 0)
    cards = as_int(dig(body, "cards_granted"), 0)
    chances = as_int(dig(body, "chances_granted"), 0)
    if credit:
        bits.append("+%s 积分" % fmt_credit(credit))
    if energy:
        bits.append("+%s 能量" % fmt_credit(energy))
    if cards:
        bits.append("+%s 补登卡" % fmt_credit(cards))
    if chances:
        bits.append("+%s 次抽奖" % fmt_credit(chances))
    if bits:
        return "（%s）" % " ".join(bits)
    return "（%s）" % _REDEEM_REWARDS.get(tier, "奖励已到账")


def _is_no_chance(msg):
    """抽奖"次数为 0"是常态不是故障，不计失败。"""
    m = str(msg or "").lower()
    if not m:
        return False
    if "insufficient" in m or "not enough" in m:
        return "chance" in m or "balance" in m
    return "no chance" in m


def _is_unknown_tier(code, body):
    """tier 标识本身不认识时才退回天数重试；参数校验阶段拒绝，不会重复兑换。"""
    if code != 400:
        return False
    m = str(dig(body, "msg") or "").lower()
    return "tier" in m and ("unknown" in m or "unsupported" in m or "invalid" in m)


def _is_tier_locked(code, body):
    """403「连续登录天数不足」是业务常态，必须先于认证拒绝判断。"""
    if code != 403:
        return False
    m = str(dig(body, "msg") or "")
    return "天数不足" in m or "不足" in m


def _makeup_candidates(streak_body, heatmap_body):
    """从日历选断登日期：当月、今天之前、活动上线之后、score==0 且未补过。
    makeup_dates 是已补登历史不能当待办；结构异常时抛错停止，不猜测消耗补登卡。
    """
    def parse_date(value):
        if not isinstance(value, str) or re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) is None:
            raise ValueError("补登日期格式无效")
        return date.fromisoformat(value)

    today_obj = dig(heatmap_body, "today")
    if not isinstance(today_obj, dict):
        raise ValueError("活跃日历缺少服务端日期")
    today = parse_date(today_obj.get("date"))
    launch = parse_date(dig(streak_body, "launch_date"))
    start = max(today.replace(day=1), launch, date(2026, 6, 17))
    streak = dig(streak_body, "streak")
    if not isinstance(streak, dict):
        raise ValueError("连登状态格式无效")
    made_up = streak.get("makeup_dates", [])
    if not isinstance(made_up, list):
        raise ValueError("已补登记录格式无效")
    made_up = {parse_date(value) for value in made_up}
    cells = dig(heatmap_body, "cells")
    if not isinstance(cells, list):
        raise ValueError("活跃日历缺少日期列表")
    scores = {}
    for cell in cells:
        if not isinstance(cell, dict):
            raise ValueError("活跃日历记录格式无效")
        day = parse_date(cell.get("date"))
        score = cell.get("score")
        if type(score) not in (int, float) or not math.isfinite(score) or score < 0:
            raise ValueError("活跃日历分数无效")
        if day in scores and scores[day] != score:
            raise ValueError("活跃日历同一日期的记录冲突")
        scores[day] = score
    # 最近断点优先，尽早恢复连登；每轮仍受 MAKEUP_MAX_PER_RUN 限制
    return sorted((day.isoformat() for day, score in scores.items()
                   if start <= day < today and score == 0 and day not in made_up), reverse=True)


def growth_one(acc):
    """成长中心（旅行以外）：任务→补登→连登兑换→盲盒→Buddy盲盒→状态展示。
    各段单独 try，一段失败不影响其余；认证/权限拒绝时中止本轮。
    返回 (是否无硬失败, 汇报文本)。
    """
    parts = []
    credits_gained = 0
    failures = 0
    hard_failures = 0
    successes = 0

    def _check_auth(code):
        return code in (401, 403)

    def _auth_report(code):
        return False, f"成长中心认证/权限被拒绝(HTTP {code})，本轮中止"

    def _note_http(code, body, label, required=False):
        """前置查询非 2xx 的统一记录；返回 True 表示跳过后续处理。
        硬失败必须计数，否则服务端故障会无声无息；必需查询失败不能解释为无需操作。
        """
        nonlocal failures, hard_failures
        if 200 <= code < 300 and (not required or biz_ok(code, body)):
            return False
        detail = msg_of(body)
        parts.append("%s失败：HTTP %s%s" % (label, code, ("（%s）" % detail) if detail else ""))
        if required or _is_hard_failure(code):
            failures += 1
            hard_failures += 1
        return True

    # --- 1. 任务领奖（放在抽奖前：任务送的抽奖机会/能量后面马上能用）---
    try:
        tcode, tbody = api("GET", GROWTH_BASE + "/tasks", acc)
        if _check_auth(tcode):
            return _auth_report(tcode)
        if not _note_http(tcode, tbody, "查任务列表"):
            tasks = dig(tbody, "tasks") or []
            # 真实契约（new.txt 2026-09 从桌面端成长中心 H5 读出）：
            #   accept_status: not_accepted|accepted|in_progress|completed|claimed
            #   接单 POST /tasks/accept body {"task_codes":[...]}（复数数组，单数一律 400）
            #   领奖 POST /tasks/{task_code}/claim（路径带 code、body 空）
            titles = {t.get("task_code"): t.get("title", t.get("task_code")) for t in tasks}
            pending = [t.get("task_code") for t in tasks
                       if t.get("task_code") and not t.get("locked")
                       and t.get("accept_status") == "not_accepted"]
            for i in range(0, len(pending), 20):  # 分批，别把 body 撑大
                batch = pending[i:i + 20]
                acode, abody = api("POST", GROWTH_BASE + "/tasks/accept", acc,
                                   {"task_codes": batch})
                if _check_auth(acode):
                    return _auth_report(acode)
                # 逐条读 results：接单失败必须报出来，静默吞掉接口坏了也没人知道
                results = dig(abody, "results")
                if not isinstance(results, list):
                    results = [{"task_code": c,
                                "status": "ok" if 200 <= acode < 300 else "error",
                                "message": dig(abody, "msg")} for c in batch]
                for r in results:
                    title = titles.get(r.get("task_code"), r.get("task_code"))
                    if r.get("status") == "error":
                        parts.append("领取任务「%s」失败：%s" % (
                            title, r.get("message") or "HTTP %s" % acode))
                        failures += 1
                        hard_failures += _is_hard_failure(acode)
                    else:
                        parts.append("领取任务「%s」（进度开始计）" % title)
                        successes += 1
            for t in tasks:
                if t.get("locked") or t.get("accept_status") != "completed":
                    continue  # 只有 completed 才发奖，且走独立路径
                code = t.get("task_code")
                title = titles.get(code, code)
                try:
                    ccode, cbody = api("POST", GROWTH_BASE + "/tasks/%s/claim" % code, acc, {})
                    if _check_auth(ccode):
                        return _auth_report(ccode)
                    if 200 <= ccode < 300 and not dig(cbody, "already_claimed"):
                        rc = _first_int(cbody, "credit", t.get("reward_credit"))
                        re_ = _first_int(cbody, "energy", t.get("reward_energy"))
                        credits_gained += rc
                        parts.append("领任务奖「%s」+credit%s+energy%s" % (title, rc, re_))
                        successes += 1
                    elif 200 <= ccode < 300:
                        parts.append("任务奖「%s」已领过" % title)
                    else:
                        parts.append("领任务奖「%s」失败：%s" % (
                            title, msg_of(cbody) or "HTTP %s" % ccode))
                        failures += 1
                        hard_failures += _is_hard_failure(ccode)
                except Exception as e:
                    parts.append("领任务奖「%s」异常（%s: %s）" % (code, type(e).__name__, e))
                    failures += 1
                    hard_failures += 1
    except Exception as e:
        parts.append("任务模块异常（%s: %s）" % (type(e).__name__, e))
        failures += 1
        hard_failures += 1

    # --- 2. 补登卡：断登自动补一张保连登；放在兑换前（补登改变连登天数）---
    streak_body = None    # 复用给展示段，避免同一轮打两次 /streak
    streak_stale = False  # 补登成功会改变天数，此时必须重新取
    try:
        mcode, mbody = api("GET", GROWTH_BASE + "/streak", acc)
        if _check_auth(mcode):
            return _auth_report(mcode)
        if not _note_http(mcode, mbody, "查连登状态", required=True):
            streak_body = mbody
            # 余额兼容 {"makeup_cards":{"balance":2}} 与 {"makeup_cards":2} 两种形状
            cards_obj = dig(mbody, "makeup_cards")
            cards = as_int(cards_obj.get("balance")) if isinstance(cards_obj, dict) \
                else as_int(cards_obj)
            dates = []
            if cards > 0:
                hcode, hbody = api("GET", GROWTH_BASE + "/heatmap", acc)
                if _check_auth(hcode):
                    return _auth_report(hcode)
                if not _note_http(hcode, hbody, "查补登日历", required=True):
                    dates = _makeup_candidates(mbody, hbody)
            if dates:
                made_up = 0
                for d in dates[:min(cards, MAKEUP_MAX_PER_RUN)]:
                    ucode, ubody = api("POST", GROWTH_BASE + "/makeup-cards/use", acc,
                                       {"target_date": d})
                    if _check_auth(ucode):
                        return _auth_report(ucode)
                    if biz_ok(ucode, ubody):
                        cards -= 1
                        made_up += 1
                        streak_stale = True
                        left_obj = dig(ubody, "makeup_cards")
                        left_cards = as_int(left_obj.get("balance"), cards) \
                            if isinstance(left_obj, dict) else as_int(left_obj, cards)
                        parts.append("补登 %s（剩 %s 张卡）" % (d, left_cards))
                        cards = max(0, left_cards)
                        successes += 1
                    else:
                        msg = msg_of(ubody)
                        if ucode == 400 and msg.strip().lower() == "date is not broken, no makeup needed":
                            # 查询后被客户端或另一轮补上，正常竞争，不算失败
                            parts.append("%s 已活跃或已补登，无需再次补登" % d)
                            break
                        parts.append("补登 %s 失败：%s" % (d, msg or "HTTP %s" % ucode))
                        failures += 1
                        hard_failures += 1
                        break
                if made_up and len(dates) > made_up and cards > 0:
                    parts.append("另有 %s 天可补、剩 %s 张卡，下轮继续" % (
                        len(dates) - made_up, cards))
    except Exception as e:
        parts.append("补登模块异常（%s: %s）" % (type(e).__name__, e))
        failures += 1
        hard_failures += 1

    # --- 3. 连登奖励兑换（7/14/28 天三档）---
    try:
        rcode, rbody = api("GET", GROWTH_BASE + "/redeem/summary", acc)
        if _check_auth(rcode):
            return _auth_report(rcode)
        if not _note_http(rcode, rbody, "查连登兑换"):
            for tier, status_key, label, days in _REDEEM_TIERS:
                status = dig(rbody, status_key + "_status")
                # 字段缺失同样跳过：接口改版时不该对三档无脑 POST
                if not status or status in ("claimed", "locked"):
                    continue
                c2code, c2body = api("POST", GROWTH_BASE + "/redeem", acc,
                                     {"tier": tier, "client_token": _client_token()})
                if _is_unknown_tier(c2code, c2body):
                    c2code, c2body = api("POST", GROWTH_BASE + "/redeem", acc,
                                         {"tier": days, "client_token": _client_token()})
                # 403「天数不足」是常态，必须先于 _check_auth，否则会中止整个成长中心
                if _is_tier_locked(c2code, c2body):
                    parts.append("连登兑换「%s」未解锁（连登天数不足）" % label)
                    continue
                if _check_auth(c2code):
                    return _auth_report(c2code)
                if 200 <= c2code < 300:
                    credits_gained += as_int(dig(c2body, "credit_granted"))
                    parts.append("连登兑换「%s」%s" % (label, _redeem_reward_desc(c2body, tier)))
                    successes += 1
                else:
                    parts.append("连登兑换「%s」失败：%s" % (
                        label, msg_of(c2body) or "HTTP %s" % c2code))
                    failures += 1
                    hard_failures += _is_hard_failure(c2code)
    except Exception as e:
        parts.append("连登兑换模块异常（%s: %s）" % (type(e).__name__, e))
        failures += 1
        hard_failures += 1

    # --- 4. 盲盒/抽奖（draw 必须带 client_token；一轮只开一次，写路径不可逆）---
    try:
        lcode, lbody = api("GET", GROWTH_BASE + "/lottery/chances", acc)
        if _check_auth(lcode):
            return _auth_report(lcode)
        chances = 0 if _note_http(lcode, lbody, "查抽奖机会") else as_int(dig(lbody, "balance"))
        if chances > 0:
            dcode, dbody = api("POST", GROWTH_BASE + "/lottery/draw", acc,
                               {"client_token": _client_token()})
            if _check_auth(dcode):
                return _auth_report(dcode)
            if 200 <= dcode < 300:
                prize = dig(dbody, "prize_name") or dig(dbody, "prize") or "未知"
                if not isinstance(prize, str):
                    prize = str(prize)
                # 实物奖需用户自己填收件信息，脚本代填不了但必须提醒
                if dig(dbody, "need_address") or dig(dbody, "require_address"):
                    prize += "（实物奖，需到成长中心填写收件信息）"
                parts.append("开盲盒获得：%s" % prize)
                successes += 1
                if chances > 1:
                    parts.append("还剩 %s 次抽奖机会，下轮继续" % (chances - 1))
            else:
                msg = msg_of(dbody)
                if _is_no_chance(msg):
                    parts.append("开盲盒：%s" % (msg or "无抽奖机会"))
                else:
                    parts.append("开盲盒失败：%s" % (msg or "HTTP %s" % dcode))
                    failures += 1
                    hard_failures += _is_hard_failure(dcode)
    except Exception as e:
        parts.append("盲盒模块异常（%s: %s）" % (type(e).__name__, e))
        failures += 1
        hard_failures += 1

    # --- 5. Buddy 盲盒（能量攒够 cost_per_open 就开；能量无其它消耗出口）---
    try:
        qcode, qbody = api("GET", GROWTH_BASE + "/buddy/quota", acc)
        if _check_auth(qcode):
            return _auth_report(qcode)
        if not _note_http(qcode, qbody, "查 Buddy 能量"):
            affordable = as_int(dig(qbody, "affordable"))
            max_open = as_int(dig(qbody, "max_open_count"), 1) or 1
            if affordable > 0:
                count = min(affordable, max_open)
                ocode, obody = api("POST", GROWTH_BASE + "/buddy/open", acc,
                                   {"count": count, "client_token": _client_token()})
                if _check_auth(ocode):
                    return _auth_report(ocode)
                if 200 <= ocode < 300:
                    name = dig(obody, "buddy") or dig(obody, "name") or dig(obody, "buddies")
                    if not isinstance(name, str):
                        name = "新 Buddy"
                    parts.append("开 Buddy 盲盒 ×%s（%s）" % (count, name))
                    successes += 1
                else:
                    parts.append("开 Buddy 盲盒失败：%s" % (
                        msg_of(obody) or "HTTP %s" % ocode))
                    failures += 1
                    hard_failures += _is_hard_failure(ocode)
    except Exception as e:
        parts.append("Buddy 盲盒模块异常（%s: %s）" % (type(e).__name__, e))
        failures += 1
        hard_failures += 1

    # --- 6. 能量 & 连签状态（纯展示，失败不计）---
    energy = None
    streak_days = None
    try:
        ecode, ebody = api("GET", GROWTH_BASE + "/energy", acc)
        if not _check_auth(ecode):
            energy = dig(ebody, "balance") if 200 <= ecode < 300 else None
    except Exception:
        pass
    try:
        if streak_body is not None and not streak_stale:
            streak_obj = dig(streak_body, "streak") or {}
            streak_days = streak_obj.get("days") if isinstance(streak_obj, dict) else None
        else:
            scode2, sbody2 = api("GET", GROWTH_BASE + "/streak", acc)
            if not _check_auth(scode2):
                streak_obj = dig(sbody2, "streak") or {}
                streak_days = streak_obj.get("days") if isinstance(streak_obj, dict) else None
    except Exception:
        pass

    tail = []
    if energy is not None:
        tail.append("能量 %s" % energy)
    if streak_days is not None:
        tail.append("连签 %s 天" % streak_days)
    if credits_gained:
        tail.append("本次共 +%s 积分" % credits_gained)
    if parts:
        report = "；".join(parts)
    elif failures:
        report = "成长中心各步骤均失败"
    else:
        report = "成长中心无可领取项"
    if tail:
        report += "（%s）" % "，".join(tail)
    return hard_failures == 0, report


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def main():
    accounts = get_accounts()
    if not accounts:
        sys.exit(2)
    merge_store(accounts)
    log(f"🔰 WorkBuddy 自动签到开始，共 {len(accounts)} 个账号"
        f"（旅行模块：{'开' if TRAVEL_ENABLE else '关'}，成长中心：{'开' if GROWTH_ENABLE else '关'}）")
    ok, fail = 0, 0
    for idx, acc in enumerate(accounts, 1):
        acc["_tag"] = (acc["uid"][:8] + "…") if acc["uid"] else f"账号{idx}"
        tag = acc["_tag"]
        account_ok = True
        try:
            success, msg = checkin_one(acc)
            log(("✅" if success else "❌") + f" [{tag}] 签到：{msg}")
            account_ok = account_ok and success
            if acc.get("_auth_dead"):
                log(f"⚠️ [{tag}] 登录态已失效，跳过旅行/成长中心")
            else:
                if TRAVEL_ENABLE:
                    success, msg = travel_one(acc)
                    log(("✅" if success else "❌") + f" [{tag}] 旅行：{msg}")
                    account_ok = account_ok and success
                if GROWTH_ENABLE and not acc.get("_auth_dead"):
                    success, msg = growth_one(acc)
                    log(("✅" if success else "❌") + f" [{tag}] 成长中心：{msg}")
                    account_ok = account_ok and success
        except Exception as e:
            account_ok = False
            log(f"❌ [{tag}] 异常: {e}")
        if account_ok:
            ok += 1
        else:
            fail += 1
        time.sleep(1)  # 多账号间隔，避免触发风控
    log(f"🏁 完成：成功 {ok} / 失败 {fail} / 共 {len(accounts)}")
    if fail > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
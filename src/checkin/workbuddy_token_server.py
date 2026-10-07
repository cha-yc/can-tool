# -*- coding: utf-8 -*-
"""
WorkBuddy Token 服务器端自动保活脚本
=====================================
适用场景：把登录态文件的一份**副本**放到服务器上，由本脚本定期刷新，
使服务器上的 token 长期可用（用于服务端调用 WorkBuddy 开放接口）。

⚠️ 重要约束（务必阅读）：
  1. 本脚本只能用于登录态文件的「副本」，且该副本必须与桌面端使用
     **不同的会话**。Keycloak 的 refreshToken 是一次性的（轮换机制）：
     每次刷新会作废旧 token、签发新 token。如果桌面客户端和服务器脚本
     用同一个 refreshToken 轮流刷新，双方会互相踢下线，导致桌面端被
     强制重新登录。
  2. 因此正确做法：在桌面端正常使用的同时，如需服务器保活，先在桌面端
     重新登录产生新会话后复制文件，或接受桌面端偶发重新登录的代价。
  3. 本脚本【永不】触碰本机 %LOCALAPPDATA% 下的原登录态文件，只处理
     通过 --file 指定的服务器副本。

工作流程：
  读取副本 JSON -> 解析 accessToken/refreshToken 剩余有效期 ->
  任一令牌剩余时间低于阈值 -> 调用 Keycloak 标准 token 端点刷新 ->
  原子回写副本（写前自动备份）-> 记录日志。

用法：
  # 手动执行一次（配合 cron / systemd timer 使用）
  python workbuddy_token_server.py --file /opt/workbuddy/workbuddy-desktop.info

  # 常驻循环模式：每 6 小时检查一次
  python workbuddy_token_server.py --file ... --loop 6

  # 演练模式：只检查、打印决策，不发起刷新、不写文件
  python workbuddy_token_server.py --file ... --dry-run

建议配合 cron（每天 09:05 检查一次）：
  5 9 * * * /usr/bin/python3 /opt/workbuddy/workbuddy_token_server.py \\
      --file /opt/workbuddy/workbuddy-desktop.info >> /var/log/wb_token.log 2>&1
"""

import argparse
import base64
import json
import os
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

# Keycloak 端点默认值；运行时优先从 refreshToken JWT 的 iss 字段解析
DEFAULT_ISS = "https://www.codebuddy.cn/auth/realms/coilot"
# 客户端 ID，与登录态 JWT 中的 azp 字段一致，Keycloak 刷新时必填
CLIENT_ID = "console"

# 备份文件保留数量，超出后删除最旧的
MAX_BACKUPS = 10


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def decode_jwt_payload(token: str) -> dict:
    """
    解码 JWT 的 payload 段（不校验签名，仅读取 iss/exp 等元信息）。
    JWT 为三段 base64url 文本以 '.' 连接，取第二段补齐 padding 后解码。
    """
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def remaining_seconds(ms_or_s: float, is_ms: bool) -> float:
    """计算给定过期时间点（秒或毫秒时间戳）距当前的剩余秒数，已过期返回 0。"""
    ts = ms_or_s / 1000.0 if is_ms else float(ms_or_s)
    return max(0.0, ts - time.time())


def human(seconds: float) -> str:
    """将秒数格式化为 'X天X小时X分' 可读字符串。"""
    seconds = int(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    return f"{days}天{hours}小时{seconds // 60}分"


def log(msg: str) -> None:
    """带时间戳输出日志行，适配 cron 重定向到日志文件的场景。"""
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


# ---------------------------------------------------------------------------
# 核心逻辑
# ---------------------------------------------------------------------------

def load_token_file(path: str) -> tuple[dict, dict]:
    """
    读取副本文件，返回 (完整 JSON 对象, auth 字典)。
    auth 字典应包含 accessToken / refreshToken / expiresAt / refreshExpiresAt。
    服务器端没有 WorkBuddy.exe，无法解密 $wbEncrypted=1；若检测到加密字段，
    引导用户先在 Windows 本机执行 wb_token_server.py seed 生成明文副本再上传。
    """
    with open(path, "r", encoding="utf-8") as f:
        full = json.load(f)
    auth = full.get("auth") or {}
    if isinstance(auth.get("accessToken"), dict) and auth["accessToken"].get("$wbEncrypted") == 1:
        raise ValueError(
            "副本中的 accessToken 是加密格式（$wbEncrypted=1），服务器端无法解密。"
            "请在 Windows 本机执行 `python wb_token_server.py seed` 生成明文 token 存储后，"
            "将该 store 文件（而非 workbuddy-desktop.info）传到服务器，"
            "并用 --file 指向 store 文件。"
        )
    if not auth.get("refreshToken"):
        raise ValueError("副本文件中缺少 auth.refreshToken，无法保活")
    return full, auth


def token_expiry_seconds(auth: dict) -> tuple[float, float]:
    """
    计算 (accessToken 剩余秒数, refreshToken 剩余秒数)。
    优先使用文件中的毫秒时间戳字段；缺失时回退到解析 JWT 的 exp 字段（秒）。
    """
    access = auth.get("accessToken", "")
    refresh = auth.get("refreshToken", "")

    access_left = (remaining_seconds(auth["expiresAt"], is_ms=True)
                   if auth.get("expiresAt")
                   else remaining_seconds(decode_jwt_payload(access).get("exp", 0), is_ms=False))
    refresh_left = (remaining_seconds(auth["refreshExpiresAt"], is_ms=True)
                    if auth.get("refreshExpiresAt")
                    else remaining_seconds(decode_jwt_payload(refresh).get("exp", 0), is_ms=False))
    return access_left, refresh_left


def refresh_via_keycloak(refresh_token: str, iss: str) -> dict:
    """
    调用 Keycloak 标准 token 端点执行刷新令牌授权。
    成功返回含 access_token / refresh_token / expires_in 的 dict；
    失败（token 已过期或被轮换作废）抛出异常。
    """
    endpoint = urllib.parse.urljoin(iss + "/", "protocol/openid-connect/token")
    payload = urllib.parse.urlencode({
        "grant_type": "refresh_token",   # OIDC 刷新令牌模式
        "client_id": CLIENT_ID,          # 与 JWT azp 一致的客户端 ID
        "refresh_token": refresh_token,
    }).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def backup_file(path: str) -> None:
    """
    回写前备份：生成带时间戳的 .bak 文件，并只保留最近 MAX_BACKUPS 份。
    """
    stamp = time.strftime("%Y%m%d_%H%M%S")
    backup = f"{path}.bak_{stamp}"
    shutil.copy2(path, backup)
    log(f"已备份原文件：{backup}")

    # 清理超出数量的旧备份（按文件名时间戳排序）
    directory = os.path.dirname(os.path.abspath(path)) or "."
    prefix = os.path.basename(path) + ".bak_"
    backups = sorted(f for f in os.listdir(directory) if f.startswith(prefix))
    for old in backups[:-MAX_BACKUPS]:
        os.remove(os.path.join(directory, old))
        log(f"清理过期备份：{old}")


def atomic_write(path: str, data: dict) -> None:
    """
    原子回写：先写临时文件再 os.replace 覆盖，避免写一半崩溃导致 JSON 损坏。
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)  # 同目录 rename，POSIX/Windows 上均为原子操作
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def apply_refresh(path: str, full: dict, auth: dict, new_tokens: dict) -> None:
    """
    把 Keycloak 返回的新令牌合并进副本文件并原子回写。
    同时更新 expiresIn/expiresAt/lastRefreshTime 等派生字段，
    保持文件结构与桌面端格式一致，便于后续工具继续读取。
    """
    now_ms = int(time.time() * 1000)
    new_auth = dict(auth)
    new_auth["accessToken"] = new_tokens["access_token"]
    # 刷新令牌轮换：服务端返回新 refreshToken 时必须保存，旧值已作废
    if new_tokens.get("refresh_token"):
        new_auth["refreshToken"] = new_tokens["refresh_token"]
    new_auth["expiresIn"] = new_tokens.get("expires_in", new_auth.get("expiresIn"))
    if new_tokens.get("refresh_expires_in"):
        new_auth["refreshExpiresIn"] = new_tokens["refresh_expires_in"]
    new_auth["expiresAt"] = now_ms + (new_auth.get("expiresIn") or 0) * 1000
    if new_auth.get("refreshExpiresIn"):
        new_auth["refreshExpiresAt"] = now_ms + new_auth["refreshExpiresIn"] * 1000
    new_auth["lastRefreshTime"] = now_ms

    backup_file(path)
    full["auth"] = new_auth
    atomic_write(path, full)
    log(f"刷新成功并已回写：accessToken 剩余 {human(new_auth['expiresIn'])}，"
        f"refreshToken 剩余 {human(new_auth.get('refreshExpiresIn', 0))}")


def run_once(path: str, threshold_days: float, dry_run: bool) -> int:
    """
    单次检查流程，返回进程退出码：
      0 = 无需刷新或刷新成功
      2 = 刷新失败（令牌失效，需要人工介入重新获取副本）
      1 = 其他错误
    """
    full, auth = load_token_file(path)
    access_left, refresh_left = token_expiry_seconds(auth)
    log(f"检查 {path}")
    log(f"accessToken 剩余 {human(access_left)}；refreshToken 剩余 {human(refresh_left)}")

    threshold = threshold_days * 86400
    if refresh_left <= 0:
        log("refreshToken 已过期，无法自动保活！请在桌面端重新登录后，重新复制一份登录态文件到服务器。")
        return 2
    if access_left > threshold and refresh_left > threshold:
        log(f"均高于阈值（{threshold_days} 天），本次无需刷新。")
        return 0

    if dry_run:
        log("[演练模式] 满足刷新条件，但不实际执行。")
        return 0

    # 优先使用 JWT iss 作为认证域地址，比硬编码更抗域名迁移
    iss = decode_jwt_payload(auth["refreshToken"]).get("iss", DEFAULT_ISS)
    try:
        new_tokens = refresh_via_keycloak(auth["refreshToken"], iss)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:300]
        log(f"刷新失败：HTTP {e.code}，响应：{body}")
        log("常见原因：refreshToken 已被其他端刷新轮换作废、已过期、接口变更。")
        return 2
    except Exception as e:
        log(f"刷新失败：{e}")
        return 1

    apply_refresh(path, full, auth, new_tokens)
    return 0


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def main() -> None:
    # 双击运行（无任何参数）时不走 argparse 报错流程，而是显示部署引导并暂停，
    # 避免窗口一闪而过、用户看不到提示。
    if len(sys.argv) == 1:
        print(__doc__)
        print("=" * 60)
        print("当前是双击运行，未指定任何参数，脚本不会执行任何操作。")
        print("部署步骤：")
        print("  1. 把本脚本放到服务器上（如 /opt/workbuddy/）")
        print("  2. 把登录态文件的【副本】复制到脚本同目录或任意路径")
        print("     （本机原文件在 %LOCALAPPDATA%\\CodeBuddyExtension\\Data\\Public\\auth\\workbuddy-desktop.info）")
        print("  3. 运行：python3 workbuddy_token_server.py --file <副本路径>")
        print("  4. 首次建议先加 --dry-run 演练确认，再接入 cron 定时")
        input("\n按回车键退出...")
        sys.exit(0)

    parser = argparse.ArgumentParser(description="WorkBuddy Token 服务器端自动保活")
    parser.add_argument("--file", required=True,
                        help="登录态副本文件路径（服务器本地文件，勿指向桌面端原文件）")
    parser.add_argument("--threshold-days", type=float, default=30.0,
                        help="剩余有效期低于该天数（默认 30）时触发刷新")
    parser.add_argument("--loop", type=float, metavar="HOURS",
                        help="常驻模式：每隔 HOURS 小时检查一次；不指定则只执行一次（配合 cron）")
    parser.add_argument("--dry-run", action="store_true",
                        help="演练模式：只检查并打印决策，不刷新、不写文件")
    args = parser.parse_args()

    if args.loop:
        # 常驻循环模式：异常不退出，下一轮重试
        interval = args.loop * 3600
        log(f"进入常驻模式，每 {args.loop} 小时检查一次。")
        while True:
            try:
                run_once(args.file, args.threshold_days, args.dry_run)
            except Exception as e:
                log(f"本轮检查异常：{e}")
            time.sleep(interval)
    else:
        sys.exit(run_once(args.file, args.threshold_days, args.dry_run))


if __name__ == "__main__":
    main()

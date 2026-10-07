# -*- coding: utf-8 -*-
"""
WorkBuddy Token 服务器自动续期脚本
====================================
适用场景：服务器上没有 WorkBuddy 桌面客户端，但需要持续使用有效的 accessToken
（例如调用 codebuddy.cn 相关接口）。

工作原理：
  1. 首次使用：在 Windows 本机执行 `seed` 子命令，从桌面端登录态文件中
     提取 accessToken / refreshToken，生成 token 存储文件（wb_token_store.json）。
  2. 服务器上通过定时任务（cron / Windows 计划任务）定期执行 `check` 子命令：
     脚本解码 JWT 读取 exp（过期时间），若剩余有效期低于阈值（默认 7 天），
     则调用 Keycloak 标准 refresh_token 接口换取新令牌并更新存储文件。
  3. 业务脚本通过 `token` 子命令获取当前有效的 accessToken：
     例如  TOKEN=$(python wb_token_server.py token)

子命令：
  seed    [在 Windows 本机执行一次] 从桌面端登录态文件初始化服务器存储
  check   [定时任务调用] 检查有效期，必要时自动刷新
  token   [业务脚本调用] 打印当前有效的 accessToken

常用参数：
  --store FILE      token 存储文件路径（默认：脚本同目录 wb_token_store.json）
  --min-days N      剩余有效期低于 N 天时触发刷新（默认 7）
  --check-only      check 模式下只检查不刷新（用于验证）

安全提示：
  - 存储文件内含长期有效的 refreshToken，请设置好文件权限（Linux 建议 chmod 600），
    不要提交到代码仓库。
  - 刷新会使旧 accessToken 失效；本脚本与桌面客户端共享同一登录会话，
    若桌面客户端也在运行并刷新令牌，可能出现令牌互相失效的情况（详见文末说明）。
"""

import argparse
import base64
import json
import os
import plistlib
import re
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from contextlib import closing

# Keycloak 认证域地址与客户端 ID（来自桌面端 JWT 的 iss / azp 字段）
DEFAULT_ISS = "https://www.codebuddy.cn/auth/realms/coilot"
CLIENT_ID = "console"


# ---------------------------------------------------------------------------
# 加密凭据解密（seed 模式使用；与 get_workbuddy_token.py 保持一致）
# ---------------------------------------------------------------------------
AUTH_HELPER_TIMEOUT = 10.0
AUTH_INPUT_LIMIT = 65536
AUTH_OUTPUT_LIMIT = 65536
TOKEN_LIMIT = 32768
AUTH_REASONS = {
    "INVALID_FORMAT": "登录凭据格式无效",
    "UNSUPPORTED_ENVELOPE": "尚不支持此加密凭据格式",
    "RUNTIME_NOT_FOUND": "未找到 WorkBuddy 客户端，请用 WORKBUDDY_EXE 指定",
    "INVALID_RUNTIME_PATH": "WORKBUDDY_EXE 不是可用的可执行文件",
    "RUNTIME_UNAVAILABLE": "客户端运行时不支持所需的原生存储接口",
    "KEY_MISMATCH": "凭据与所选客户端的密钥不匹配",
    "DECRYPT_FAILED": "加密凭据认证失败",
    "HELPER_TIMEOUT": "凭据处理超时",
    "HELPER_PROTOCOL": "客户端凭据助手返回无效结果",
}

AUTH_HELPER_JS = r"""
'use strict';
const crypto = require('crypto');
const inputLimit = 65536;
const failure = reason => { throw {reason}; };
const object = x => x !== null && typeof x === 'object' && !Array.isArray(x);
function base64(value, length) {
  if (typeof value !== 'string' || value.length > inputLimit) failure('INVALID_FORMAT');
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value || (length !== undefined && bytes.length !== length))
    failure('INVALID_FORMAT');
  return bytes;
}
function utf8(bytes) {
  const text = bytes.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(bytes)) failure('INVALID_FORMAT');
  return text;
}
function decode(value) {
  if (!object(value) || Object.keys(value).sort().join(',') !== '$wbEncrypted,envelope' || value.$wbEncrypted !== 1)
    failure('UNSUPPORTED_ENVELOPE');
  let envelope;
  try { envelope = JSON.parse(utf8(base64(value.envelope))); }
  catch (e) { failure(e.reason || 'INVALID_FORMAT'); }
  if (!object(envelope) || !Number.isInteger(envelope.suite)) failure('INVALID_FORMAT');
  if (envelope.suite !== 1) failure('UNSUPPORTED_ENVELOPE');
  if (Object.keys(envelope).sort().join(',') !== 'authTag,ciphertext,keyId,nonce,suite' ||
      typeof envelope.keyId !== 'string' || !/^[0-9a-f]{16}$/.test(envelope.keyId)) failure('INVALID_FORMAT');
  return {keyId: envelope.keyId, nonce: base64(envelope.nonce, 12),
    tag: base64(envelope.authTag, 16), ciphertext: base64(envelope.ciphertext)};
}
function nativeStorage() {
  try {
    const storage = process._linkedBinding('electron_browser_workbuddy_storage');
    if (typeof storage.loggerGet !== 'function') failure('RUNTIME_UNAVAILABLE');
    return storage;
  } catch (_) { failure('RUNTIME_UNAVAILABLE'); }
}
function decrypt(envelope) {
  let payload;
  try { payload = JSON.parse(nativeStorage().loggerGet()); }
  catch (_) { failure('RUNTIME_UNAVAILABLE'); }
  let key, plaintext;
  try {
    if (!object(payload) || payload.version !== 1) failure('RUNTIME_UNAVAILABLE');
    let secret;
    try { secret = base64(payload.atRestSecretKey, 32); }
    catch (_) { failure('RUNTIME_UNAVAILABLE'); }
    const empty = secret.every(b => b === 0);
    secret.fill(0);
    if (empty) failure('RUNTIME_UNAVAILABLE');
    key = crypto.createHash('sha256').update(payload.atRestSecretKey, 'utf8').digest();
    payload = null;
    if (crypto.createHash('sha256').update(key).digest('hex').slice(0, 16) !== envelope.keyId)
      failure('KEY_MISMATCH');
    const lp = s => {
      const bytes = Buffer.from(s, 'utf8');
      const length = Buffer.alloc(4); length.writeUInt32BE(bytes.length);
      return Buffer.concat([length, bytes]);
    };
    const aad = Buffer.concat([Buffer.from('WB-AAD\0', 'ascii'), Buffer.from([1]),
      lp('WBEV1'), lp('sym-v1'), Buffer.from([0, 0, 0, 1]), lp(envelope.keyId), Buffer.from([2, 0, 0])]);
    try {
      const cipher = crypto.createDecipheriv('aes-256-gcm', key, envelope.nonce, {authTagLength: 16});
      cipher.setAAD(aad); cipher.setAuthTag(envelope.tag);
      plaintext = Buffer.concat([cipher.update(envelope.ciphertext), cipher.final()]);
    } catch (_) { failure('DECRYPT_FAILED'); }
    const token = utf8(plaintext);
    if (!token.length || token.length > 32768 || !/^[A-Za-z0-9._~+\/-]+=*$/.test(token))
      failure('INVALID_FORMAT');
    return token;
  } finally {
    if (key) key.fill(0);
    if (plaintext) plaintext.fill(0);
  }
}
let chunks = [], size = 0;
function reply(value) {
  process.stdout.write(JSON.stringify({version: 1, ...value}), () => process.exit(value.ok ? 0 : 1));
}
process.stdin.on('data', chunk => {
  size += chunk.length;
  if (size > inputLimit) reply({ok: false, reason: 'INVALID_FORMAT'});
  else chunks.push(chunk);
});
process.stdin.on('error', () => reply({ok: false, reason: 'HELPER_PROTOCOL'}));
process.stdin.on('end', () => {
  try {
    const request = JSON.parse(utf8(Buffer.concat(chunks))); chunks = [];
    if (!object(request) || request.version !== 1) failure('HELPER_PROTOCOL');
    if (request.operation === 'probe') {
      nativeStorage();
      if (!crypto.getCiphers().includes('aes-256-gcm')) failure('RUNTIME_UNAVAILABLE');
      reply({ok: true, electron: process.versions.electron || 'unknown'});
    } else if (request.operation === 'decrypt') {
      reply({ok: true, accessToken: decrypt(decode(request.value))});
    } else failure('HELPER_PROTOCOL');
  } catch (e) {
    const reasons = ['INVALID_FORMAT','UNSUPPORTED_ENVELOPE','RUNTIME_UNAVAILABLE',
      'KEY_MISMATCH','DECRYPT_FAILED','HELPER_PROTOCOL'];
    reply({ok: false, reason: reasons.includes(e.reason) ? e.reason : 'HELPER_PROTOCOL'});
  }
});
"""


class AuthError(Exception):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(AUTH_REASONS.get(reason, "本地未找到有效登录会话"))


def _valid_token(token):
    return (isinstance(token, str) and 0 < len(token) <= TOKEN_LIMIT
            and re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", token) is not None)


def _is_encrypted_field(value) -> bool:
    return isinstance(value, dict) and value.get("$wbEncrypted") == 1


def _mac_runtime(bundle):
    try:
        with open(os.path.join(bundle, "Contents", "Info.plist"), "rb") as f:
            name = plistlib.load(f).get("CFBundleExecutable")
        if not isinstance(name, str) or not name or "/" in name or "\\" in name:
            return None
        return os.path.join(bundle, "Contents", "MacOS", name)
    except (OSError, ValueError, TypeError, AttributeError):
        return None


def _registry_text(registry, key, field):
    try:
        value, kind = registry.QueryValueEx(key, field)
        if not isinstance(value, str) or kind not in (registry.REG_SZ, registry.REG_EXPAND_SZ):
            return None
        if kind == registry.REG_EXPAND_SZ:
            value = registry.ExpandEnvironmentStrings(value)
        return value
    except OSError:
        return None


def _registry_runtime_path(value, icon=False):
    import ntpath
    if not isinstance(value, str) or re.search(r"[\x00-\x1f\x7f]", value):
        return None
    value = value.strip()
    if value.startswith('"'):
        suffix = r"(?:\s*,\s*-?\d+)?" if icon else ""
        m = re.fullmatch(r'"([^"]+)"' + suffix, value)
        if not m:
            return None
        value = m[1]
    elif '"' in value:
        return None
    elif icon:
        value = re.sub(r",\s*-?\d+$", "", value).rstrip()
    if not ntpath.splitdrive(value)[0] or not ntpath.isabs(value):
        return None
    if not icon:
        value = ntpath.join(value, "WorkBuddy.exe")
    value = ntpath.normpath(value)
    if ntpath.basename(value).casefold() != "workbuddy.exe":
        return None
    return value


def _windows_registry_runtimes():
    if sys.platform != "win32":
        return
    try:
        import winreg
    except ImportError:
        return
    subkey = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    seen = set()
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | view) as root:
                    count = winreg.QueryInfoKey(root)[0]
                    for index in range(count):
                        try:
                            with winreg.OpenKey(root, winreg.EnumKey(root, index),
                                                0, winreg.KEY_READ | view) as entry:
                                name = _registry_text(winreg, entry, "DisplayName")
                                if not name or not re.fullmatch(
                                        r"WorkBuddy(?:\s+\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?)?",
                                        name.strip(), re.IGNORECASE):
                                    continue
                                for field in ("InstallLocation", "DisplayIcon"):
                                    path = _registry_runtime_path(
                                        _registry_text(winreg, entry, field), icon=field == "DisplayIcon")
                                    if path and os.path.normcase(path) not in seen:
                                        seen.add(os.path.normcase(path))
                                        if os.path.isfile(path):
                                            yield path
                        except OSError:
                            continue
            except OSError:
                continue


def find_workbuddy_runtime():
    override = os.environ.get("WORKBUDDY_EXE")
    if override:
        path = os.path.abspath(os.path.expanduser(override))
        if not os.path.isfile(path) or (os.name != "nt" and not os.access(path, os.X_OK)):
            raise AuthError("INVALID_RUNTIME_PATH")
        return path
    home = os.path.expanduser("~")
    candidates = []
    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")
        candidates.append(os.path.join(local, "Programs", "WorkBuddy", "WorkBuddy.exe"))
        for name in ("ProgramFiles", "ProgramFiles(x86)"):
            if os.environ.get(name):
                candidates.append(os.path.join(os.environ[name], "WorkBuddy", "WorkBuddy.exe"))
    elif sys.platform == "darwin":
        candidates = [_mac_runtime(os.path.join(root, "WorkBuddy.app"))
                      for root in ("/Applications", os.path.join(home, "Applications"))]
    for path in candidates:
        if path and os.path.isfile(path) and (os.name == "nt" or os.access(path, os.X_OK)):
            return os.path.abspath(path)
    if sys.platform == "win32":
        with closing(_windows_registry_runtimes()) as entries:
            registered = next(entries, None)
        if registered:
            return registered
    raise AuthError("RUNTIME_NOT_FOUND")


def _run_auth_helper(exe, request):
    data = json.dumps(dict(request, version=1), ensure_ascii=True).encode("ascii")
    if len(data) > AUTH_INPUT_LIMIT:
        raise AuthError("INVALID_FORMAT")
    env = {k: v for k, v in os.environ.items()
           if not k.upper().startswith(("NODE_", "ELECTRON_", "WORKBUDDY_"))}
    env["ELECTRON_RUN_AS_NODE"] = "1"
    try:
        process = subprocess.Popen([exe, "-e", AUTH_HELPER_JS],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=env, shell=False,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except OSError:
        raise AuthError("RUNTIME_UNAVAILABLE") from None
    output = {}
    failed = threading.Event()

    def read_pipe(name, pipe, limit):
        try:
            captured = pipe.read(limit + 1)
            if len(captured) > limit:
                failed.set(); process.kill()
            else:
                output[name] = captured
        except OSError:
            failed.set()

    def write_pipe():
        try:
            process.stdin.write(data); process.stdin.close()
        except OSError:
            failed.set()

    workers = [threading.Thread(target=read_pipe, args=("stdout", process.stdout, AUTH_OUTPUT_LIMIT), daemon=True),
               threading.Thread(target=read_pipe, args=("stderr", process.stderr, 8192), daemon=True),
               threading.Thread(target=write_pipe, daemon=True)]
    deadline = time.monotonic() + AUTH_HELPER_TIMEOUT
    try:
        for w in workers: w.start()
        try:
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise AuthError("HELPER_TIMEOUT") from None
        for w in workers: w.join(max(0, deadline - time.monotonic()))
        if any(w.is_alive() for w in workers): raise AuthError("HELPER_TIMEOUT")
        if failed.is_set(): raise AuthError("HELPER_PROTOCOL")
        try:
            reply = json.loads(output.get("stdout", b"").decode("utf-8"))
        except (ValueError, UnicodeError):
            raise AuthError("HELPER_PROTOCOL") from None
        if not isinstance(reply, dict) or reply.get("version") != 1:
            raise AuthError("HELPER_PROTOCOL")
        if reply.get("ok") is False and process.returncode == 1:
            reason = reply.get("reason")
            raise AuthError(reason if isinstance(reason, str) and reason in AUTH_REASONS else "HELPER_PROTOCOL")
        if reply.get("ok") is not True or process.returncode != 0:
            raise AuthError("HELPER_PROTOCOL")
        if request["operation"] == "decrypt":
            if set(reply) != {"version", "ok", "accessToken"} or not _valid_token(reply.get("accessToken")):
                raise AuthError("HELPER_PROTOCOL")
        return reply
    finally:
        if process.poll() is None: process.kill()
        process.wait()
        for w in workers:
            if w.ident is not None: w.join(1)
        if not any(w.is_alive() for w in workers):
            for pipe in (process.stdin, process.stdout, process.stderr):
                try: pipe.close()
                except OSError: pass


def decrypt_auth_fields(auth: dict) -> dict:
    """对 auth.accessToken / auth.refreshToken 分别尝试解密，返回明文副本。"""
    if not isinstance(auth, dict):
        return auth
    if not (_is_encrypted_field(auth.get("accessToken")) or
            _is_encrypted_field(auth.get("refreshToken"))):
        return auth
    exe = find_workbuddy_runtime()
    out = dict(auth)
    out["accessToken"] = _run_auth_helper(exe, {"operation": "decrypt", "value": auth["accessToken"]})["accessToken"]
    if _is_encrypted_field(auth.get("refreshToken")):
        out["refreshToken"] = _run_auth_helper(exe, {"operation": "decrypt", "value": auth["refreshToken"]})["accessToken"]
    return out

# Windows 桌面端登录态文件的候选路径（seed 模式使用）
DESKTOP_AUTH_CANDIDATES = []
_localappdata = os.environ.get("LOCALAPPDATA", "")
_appdata = os.environ.get("APPDATA", "")
if _localappdata:
    DESKTOP_AUTH_CANDIDATES.append(
        os.path.join(_localappdata, "CodeBuddyExtension", "Data", "Public", "auth", "workbuddy-desktop.info")
    )
if _appdata:
    DESKTOP_AUTH_CANDIDATES.append(
        os.path.join(_appdata, "CodeBuddyExtension", "Data", "Public", "auth", "workbuddy-desktop.info")
    )

# 脚本所在目录（存储文件默认放在这里，便于定时任务用绝对路径引用）
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_STORE = os.path.join(SCRIPT_DIR, "wb_token_store.json")


# ---------------------------------------------------------------------------
# JWT 工具函数
# ---------------------------------------------------------------------------
def decode_jwt_payload(token: str) -> dict:
    """
    解码 JWT 的 payload 段（不校验签名，仅读取 exp/iss 等元信息）。
    JWT 由三段 base64url 文本以 '.' 连接，取第二段解码为 JSON。
    """
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)  # 补齐 base64url padding
    try:
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def token_expiry_ms(token: str) -> int:
    """
    从 JWT 的 exp 字段（Unix 秒）计算过期时间的毫秒时间戳。
    exp 缺失时返回 0，视为已过期，促使脚本走刷新流程。
    """
    exp = decode_jwt_payload(token).get("exp")
    return int(exp * 1000) if exp else 0


def format_remaining(ms: int) -> str:
    """将过期时间戳（毫秒）格式化为 'X天X小时X分' 的可读字符串。"""
    seconds = max(0, (ms - int(time.time() * 1000)) // 1000)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes = seconds // 60
    return f"{days}天{hours}小时{minutes}分"


# ---------------------------------------------------------------------------
# 存储读写
# ---------------------------------------------------------------------------
def load_store(path: str) -> dict:
    """读取 token 存储文件；文件不存在或结构缺失时给出明确指引并退出。"""
    if not os.path.isfile(path):
        print(f"[错误] token 存储文件不存在：{path}\n"
              "请先在 Windows 本机执行一次 seed 子命令生成该文件：\n"
              "  python wb_token_server.py seed", file=sys.stderr)
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        store = json.load(f)
    if not store.get("refreshToken") or not store.get("accessToken"):
        print(f"[错误] 存储文件缺少 accessToken/refreshToken 字段：{path}", file=sys.stderr)
        sys.exit(1)
    return store


def save_store(path: str, store: dict) -> None:
    """将 token 存储写入文件；Linux 下自动收紧权限到 0600（仅属主可读写）。"""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(store, f, ensure_ascii=False, indent=2)
    if os.name == "posix":
        os.chmod(path, 0o600)


# ---------------------------------------------------------------------------
# Keycloak 刷新
# ---------------------------------------------------------------------------
def refresh_tokens(refresh_token: str, iss: str) -> dict:
    """
    调用 Keycloak 标准 token 端点，用 refreshToken 换取新令牌。
    端点：{iss}/protocol/openid-connect/token（OIDC refresh_token 授权模式）。
    成功返回含 access_token / refresh_token / expires_in 的 dict，失败抛异常。
    """
    endpoint = urllib.parse.urljoin(iss + "/", "protocol/openid-connect/token")
    payload = urllib.parse.urlencode(
        {
            "grant_type": "refresh_token",   # OIDC 刷新令牌授权模式
            "client_id": CLIENT_ID,          # 客户端 ID，与桌面端 JWT 的 azp 一致
            "refresh_token": refresh_token,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def ensure_fresh(store_path: str, min_days: int, check_only: bool = False, log=None) -> dict:
    """
    核心逻辑：检查存储中的 accessToken 剩余有效期，低于阈值则自动刷新。
    返回确保可用的 store dict。check_only=True 时只报告不刷新（验证用）。
    log 参数指定状态输出流：默认 stdout；token 子命令传入 stderr，
    保证令牌捕获场景（TOKEN=$(...)）下 stdout 只有令牌本身。
    """
    out = log if log is not None else sys.stdout
    def log_print(msg: str) -> None:
        print(msg, file=out)

    store = load_store(store_path)
    exp_ms = store.get("expiresAt") or token_expiry_ms(store["accessToken"])
    remaining_days = (exp_ms - time.time() * 1000) / 86400000

    log_print(f"[状态] accessToken 剩余有效期：{format_remaining(exp_ms)}（约 {remaining_days:.1f} 天）")

    if remaining_days >= min_days:
        log_print(f"[状态] 有效期充足（阈值 {min_days} 天），无需刷新。")
        return store

    if check_only:
        log_print("[状态] --check-only 已启用：仅报告，不执行刷新。")
        return store

    log_print(f"[刷新] 剩余有效期低于 {min_days} 天，开始刷新...")
    # iss 优先取存储文件中记录的值，保证与令牌签发方一致
    iss = store.get("iss", DEFAULT_ISS)
    try:
        new_tokens = refresh_tokens(store["refreshToken"], iss)
    except Exception as e:
        log_print(f"[错误] 刷新失败：{e}\n"
                  "可能原因：1) refreshToken 已过期（需在本机桌面端重新登录后重新 seed）；\n"
                  "        2) 认证接口变更；3) 服务器无法访问认证域。")
        sys.exit(2)

    # 用服务端返回的新令牌更新存储；expiresAt 直接取新 JWT 的 exp，避免本地时钟误差
    store["accessToken"] = new_tokens["access_token"]
    if new_tokens.get("refresh_token"):
        # 服务端返回了新 refreshToken 时更新（离线令牌可能复用旧值）
        store["refreshToken"] = new_tokens["refresh_token"]
    store["expiresIn"] = new_tokens.get("expires_in")
    store["expiresAt"] = token_expiry_ms(store["accessToken"])
    store["iss"] = iss
    store["lastRefresh"] = int(time.time() * 1000)
    save_store(store_path, store)
    log_print(f"[完成] 刷新成功，新有效期至：{format_remaining(store['expiresAt'])}")
    return store


# ---------------------------------------------------------------------------
# 子命令实现
# ---------------------------------------------------------------------------
def cmd_seed(args) -> None:
    """
    [Windows 本机执行一次] 从桌面端登录态文件提取令牌，生成服务器存储文件。
    只读取桌面端文件，不刷新、不回写。
    """
    # 按优先级查找桌面端登录态文件
    auth_path = next((p for p in DESKTOP_AUTH_CANDIDATES if os.path.isfile(p)), None)
    if not auth_path:
        print("[错误] 未找到桌面端登录态文件，请确认 WorkBuddy 已登录。", file=sys.stderr)
        sys.exit(1)

    with open(auth_path, "r", encoding="utf-8") as f:
        auth = json.load(f).get("auth", {})
    if not auth.get("accessToken") or not auth.get("refreshToken"):
        print("[错误] 登录态文件中缺少令牌字段，文件结构可能已变化。", file=sys.stderr)
        sys.exit(1)

    if _is_encrypted_field(auth.get("accessToken")) or _is_encrypted_field(auth.get("refreshToken")):
        print("[信息] 检测到加密凭据，使用 WorkBuddy 运行时解密...")
        try:
            auth = decrypt_auth_fields(auth)
        except AuthError as e:
            print(f"[错误] 解密失败：{e}", file=sys.stderr)
            sys.exit(1)
        print("[信息] 解密完成，将以明文形式落盘到 store")

    store = {
        "accessToken": auth["accessToken"],
        "refreshToken": auth["refreshToken"],
        # expiresAt 直接取桌面端记录值；缺失时回退到解析 JWT exp
        "expiresAt": auth.get("expiresAt") or token_expiry_ms(auth["accessToken"]),
        # 记录认证域地址，刷新时优先使用；来源为桌面端 JWT 的 iss 字段
        "iss": DEFAULT_ISS,
        "seededAt": int(time.time() * 1000),
    }
    save_store(args.store, store)
    print(f"[完成] 已从桌面端导入令牌，存储文件：{args.store}")
    print(f"[状态] accessToken 剩余有效期：{format_remaining(store['expiresAt'])}")
    print("[提示] 请将该脚本与存储文件一并部署到服务器，并配置定时任务执行 check 子命令。")


def cmd_check(args) -> None:
    """[定时任务调用] 检查并按需刷新，刷新后把最新 accessToken 落盘到 --out 文件（可选）。"""
    store = ensure_fresh(args.store, args.min_days, check_only=args.check_only)
    if args.out:
        # 可选：把最新 token 写到指定文件，供服务器上其他程序直接读取
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(store["accessToken"])
        if os.name == "posix":
            os.chmod(args.out, 0o600)
        print(f"[完成] 最新 accessToken 已写入：{args.out}")


def cmd_token(args) -> None:
    """[业务脚本调用] 确保令牌可用后，仅打印 accessToken（可被 $() 捕获）。"""
    # 状态日志输出到 stderr，stdout 只保留令牌本身，确保 TOKEN=$(...) 捕获纯净
    store = ensure_fresh(args.store, args.min_days, log=sys.stderr)
    print(store["accessToken"])


def main() -> None:
    parser = argparse.ArgumentParser(description="WorkBuddy Token 服务器自动续期")
    parser.add_argument("--store", default=DEFAULT_STORE,
                        help=f"token 存储文件路径（默认：{DEFAULT_STORE}）")
    parser.add_argument("--min-days", type=int, default=7,
                        help="剩余有效期低于该天数时触发刷新（默认 7 天）")
    sub = parser.add_subparsers(dest="command", required=True)

    p_seed = sub.add_parser("seed", help="[本机执行一次] 从桌面端登录态文件初始化存储")
    p_check = sub.add_parser("check", help="[定时任务] 检查有效期并按需刷新")
    p_check.add_argument("--check-only", action="store_true", help="只检查不刷新")
    p_check.add_argument("--out", metavar="FILE", help="刷新后将最新 accessToken 写入该文件")
    p_token = sub.add_parser("token", help="[业务脚本] 打印当前有效的 accessToken")

    args = parser.parse_args()
    if args.command == "seed":
        cmd_seed(args)
    elif args.command == "check":
        cmd_check(args)
    elif args.command == "token":
        cmd_token(args)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        import traceback
        print("\n[错误] 未处理异常，堆栈如下：", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)

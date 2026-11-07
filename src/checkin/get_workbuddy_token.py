# -*- coding: utf-8 -*-
"""
WorkBuddy 桌面端 Token 自动获取脚本
====================================
功能：
  1. 自动定位登录态文件（LOCALAPPDATA 优先，APPDATA 回退）
  2. 解析 JSON，提取 accessToken / refreshToken 及有效期
  3. 默认输出 accessToken 与剩余有效期
  4. 支持 --copy 将 accessToken 复制到剪贴板（Windows）
  5. 支持 --out <file> 将 token 导出到文件
  6. 支持 --refresh 实验性刷新：走 Keycloak 标准协议用 refreshToken 换新 token，
     成功后自动备份原文件并回写（未公开接口，可能随官方版本失效）
  7. 支持 --env 输出环境变量格式：stdout 仅一行 accessToken#refreshToken，
     可直接粘贴为 workbuddy_checkin.py 的 WB_ACCESS_TOKENS（多账号用逗号拼接）；
     其余提示信息全部走 stderr，保证 $(...) 捕获纯净

用法示例：
  python get_workbuddy_token.py                # 打印 accessToken 和剩余有效期
  python get_workbuddy_token.py --copy         # 打印并复制到剪贴板
  python get_workbuddy_token.py --out token.txt  # 导出到文件
  python get_workbuddy_token.py --refresh      # 尝试刷新并回写登录态文件
  python get_workbuddy_token.py --env          # 输出 accessToken#refreshToken
  python get_workbuddy_token.py --env --refresh  # 先刷新再输出环境变量格式
"""

import argparse
import base64
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from contextlib import closing

# ---------------------------------------------------------------------------
# Keycloak 端点：从 refreshToken 的 JWT iss 字段解析而来，硬编码作为默认值，
# 运行时若 JWT 中 iss 存在则优先使用 JWT 中的值
# ---------------------------------------------------------------------------
DEFAULT_ISS = "https://www.codebuddy.cn/auth/realms/coilot"
# azp (authorized party) 字段中的客户端 ID，Keycloak 刷新时必填
CLIENT_ID = "console"


# ---------------------------------------------------------------------------
# 加密凭据解密：把 WorkBuddy.exe 自身当 Node 运行时，用其原生 binding 拿密钥
# ---------------------------------------------------------------------------
AUTH_HELPER_TIMEOUT = 10.0
AUTH_INPUT_LIMIT = 65536
AUTH_OUTPUT_LIMIT = 65536
TOKEN_LIMIT = 32768
AUTH_REASONS = {
    "INVALID_FORMAT": "登录凭据格式无效，请检查凭据来源和客户端版本",
    "UNSUPPORTED_ENVELOPE": "尚不支持此加密凭据格式，请更新脚本",
    "RUNTIME_NOT_FOUND": "未找到 WorkBuddy 客户端，请用 WORKBUDDY_EXE 指定其可执行文件",
    "INVALID_RUNTIME_PATH": "WORKBUDDY_EXE 不是可用的可执行文件，请核对路径",
    "RUNTIME_UNAVAILABLE": "客户端运行时不支持所需的原生存储接口",
    "KEY_MISMATCH": "凭据与所选客户端的密钥不匹配，请用 WORKBUDDY_EXE 指定对应客户端",
    "DECRYPT_FAILED": "加密凭据认证失败，请检查客户端版本及凭据是否完整",
    "HELPER_TIMEOUT": "凭据处理超时，已停止子进程，请稍后重试",
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
  let key;
  let plaintext;
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


def _token_format(value):
    if isinstance(value, str):
        if not _valid_token(value):
            raise AuthError("INVALID_FORMAT")
        return "plaintext"
    if not isinstance(value, dict):
        raise AuthError("INVALID_FORMAT")
    if (set(value) != {"$wbEncrypted", "envelope"} or
            type(value.get("$wbEncrypted")) is not int or value["$wbEncrypted"] != 1):
        raise AuthError("UNSUPPORTED_ENVELOPE")
    try:
        encoded = value["envelope"]
        if not isinstance(encoded, str) or not 0 < len(encoded) <= AUTH_INPUT_LIMIT - 1024:
            raise ValueError()
        raw = base64.b64decode(encoded, validate=True)
        if base64.b64encode(raw).decode("ascii") != encoded:
            raise ValueError()
        envelope = json.loads(raw.decode("utf-8"))
        if not isinstance(envelope, dict) or type(envelope.get("suite")) is not int:
            raise ValueError()
        if envelope["suite"] != 1:
            raise AuthError("UNSUPPORTED_ENVELOPE")
        if set(envelope) != {"suite", "keyId", "nonce", "authTag", "ciphertext"}:
            raise ValueError()
        if not isinstance(envelope["keyId"], str) or not re.fullmatch(r"[0-9a-f]{16}", envelope["keyId"]):
            raise ValueError()
        for field, length in (("nonce", 12), ("authTag", 16), ("ciphertext", None)):
            data = envelope[field]
            if not isinstance(data, str):
                raise ValueError()
            decoded = base64.b64decode(data, validate=True)
            if base64.b64encode(decoded).decode("ascii") != data or (length is not None and len(decoded) != length):
                raise ValueError()
        return "sym-v1"
    except (ValueError, TypeError, KeyError):
        raise AuthError("INVALID_FORMAT") from None


def _mac_runtime(bundle):
    try:
        with open(os.path.join(bundle, "Contents", "Info.plist"), "rb") as f:
            name = plistlib.load(f).get("CFBundleExecutable")
        if not isinstance(name, str) or not name or name in (".", "..") or "/" in name or "\\" in name:
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
        match = re.fullmatch(r'"([^"]+)"' + suffix, value)
        if not match:
            return None
        value = match[1]
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
        for w in workers:
            w.start()
        try:
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise AuthError("HELPER_TIMEOUT") from None
        for w in workers:
            w.join(max(0, deadline - time.monotonic()))
        if any(w.is_alive() for w in workers):
            raise AuthError("HELPER_TIMEOUT")
        if failed.is_set():
            raise AuthError("HELPER_PROTOCOL")
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
        if process.poll() is None:
            process.kill()
        process.wait()
        for w in workers:
            if w.ident is not None:
                w.join(1)
        if not any(w.is_alive() for w in workers):
            for pipe in (process.stdin, process.stdout, process.stderr):
                try: pipe.close()
                except OSError: pass


def _decrypt_field(value, runtime_exe=None):
    """把 $wbEncrypted=1 的字段解成明文字符串；已是明文原样返回。"""
    if not _is_encrypted_field(value):
        return value
    if runtime_exe is None:
        runtime_exe = find_workbuddy_runtime()
    return _run_auth_helper(runtime_exe, {"operation": "decrypt", "value": value})["accessToken"]


def decrypt_auth_fields(auth: dict) -> dict:
    """对 auth.accessToken / auth.refreshToken 分别尝试解密，返回明文副本。"""
    if not isinstance(auth, dict):
        return auth
    if not (_is_encrypted_field(auth.get("accessToken")) or
            _is_encrypted_field(auth.get("refreshToken"))):
        return auth
    exe = find_workbuddy_runtime()
    out = dict(auth)
    out["accessToken"] = _decrypt_field(auth.get("accessToken"), exe)
    if _is_encrypted_field(auth.get("refreshToken")):
        try:
            out["refreshToken"] = _decrypt_field(auth["refreshToken"], exe)
        except AuthError as e:
            print(f"[警告] refreshToken 解密失败: {e}", file=sys.stderr)
    return out


def find_auth_file() -> str:
    """按官方文档的优先级查找登录态文件，找到则返回绝对路径，找不到则报错退出。"""
    localappdata = os.environ.get("LOCALAPPDATA", "")
    appdata = os.environ.get("APPDATA", "")

    candidates = []
    if localappdata:
        # 新版登录态文件的首选路径
        candidates.append(
            os.path.join(localappdata, "CodeBuddyExtension", "Data", "Public", "auth", "workbuddy-desktop.info")
        )
    if appdata:
        # 回退路径：旧版本或目录被迁移的情况
        candidates.append(
            os.path.join(appdata, "CodeBuddyExtension", "Data", "Public", "auth", "workbuddy-desktop.info")
        )

    for path in candidates:
        if os.path.isfile(path):
            return path

    # 全部未命中，给出明确的排查提示
    print("[错误] 未找到登录态文件，已尝试以下路径：", file=sys.stderr)
    for p in candidates:
        print("  -", p, file=sys.stderr)
    print("请确认 WorkBuddy 桌面端已登录并进入主界面。", file=sys.stderr)
    sys.exit(1)


def load_auth_json(path: str, info=sys.stdout) -> dict:
    """读取并解析登录态文件，返回其中的 auth 字段（含 token 信息）。
    若 accessToken/refreshToken 是 $wbEncrypted=1 加密对象，自动用 WorkBuddy 运行时解密。
    info 指定提示信息输出流（--env 模式下传 stderr，保证 stdout 只有令牌）。
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    auth = data.get("auth")
    if not auth or not auth.get("accessToken"):
        print("[错误] 文件中未找到 auth.accessToken 字段，文件结构可能已变化。", file=sys.stderr)
        sys.exit(1)
    if _is_encrypted_field(auth.get("accessToken")) or _is_encrypted_field(auth.get("refreshToken")):
        print("[信息] 检测到加密凭据，使用 WorkBuddy 运行时解密...", file=info)
        auth = decrypt_auth_fields(auth)
    return auth


def format_remaining(ms: int) -> str:
    """将以毫秒表示的剩余有效期格式化为 'X天X小时X分' 的可读字符串。"""
    seconds = max(0, (ms - int(time.time() * 1000)) // 1000)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes = seconds // 60
    return f"{days}天{hours}小时{minutes}分"


def decode_jwt_payload(token: str) -> dict:
    """
    解码 JWT 的 payload 部分（不校验签名，仅用于读取 iss/exp 等元信息）。
    JWT 由三段 base64url 编码文本用 '.' 连接，取第二段解码。
    """
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1]
    # base64url 需要 补齐 padding
    payload += "=" * (-len(payload) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def refresh_token_via_keycloak(refresh_token: str, iss: str) -> dict:
    """
    [实验性] 调用 Keycloak 标准 token 端点，用 refreshToken 换取新 token。
    端点格式：{iss}/protocol/openid-connect/token
    成功时返回包含新 accessToken/refreshToken/expiresAt 的 dict，失败时抛出异常。

    说明：这是 Keycloak OIDC 标准协议，但 WorkBuddy 官方并未公开此用法，
    client_id 取自 JWT 的 azp 字段（console）。接口变更时此功能会失效。
    """
    endpoint = urllib.parse.urljoin(iss + "/", "protocol/openid-connect/token")
    payload = urllib.parse.urlencode(
        {
            "grant_type": "refresh_token",       # OIDC 刷新令牌模式
            "client_id": CLIENT_ID,              # 客户端 ID，与 JWT 的 azp 一致
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


def write_back_auth_file(path: str, auth: dict, new_tokens: dict, info=sys.stdout) -> None:
    """
    将刷新后的 token 回写到登录态文件。
    回写前先在同级目录生成带时间戳的备份，避免写坏导致客户端登录态丢失。
    """
    # 1. 备份原文件（复制而非移动，保证原文件始终存在）
    stamp = time.strftime("%Y%m%d_%H%M%S")
    backup = f"{path}.bak_{stamp}"
    shutil.copy2(path, backup)
    print(f"[备份] 原文件已备份至：{backup}", file=info)

    # 2. 基于服务端返回的字段计算过期时间戳（毫秒）
    now_ms = int(time.time() * 1000)
    new_auth = dict(auth)  # 保留 sessionState/scope 等原字段
    new_auth["accessToken"] = new_tokens["access_token"]
    new_auth["refreshToken"] = new_tokens.get("refresh_token", auth.get("refreshToken"))
    new_auth["expiresIn"] = new_tokens.get("expires_in", new_auth.get("expiresIn"))
    new_auth["refreshExpiresIn"] = new_tokens.get("refresh_expires_in", new_auth.get("refreshExpiresIn"))
    new_auth["expiresAt"] = now_ms + new_auth["expiresIn"] * 1000
    if new_auth["refreshExpiresIn"]:
        new_auth["refreshExpiresAt"] = now_ms + new_auth["refreshExpiresIn"] * 1000
    new_auth["lastRefreshTime"] = now_ms

    # 3. 读取完整 JSON、替换 auth 字段后整体回写（保持其他字段不变）
    with open(path, "r", encoding="utf-8") as f:
        full = json.load(f)
    full["auth"] = new_auth
    with open(path, "w", encoding="utf-8") as f:
        json.dump(full, f, ensure_ascii=False, indent=2)
    print("[完成] 新 token 已回写登录态文件。", file=info)


def main() -> None:
    parser = argparse.ArgumentParser(description="自动获取 WorkBuddy 桌面端 Token")
    parser.add_argument("--copy", action="store_true", help="将 accessToken 复制到剪贴板（Windows）")
    parser.add_argument("--out", metavar="FILE", help="将 token 信息导出为 JSON 文件")
    parser.add_argument("--refresh", action="store_true",
                        help="[实验性] 用 refreshToken 换取新 token 并回写登录态文件")
    parser.add_argument("--env", action="store_true",
                        help="stdout 仅输出 accessToken#refreshToken 一行，可直接设为 WB_ACCESS_TOKENS；"
                             "提示信息走 stderr。--copy/--out 同步作用于该格式")
    args = parser.parse_args()

    # --env 模式下所有提示信息走 stderr，stdout 只保留令牌行，保证捕获纯净
    info = sys.stderr if args.env else sys.stdout

    path = find_auth_file()
    print(f"[信息] 登录态文件：{path}", file=info)
    with open(path, "r", encoding="utf-8") as f:
        _raw_auth = json.load(f).get("auth") or {}
    encrypted_mode = (_is_encrypted_field(_raw_auth.get("accessToken")) or
                      _is_encrypted_field(_raw_auth.get("refreshToken")))
    auth = load_auth_json(path, info=info)

    # ------- 实验性刷新分支 -------
    if args.refresh:
        rt = auth.get("refreshToken", "")
        jwt_payload = decode_jwt_payload(rt)
        # 优先使用 JWT 中声明的 iss（身份提供方地址），比硬编码更抗迁移
        iss = jwt_payload.get("iss", DEFAULT_ISS)
        print(f"[信息] 刷新端点所属域：{iss}", file=info)
        try:
            new_tokens = refresh_token_via_keycloak(rt, iss)
        except Exception as e:
            print(f"[错误] 刷新失败：{e}\n"
                  "可能原因：接口变更、refreshToken 已过期（需在客户端重新登录）。", file=sys.stderr)
            sys.exit(2)
        if encrypted_mode:
            print("[信息] 加密模式下仅内存刷新，不回写文件（WorkBuddy 需要加密格式）", file=info)
            auth = dict(auth,
                        accessToken=new_tokens["access_token"],
                        refreshToken=new_tokens.get("refresh_token", rt),
                        expiresAt=int(time.time() * 1000) + new_tokens.get("expires_in", 300) * 1000)
        else:
            write_back_auth_file(path, auth, new_tokens, info=info)
            auth = load_auth_json(path, info=info)  # 重新加载回写后的内容用于展示

    access = auth["accessToken"]
    refresh_tok = auth.get("refreshToken") or ""
    expires_at = auth.get("expiresAt")

    # ------- 环境变量格式输出：accessToken#refreshToken -------
    if args.env:
        # JWT 只含 A-Za-z0-9._~- 和 =，不含 #，可安全用作访问/刷新令牌分隔符
        env_line = f"{access}#{refresh_tok}" if refresh_tok else access
        print(env_line)
        if args.copy:
            ret = os.system(f'powershell -NoProfile -Command "Set-Clipboard -Value \'{env_line}\'"')
            print("[完成] 环境变量格式已复制到剪贴板" if ret == 0 else "[警告] 复制到剪贴板失败",
                  file=sys.stderr)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(env_line + "\n")
            print(f"[完成] 环境变量格式已写入：{args.out}", file=sys.stderr)
        return

    # ------- 展示结果 -------
    print("-" * 60)
    print("accessToken:")
    print(access)
    print("-" * 60)
    if expires_at:
        print(f"剩余有效期：{format_remaining(expires_at)}")
    if auth.get("refreshToken"):
        re_at = auth.get("refreshExpiresAt")
        if re_at:
            print(f"refreshToken 剩余有效期：{format_remaining(re_at)}")

    # ------- 可选动作：复制到剪贴板 -------
    if args.copy:
        # 通过 PowerShell 原生剪贴板命令复制，无需第三方依赖
        ret = os.system(f'powershell -NoProfile -Command "Set-Clipboard -Value \'{access}\'"')
        print("[完成] accessToken 已复制到剪贴板" if ret == 0 else "[警告] 复制到剪贴板失败", file=sys.stderr)

    # ------- 可选动作：导出 JSON 文件 -------
    if args.out:
        export = {
            "accessToken": access,
            "refreshToken": auth.get("refreshToken", ""),
            "tokenType": auth.get("tokenType", "Bearer"),
            "expiresAt": expires_at,
        }
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(export, f, ensure_ascii=False, indent=2)
        print(f"[完成] token 已导出至：{args.out}")


if __name__ == "__main__":
    # 双击 .py 运行时命令行参数为空，此时窗口执行完会立即关闭；
    # 捕获异常打印完整堆栈，并在结束后暂停等待回车，确保信息可读。
    try:
        main()
    except SystemExit:
        # argparse 等主动退出的场景，仍然暂停以便看到提示
        if len(sys.argv) == 1:
            input("\n按回车键退出...")
        raise
    except Exception:
        import traceback
        print("\n[错误] 脚本执行出现未处理异常，堆栈如下：", file=sys.stderr)
        traceback.print_exc()
        input("\n按回车键退出...")
        sys.exit(1)

    # 正常执行完毕：双击运行（无参数）时暂停，避免窗口一闪而过
    if len(sys.argv) == 1:
        input("\n按回车键退出...")

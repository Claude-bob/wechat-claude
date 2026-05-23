import os
import sys
import time
import json
import hashlib
import base64
import struct
import socket
import xml.etree.ElementTree as ET

from flask import Flask, request, Response
from datetime import datetime, timezone, timedelta

tz_cn = timezone(timedelta(hours=8))

# Simple request log
_request_log: list[dict] = []


def _log(method: str, status: str, detail: str = "") -> None:
    _request_log.append({
        "time": datetime.now(tz_cn).strftime("%H:%M:%S"),
        "method": method,
        "status": status,
        "detail": detail,
    })
    if len(_request_log) > 50:
        _request_log.pop(0)


# Conditional import: try the real crypto lib first, fall back to hashlib shim
try:
    from Crypto.Cipher import AES as _AES
except ImportError:
    # pycryptodome not installed — install it: pip install pycryptodome
    raise ImportError("pycryptodome is required: pip install pycryptodome")

try:
    from openai import OpenAI as _OpenAI
except ImportError:
    raise ImportError("openai SDK is required: pip install openai")

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)

# ---------------------------------------------------------------------------
# Config (all from environment variables — never hardcode secrets)
# ---------------------------------------------------------------------------
WECHAT_TOKEN          = os.environ.get("WECHAT_TOKEN", "")
WECHAT_ENCODING_AES   = os.environ.get("WECHAT_ENCODING_AES_KEY", "")
WECHAT_CORP_ID        = os.environ.get("WECHAT_CORP_ID", "")
ANTHROPIC_API_KEY     = os.environ.get("ANTHROPIC_API_KEY", "")

# ---------------------------------------------------------------------------
# WeChat Enterprise message crypto
# ---------------------------------------------------------------------------
class WXBizMsgCrypt:
    """WeChat Enterprise message encryption/decryption (AES-256-CBC)."""

    def __init__(self, token: str, encoding_aes_key: str, corp_id: str):
        self.token = token
        self.corp_id = corp_id
        # WeChat gives the AES key as Base64, but without the trailing '='
        self.aes_key = base64.b64decode(encoding_aes_key + "=")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def verify_url(self, msg_signature: str, timestamp: str,
                   nonce: str, echostr: str) -> tuple:
        """GET request — verify the callback URL. Returns (decrypted_echostr, err_code)."""
        sig = self._sha1(self.token, timestamp, nonce, echostr)
        if sig != msg_signature:
            return None, -1
        plain, ok = self._decrypt(echostr)
        return plain, ok

    def decrypt_msg(self, msg_signature: str, timestamp: str,
                    nonce: str, raw_xml: str) -> tuple:
        """POST request — verify signature & decrypt the message body.
        Returns (plaintext_xml, err_code)."""
        root = ET.fromstring(raw_xml)
        enc = root.find("Encrypt")
        if enc is None:
            return None, -2
        cipher_text = enc.text

        sig = self._sha1(self.token, timestamp, nonce, cipher_text)
        if sig != msg_signature:
            return None, -1

        return self._decrypt(cipher_text)

    def encrypt_msg(self, reply_xml: str, nonce: str,
                    timestamp: str | None = None) -> str:
        """Encrypt the reply and wrap it in the XML envelope."""
        encrypted = self._encrypt(reply_xml)
        if timestamp is None:
            timestamp = str(int(time.time()))
        sig = self._sha1(self.token, timestamp, nonce, encrypted)
        return (
            f"<xml>\n"
            f"<Encrypt><![CDATA[{encrypted}]]></Encrypt>\n"
            f"<MsgSignature><![CDATA[{sig}]]></MsgSignature>\n"
            f"<TimeStamp>{timestamp}</TimeStamp>\n"
            f"<Nonce><![CDATA[{nonce}]]></Nonce>\n"
            f"</xml>"
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _sha1(self, *parts: str) -> str:
        s = "".join(sorted(parts))
        return hashlib.sha1(s.encode()).hexdigest()

    def _decrypt(self, cipher_text: str) -> tuple:
        raw = base64.b64decode(cipher_text)
        cipher = _AES.new(self.aes_key, _AES.MODE_CBC, self.aes_key[:16])
        plain = cipher.decrypt(raw)

        # PKCS#7 unpad
        pad = plain[-1]
        plain = plain[:-pad]

        # Layout: random(16) + msg_len(4) + msg + corp_id
        content = plain[16:]
        msg_len = socket.ntohl(struct.unpack("I", content[:4])[0])
        msg     = content[4 : 4 + msg_len].decode("utf-8")
        corp    = content[4 + msg_len :].decode("utf-8")

        if corp != self.corp_id:
            raise ValueError(f"CorpID mismatch: expected {self.corp_id}, got {corp}")
        return msg, 0

    def _encrypt(self, text: str) -> str:
        rand_bytes = os.urandom(16)
        msg_bytes  = text.encode("utf-8")
        msg_len    = struct.pack("!I", len(msg_bytes))  # network byte-order
        corp_bytes = self.corp_id.encode("utf-8")

        plain = rand_bytes + msg_len + msg_bytes + corp_bytes

        # PKCS#7 pad to 32-byte blocks
        pad = 32 - (len(plain) % 32)
        if pad == 0:
            pad = 32
        plain += bytes([pad]) * pad

        cipher = _AES.new(self.aes_key, _AES.MODE_CBC, self.aes_key[:16])
        return base64.b64encode(cipher.encrypt(plain)).decode()

# ---------------------------------------------------------------------------
# MiMo API client (OpenAI-compatible)
# ---------------------------------------------------------------------------
mimo = _OpenAI(
    api_key=ANTHROPIC_API_KEY,
    base_url="https://api.xiaomimimo.com/v1",
)

SYSTEM_PROMPT = """\
你是一个正在通过企业微信和朋友聊天的AI助手。回复要求：

1. 自然口语化 — 像真人朋友打字聊天一样，不要像在写文章
2. 简洁 — 通常 2-5 句话即可，符合微信聊天节奏
3. 用中文，可以偶尔用微信常用表情
4. 温暖、共情、有幽默感
5. 对方聊日常/感情/情绪时，用心倾听并给予温暖回应
6. 可以适当主动提问，延续对话

你是朋友，不是客服。"""

# ---------------------------------------------------------------------------
# Webhook — single endpoint handles GET (verify) and POST (receive)
# ---------------------------------------------------------------------------
@app.route("/api/webhook", methods=["GET", "POST"])
def webhook():
    if request.method == "GET":
        return _handle_verify()
    return _handle_message()

# ---------------------------------------------------------------------------
# GET — URL verification
# ---------------------------------------------------------------------------
def _handle_verify():
    _log("GET", "verify", "WeChat callback URL verification")
    wxcpt = _get_crypt()
    plain, code = wxcpt.verify_url(
        request.args.get("msg_signature", ""),
        request.args.get("timestamp", ""),
        request.args.get("nonce", ""),
        request.args.get("echostr", ""),
    )
    if code != 0:
        _log("GET", "verify_fail", "signature mismatch")
        return "verify failed", 403
    return Response(plain, mimetype="text/plain")

# ---------------------------------------------------------------------------
# POST — receive & reply
# ---------------------------------------------------------------------------
def _handle_message():
    _log("POST", "received")
    try:
        wxcpt = _get_crypt()
        raw_body = request.get_data(as_text=True) or ""
        plain_xml, code = wxcpt.decrypt_msg(
            request.args.get("msg_signature", ""),
            request.args.get("timestamp", ""),
            request.args.get("nonce", ""),
            raw_body,
        )
        if code != 0:
            _log("POST", "decrypt_fail", f"code={code}")
            return "decrypt failed", 403

        root     = ET.fromstring(plain_xml)
        msg_type = root.find("MsgType")
        if msg_type is None:
            _log("POST", "no_msgtype")
            return "success"

        msg_type = msg_type.text
        from_user = root.find("FromUserName").text
        to_user   = root.find("ToUserName").text
        _log("POST", f"msg_{msg_type}", f"from={from_user}")

        # --- Text message ---
        if msg_type == "text":
            content = root.find("Content").text or ""
            _log("POST", "calling_claude", content[:80])
            reply = _chat(content)
            _log("POST", "reply", reply[:80])
            return _reply_xml(wxcpt, from_user, to_user, reply, request.args.get("nonce", ""))

        # --- Event (subscribe / enter chat) ---
        if msg_type == "event":
            event = root.find("Event")
            if event is not None and event.text == "subscribe":
                return _reply_xml(
                    wxcpt, from_user, to_user,
                    "嗨！终于等到你了~ 😊\n我是你的AI聊天伙伴，随便聊什么都可以，我会认真倾听和回应。",
                    request.args.get("nonce", ""),
                )

        # For other message types, return empty success (no reply)
        return "success"
    except Exception:
        import traceback
        _log("POST", "error", traceback.format_exc()[:200])
        traceback.print_exc()
        return "success"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _get_crypt() -> WXBizMsgCrypt:
    return WXBizMsgCrypt(WECHAT_TOKEN, WECHAT_ENCODING_AES, WECHAT_CORP_ID)


def _chat(user_msg: str) -> str:
    """Call MiMo and return the assistant's reply text."""
    try:
        resp = mimo.chat.completions.create(
            model="mimo-v2-flash",
            max_tokens=300,
            temperature=0.85,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
        )
        return resp.choices[0].message.content or ""
    except Exception as exc:
        _log("POST", "api_error", str(exc)[:200])
        return "哎呀刚才走神了😅 再说一遍？"


def _reply_xml(wxcpt: WXBizMsgCrypt, to_user: str, from_user: str,
               text: str, nonce: str) -> Response:
    """Build the plaintext reply XML, encrypt it, and return the response."""
    plain = (
        f"<xml>\n"
        f"<ToUserName><![CDATA[{to_user}]]></ToUserName>\n"
        f"<FromUserName><![CDATA[{from_user}]]></FromUserName>\n"
        f"<CreateTime>{int(time.time())}</CreateTime>\n"
        f"<MsgType><![CDATA[text]]></MsgType>\n"
        f"<Content><![CDATA[{text}]]></Content>\n"
        f"</xml>"
    )
    encrypted = wxcpt.encrypt_msg(plain, nonce)
    return Response(encrypted, mimetype="application/xml")

# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def health():
    import sys
    return {
        "status": "ok",
        "python": sys.version,
        "corp_id_configured": bool(WECHAT_CORP_ID),
        "token_configured": bool(WECHAT_TOKEN),
        "aes_key_configured": bool(WECHAT_ENCODING_AES),
        "api_key_configured": bool(ANTHROPIC_API_KEY) and len(ANTHROPIC_API_KEY) > 10,
        "recent_requests": _request_log[-20:],
    }

# ---------------------------------------------------------------------------
# Ensure a clean name for Vercel's dev server / logging
# ---------------------------------------------------------------------------
app.config["SERVER_NAME"] = None

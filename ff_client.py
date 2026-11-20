"""Clean wrappers for Free Fire login and player fetching."""
import io, zlib, threading, contextlib
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from RishuxImp import AES_KEY, AES_IV, RELEASE_VERSION

# Import the login and data functions from your existing modules
from RishuXMaJor import oauth as _oauth, RishuxMajoLogin as _major_login, get_login_data as _get_login_data

PERSONAL_SHOW_URL = "https://clientbp.ppmainecoonghj.com/GetPlayerPersonalShow"
UNITY_VERSION     = "2018.4.11f1"
_login_lock = threading.Lock()

def login_account(uid: str, password: str) -> dict:
    """Performs OAuth -> MajorLogin -> GetLoginData and extracts Account ID."""
    with _login_lock:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                # 1. OAuth to get Access Token
                oid, at = _oauth(str(uid), str(password))
                
                # 2. Major Login: 
                # The function automatically parses the Protobuf response.
                # It extracts Field 1 (Account ID), Field 8 (JWT), Field 22 (Key), Field 23 (IV)
                jwt, _sk, _siv, acc_id, _kts = _major_login(oid, at, "4")
                
                # 3. Get Login Data (to ensure account is valid and fetch region)
                gld = _get_login_data(jwt, oid, "4")
                
        except Exception as e:
            raise RuntimeError(f"Free Fire login failed: {e}")
            
    return {
        "jwt": jwt, 
        "account_id": int(acc_id),   # This is the '19147901223' from your response
        "region": gld.get("region", "IND"),
        "nickname": gld.get("nickname", ""),
        "online": gld.get("online", "")
    }

def _varint(v):
    v = int(v); out = bytearray()
    while v > 127:
        out.append((v & 127) | 128); v >>= 7
    out.append(v); return bytes(out)

def _field(n, v): return _varint((n << 3) | 0) + _varint(v)
def _build_show_request(uid): return _field(1, uid) + _field(2, 9) + _field(3, 1) + _field(4, 1)
def _encrypt(d): return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(d, 16))

def _decompress(d):
    for w in (16 + zlib.MAX_WBITS, zlib.MAX_WBITS, -zlib.MAX_WBITS):
        try: return zlib.decompress(d, w)
        except zlib.error: continue
    return d

def _read_varint(d, p):
    v = s = 0
    while p < len(d):
        b = d[p]; p += 1; v |= (b & 0x7F) << s
        if not (b & 0x80): return v, p
        s += 7
        if s >= 70: raise ValueError("bad varint")
    raise ValueError("eof")

def _parse(d):
    out, p = {}, 0
    while p < len(d):
        tag, p = _read_varint(d, p); f, w = tag >> 3, tag & 7
        if f == 0: raise ValueError("bad field")
        if w == 0: v, p = _read_varint(d, p)
        elif w == 1: v = d[p:p+8]; p += 8
        elif w == 2:
            ln, p = _read_varint(d, p); v = d[p:p+ln]; p += ln
        elif w == 5: v = d[p:p+4]; p += 4
        else: raise ValueError(f"wire {w}")
        out.setdefault(f, []).append(v)
    return out

def _first(f, n): return f.get(n, [None])[0]
def _text(v): return v.decode("utf-8", "replace") if isinstance(v, bytes) else (v or "")

def fetch_player(jwt_token: str, target_uid: int) -> dict:
    """Fetches player level, exp, name using the JWT."""
    req = _encrypt(_build_show_request(int(target_uid)))
    headers = {
        "Host": "clientbp.ppmainecoonghj.com",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Authorization": f"Bearer {jwt_token}",
        "X-Unity-Version": UNITY_VERSION,
        "X-GA": "v1 1",
        "ReleaseVersion": RELEASE_VERSION,
    }
    try:
        r = requests.post(PERSONAL_SHOW_URL, data=req, headers=headers, timeout=25)
        r.raise_for_status()
    except Exception as e:
        raise RuntimeError(f"GetPlayerPersonalShow failed: {e}")

    data = _decompress(r.content)
    outer = _parse(data)
    inner = _first(outer, 1)
    if not isinstance(inner, bytes):
        raise RuntimeError("Player message not found in response")
    p = _parse(inner)
    return {
        "uid":    int(_first(p, 1) or 0),
        "name":   _text(_first(p, 3)),
        "region": _text(_first(p, 5)),
        "level":  int(_first(p, 6) or 0),
        "exp":    int(_first(p, 7) or 0),
    }
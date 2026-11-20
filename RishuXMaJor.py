import asyncio, socket, struct, random, time, re, base64, json
from datetime import datetime

import requests, urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from RishuxImp import (
    AES_KEY, AES_IV, CLIENT_SECRET, APP_ID,
    OAUTH_URL, MAJOR_LOGIN_URL, GETLOGIN_HOST,
    CLIENT_VERSION, RELEASE_VERSION, REGION,
    TCP_WAIT_0300, DEFAULT_MASK,
    CLOUDFLARE_PRIMARY_DNS, CLOUDFLARE_SECONDARY_DNS, DNS_CACHE_TTL,
    MATCH_START_DECRYPTED_HEX,
    FIELD_SIZES, FIELD_NAMES, CMD_NAMES,
    MSG_KEY_HELLO, MSG_KEY_ACK_HELLO, MSG_KEY_ACK,
    MSG_KEY_AUTH_447, MSG_KEY_AUTH_448, MSG_KEY_PING_POOL,
    UDP_DEVICE_ID, UDP_CLIENT_IP, UDP_DEVICE_HASH,
    TOKEN_SPLIT,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def hdr(t):   print("\n" + "=" * 70 + f"\n  {t}\n" + "=" * 70, flush=True)
def ok(m):    print(f"[+] {m}", flush=True)
def info(m):  print(f"[i] {m}", flush=True)
def warn(m):  print(f"[!] {m}", flush=True)
def err(m):   print(f"[-] {m}", flush=True)


_CRC7_TABLE = bytes([
    0,9,18,27,36,45,54,63,72,65,90,83,108,101,126,119,25,16,11,2,61,52,47,38,
    81,88,67,74,117,124,103,110,50,59,32,41,22,31,4,13,122,115,104,97,94,87,
    76,69,43,34,57,48,15,6,29,20,99,106,113,120,71,78,85,92,100,109,118,127,
    64,73,82,91,44,37,62,55,8,1,26,19,125,116,111,102,89,80,75,66,53,60,39,
    46,17,24,3,10,86,95,68,77,114,123,96,105,30,23,12,5,58,51,40,33,79,70,
    93,84,107,98,121,112,7,14,21,28,35,42,49,56,65,72,83,90,101,108,119,126,
    9,0,27,18,45,36,63,54,88,81,74,67,124,117,110,103,16,25,2,11,52,61,38,
    47,115,122,97,104,87,94,69,76,59,50,41,32,31,22,13,4,106,99,120,113,78,
    71,92,85,34,43,48,57,6,15,20,29,37,44,55,62,1,8,19,26,109,100,127,118,
    73,64,91,82,60,53,46,39,24,17,10,3,116,125,102,111,80,89,66,75,23,30,5,
    12,51,58,33,40,95,86,77,68,123,114,105,96,14,7,28,21,42,35,56,49,70,79,
    84,93,98,107,112,121,
])

def crc7(buf, c=0):
    c &= 0x7F
    for b in buf:
        c = _CRC7_TABLE[((2 * c) ^ b) & 0xFF] & 0x7F
    return c


_M = 0xFFFFFFFF
_DELTA = 0x9E3779B9
_ROUNDS = 16

def _tea_enc(v0, v1, k):
    s = 0
    for _ in range(_ROUNDS):
        s = (s + _DELTA) & _M
        v0 = (v0 + ((((v1 << 4) + k[0]) & _M)
                    ^ ((v1 + s) & _M)
                    ^ ((v1 >> 5) + k[1]))) & _M
        v1 = (v1 + ((((v0 << 4) + k[2]) & _M)
                    ^ ((v0 + s) & _M)
                    ^ ((v0 >> 5) + k[3]))) & _M
    return v0, v1

def _tea_dec(v0, v1, k):
    s = (_DELTA * _ROUNDS) & _M
    for _ in range(_ROUNDS):
        v1 = (v1 - ((((v0 << 4) + k[2]) & _M)
                    ^ ((v0 + s) & _M)
                    ^ ((v0 >> 5) + k[3]))) & _M
        v0 = (v0 - ((((v1 << 4) + k[0]) & _M)
                    ^ ((v1 + s) & _M)
                    ^ ((v1 >> 5) + k[1]))) & _M
        s = (s - _DELTA) & _M
    return v0, v1

def _udp_pad(content):
    pad_len = (8 - (len(content) + 10) % 8) % 8
    return bytes([pad_len]) + bytes(pad_len + 2) + content + bytes(7)

def _udp_unpad(padded):
    if len(padded) < 8 or any(padded[-1 - i] for i in range(7)):
        return None
    n = padded[0] & 7
    s, e = 3 + n, len(padded) - 7
    return padded[s:e] if s < e else b""

def udp_encrypt_body(content, key):
    padded = _udp_pad(content)
    k = struct.unpack("<4I", key)
    out = bytearray(len(padded))
    pc, pi = bytes(8), bytes(8)
    for i in range(0, len(padded), 8):
        d = bytes(a ^ b for a, b in zip(padded[i:i+8], pc))
        x = struct.pack("<2I", *_tea_enc(*struct.unpack("<2I", d), k))
        c = bytes(a ^ b for a, b in zip(x, pi))
        out[i:i+8] = c
        pc, pi = c, d
    return bytes(out)

def udp_decrypt_body(body, key):
    k = struct.unpack("<4I", key)
    out = bytearray(len(body))
    pc, pi = bytes(8), bytes(8)
    for i in range(0, len(body), 8):
        x = bytes(a ^ b for a, b in zip(body[i:i+8], pi))
        d = struct.pack("<2I", *_tea_dec(*struct.unpack("<2I", x), k))
        out[i:i+8] = bytes(a ^ b for a, b in zip(d, pc))
        pc, pi = body[i:i+8], d
    return bytes(out)


def RishuxEncryp(data, key=AES_KEY, iv=AES_IV):
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, AES.block_size))


def aes_encrypt(data, key=AES_KEY, iv=AES_IV):
    return RishuxEncryp(data, key, iv)

def aes_decrypt(data, key=AES_KEY, iv=AES_IV):
    if not data or len(data) % 16:
        return None
    try:
        try:
            return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(data),
                         AES.block_size)
        except ValueError:
            return AES.new(key, AES.MODE_CBC, iv).decrypt(data)
    except Exception:
        return None


def varint(n):
    if n < 0:
        n &= (1 << 64) - 1
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            b |= 0x80
        out.append(b)
        if not n:
            break
    return bytes(out)

def read_varint(buf, i):
    n = shift = 0
    while True:
        c = buf[i]
        i += 1
        n |= (c & 0x7F) << shift
        shift += 7
        if not (c & 0x80):
            return n, i

def zigzag_str(s):
    if isinstance(s, str):
        s = s.encode()
    n = len(s) << 1
    out = bytearray()
    while n > 0x7F:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out) + s

def _wv(v):    return varint(v)
def _fv(n, v): return _wv((n << 3) | 0) + _wv(int(v))
def _fs(n, s):
    b = s.encode() if isinstance(s, str) else bytes(s)
    return _wv((n << 3) | 2) + _wv(len(b)) + b

def serialize(fields):
    out = bytearray()
    for k, v in fields.items():
        if isinstance(v, bool):                 out += _fv(k, 1 if v else 0)
        elif isinstance(v, int):                out += _fv(k, v)
        elif isinstance(v, str):                out += _fs(k, v)
        elif isinstance(v, (bytes, bytearray)): out += _fs(k, bytes(v))
        elif isinstance(v, dict):               out += _fs(k, serialize(v))
    return bytes(out)

def _rv(buf, off):
    r, s = 0, 0
    while True:
        if off >= len(buf):
            raise ValueError("eof")
        b = buf[off]
        off += 1
        r |= (b & 0x7F) << s
        if not (b & 0x80):
            return r, off
        s += 7
        if s > 63:
            raise ValueError("long")

def _decode_len(raw, depth):
    if raw and all(32 <= b < 127 or b in (9, 10, 13) for b in raw):
        try:
            return raw.decode("utf-8")
        except Exception:
            pass
    if depth < 4 and len(raw) >= 2:
        try:
            sub, used = _parse(raw, depth + 1)
            if used == len(raw) and sub:
                return sub
        except Exception:
            pass
    try:
        return raw.decode("utf-8")
    except Exception:
        return raw

def _parse(buf, depth=0):
    out, off = {}, 0
    while off < len(buf):
        try:
            tag, off = _rv(buf, off)
        except Exception:
            break
        f, w = tag >> 3, tag & 7
        if f == 0:
            break
        try:
            if w == 0:
                v, off = _rv(buf, off)
            elif w == 1:
                v = buf[off:off + 8]; off += 8
            elif w == 2:
                ln, off = _rv(buf, off)
                chunk = buf[off:off + ln]; off += ln
                v = _decode_len(chunk, depth)
            elif w == 5:
                v = buf[off:off + 4]; off += 4
            else:
                break
        except Exception:
            break
        if f in out:
            out[f] = out[f] + [v] if isinstance(out[f], list) else [out[f], v]
        else:
            out[f] = v
    return out, off

def parse_proto(data):
    try:
        return _parse(data, 0)[0]
    except Exception:
        return {}

def first(d, k, default=None):
    v = d.get(k, default)
    if isinstance(v, list):
        v = v[0] if v else default
    return v

def to_int(v, default=0):
    v = first({0: v}, 0)
    if v is None:
        return default
    if isinstance(v, int):
        return v
    if isinstance(v, bytes):
        try:
            return int(v.decode("ascii", "ignore"))
        except Exception:
            return default
    try:
        return int(v)
    except Exception:
        return default

def to_str(v, default=""):
    v = first({0: v}, 0)
    if v is None:
        return default
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8", "ignore")
        except Exception:
            return default
    return str(v)


def non_reliable(mask):
    return "".join(c for c in mask if c != "2")

def build_pkt(cmd, content, key, mask, *, reliable=True, order_id=0,
              send_option=1, flags=1, msg_key=None, extra=b""):
    k0 = key[0]
    if extra:
        flags |= 4
    layout = [int(c) for c in (mask if reliable else non_reliable(mask))]
    body = udp_encrypt_body(content, key) if flags & 1 else content
    values = {0: send_option, 1: cmd, 2: order_id, 3: flags, 4: len(body)}
    head = b""
    for c in layout:
        v, n = values[c], FIELD_SIZES[c]
        head += (bytes([(v ^ k0) & 0xFF]) if n == 1
                 else struct.pack("<H", (v ^ ((k0 << 8) | k0)) & 0xFFFF))
    rest = head + bytes(b ^ k0 for b in extra) + body
    mk = msg_key if msg_key is not None else 90 + random.randrange(20)
    return bytes([mk, crc7(rest)]) + rest

def decode_header(pkt, key, mask):
    if len(pkt) < 8:
        return None
    k0 = key[0]
    v80 = ((k0 << 8) | k0) & 0xFFFF
    crc_ok = (pkt[1] & 0x7F) == crc7(pkt[2:])
    for m in (mask, non_reliable(mask)):
        off, f, valid = 2, {}, True
        for ch in m:
            c = int(ch)
            n = FIELD_SIZES[c]
            if off + n > len(pkt):
                valid = False
                break
            if n == 1:
                f[FIELD_NAMES[c]] = pkt[off] ^ k0
            else:
                f[FIELD_NAMES[c]] = (
                    (pkt[off] | (pkt[off + 1] << 8)) ^ v80) & 0xFFFF
            off += n
        if not valid:
            continue
        if f["flags"] > 7 or f["sendOption"] > 7:
            continue
        extra = 3 if f["flags"] & 4 else 0
        if f["length"] != len(pkt) - off - extra:
            continue
        return {"mask": m, "header_len": off, "extra": extra,
                "crc_ok": crc_ok, **f}
    return None


def pkt_hello(player_id, suffix, key, mask):
    data = f"{player_id}_{suffix}".encode()
    if len(data) < 16:
        data = data + b"\x00" * (16 - len(data))
    else:
        data = data[:16]
    body = b"\x10\x00\x00\x00" + data + b"\x00" * 9
    return build_pkt(1, body, key, mask, reliable=True, order_id=0,
                     send_option=1, flags=1, msg_key=MSG_KEY_HELLO)

def pkt_ack(acked, key, mask, style="regular"):
    body = struct.pack("<H", acked & 0xFFFF)
    mk = MSG_KEY_ACK_HELLO if style == "short" else MSG_KEY_ACK
    return build_pkt(2, body, key, mask, reliable=False, order_id=0,
                     send_option=0, flags=1, msg_key=mk)

def token_tail_len_for(token):
    """The client splits the 0300 token between cmd 447 (head) and cmd 448 (tail):
    780-char token -> 660 + 120 (capture 3); 1255 -> 1060 + 195 (older capture).  tail ~ 2/13 of the token."""
    return (2 * len(token)) // 13

def pkt_auth447(token, key, mask, order_id=0):
                                                                                                
    return build_pkt(447, zigzag_str(token[:len(token) - token_tail_len_for(token)]), key, mask,
                     reliable=True, order_id=order_id,
                     send_option=2, flags=1, msg_key=MSG_KEY_AUTH_447)

                                                                                  
 
                                                                   
                                                                                      
                                                                            
                                          
                                
                                                                                                                        
         
                             
                                                                           
                             
                                                                                  
 
def _m448_a(a0=0x1a, x=3, p=2, last=None):
    """23-byte block. a0 = field 6 of the 0300 sub-message (26), x = outer field 2 of 0300 (3);
    last byte = 1 << x  (x=2 -> 04 in the Oct capture, x=3 -> 08 here)."""
                                                                                 
                                                                              
    if last is None:
        last = (1 << x) & 0xFF
    return (bytes([a0 & 0xFF]) + bytes(6) + bytes([0x01, p & 0xFF, x, 0x01, 0x01, 0x04, 0x49, 0x4e, 0x00,
            x, 0x03, 0x00, 0x01, 0x00, 0x00, last & 0xFF]))
M448_A         = _m448_a()
M448_BLOCK16   = bytes.fromhex("0000010000000000010000000000")                          
M448_TAIL      = b"\x02\x00"
_LOGIN_TICKS   = (time.time_ns() // 100) + 621355968000000000 - 400_000_000                       

def _zz_int(n):
    return varint(((n << 1) ^ (n >> 63)) & ((1 << 64) - 1))

def pkt_auth448(token, key, mask, player_id, match_id,
                client_version="1.134.21",
                order_id=1,
                mode_id=62,
                flags_byte=None,                                                           
                msg_key=0x5D,
                device_id=None,
                device_hash=None,
                client_ip=None,
                device_fingerprint=None,
                hot_update_url=None,
                slot_byte=0x05,
                pre=0x09,
                a0=0x1a,
                room_x=3,
                login_ticks=None,
                token_tail_len=None,
                a_p=2, a_last=None, head_last=0):
    """Build cmd 448 exactly as the real client (capture: msg_key 0x5D, order 1, flags 1)."""
                                                                                             
    if not str(client_version).startswith("1."):
        client_version = "1.134.21"
    if device_id is None:          device_id = "2019121269"                                                                
    if device_hash is None:        device_hash = UDP_DEVICE_HASH
    if client_ip is None:          client_ip = UDP_CLIENT_IP
    if device_fingerprint is None: device_fingerprint = "B508C9D4DAAC63F7391B871519DE84397490"
    if hot_update_url is None:
        hot_update_url = ("https://dl-ind-production.freefiremobile.com/"
                          "2832022628717E276054_7104117490_107_1767713981_0")
    if login_ticks is None:        login_ticks = _LOGIN_TICKS
    if not token_tail_len: token_tail_len = token_tail_len_for(token)
    tail = token[-token_tail_len:]

    body = (
        varint(int(player_id))
        + varint(int(match_id))
        + bytes([0x01, mode_id & 0xFF])
        + varint(int(match_id))
        + _m448_a(a0, room_x, a_p, a_last)
        + zigzag_str(client_version)
        + zigzag_str(device_id)
        + bytes([0, 0, 0, pre & 0xFF, 0, 0, 0, head_last & 0xFF])
        + zigzag_str(device_fingerprint)
        + b"\x00" * 8
        + zigzag_str(hot_update_url)
        + M448_BLOCK16 + bytes([slot_byte & 0xFF, 0x00])
        + _zz_int(int(login_ticks)) + M448_TAIL
        + zigzag_str(client_ip)
        + zigzag_str(device_hash.lower().zfill(64))
        + zigzag_str(tail)
    )
    return build_pkt(448, body, key, mask, reliable=True, order_id=order_id,
                     send_option=2, flags=1, msg_key=msg_key)

def pkt_ping(tick, key, mask, msg_key=None, extra=b""):
    if msg_key is None:
        msg_key = MSG_KEY_PING_POOL[random.randrange(len(MSG_KEY_PING_POOL))]
    body = varint(tick & 0xFFFFFFFF) + b"\x00\x00\x00"
    return build_pkt(3, body, key, mask,
                     reliable=False, order_id=0,
                     send_option=0, flags=0,
                     msg_key=msg_key, extra=extra)

def cmd_name(cmd):
    return CMD_NAMES.get(cmd, f"cmd_{cmd}")


_DNS_CACHE = {}

async def resolve_host_cloudflare(hostname):
    if not hostname:
        return hostname
    parts = hostname.split('.')
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return hostname
    now = time.time()
    if hostname in _DNS_CACHE:
        ip, exp = _DNS_CACHE[hostname]
        if now < exp:
            return ip

    def _query(server_ip):
        s = None
        try:
            tx = random.randint(1000, 65535)
            header = struct.pack(">HHHHHH", tx, 0x0100, 1, 0, 0, 0)
            qname = b"".join(bytes([len(p)]) + p.encode('ascii')
                             for p in hostname.split('.')) + b"\x00"
            q = header + qname + struct.pack(">HH", 1, 1)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.2)
            s.sendto(q, (server_ip, 53))
            resp, _ = s.recvfrom(1024)
            if len(resp) >= 12 and struct.unpack(">H", resp[6:8])[0] > 0:
                off = 12 + len(qname) + 4
                for _ in range(struct.unpack(">H", resp[6:8])[0]):
                    if off >= len(resp):
                        break
                    if (resp[off] & 0xC0) == 0xC0:
                        off += 2
                    else:
                        while off < len(resp) and resp[off] != 0:
                            off += 1 + resp[off]
                        off += 1
                    if off + 10 > len(resp):
                        break
                    rt, rc, ttl, rdlen = struct.unpack(">HHIH", resp[off:off + 10])
                    off += 10
                    if rt == 1 and rdlen == 4 and off + 4 <= len(resp):
                        return socket.inet_ntoa(resp[off:off + 4])
                    off += rdlen
        except Exception:
            pass
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass
        return None

    loop = asyncio.get_running_loop()
    ip = await loop.run_in_executor(None, _query, CLOUDFLARE_PRIMARY_DNS)
    if not ip:
        ip = await loop.run_in_executor(None, _query, CLOUDFLARE_SECONDARY_DNS)
    if not ip:
        try:
            inf = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
            if inf:
                ip = inf[0][4][0]
        except Exception:
            ip = hostname
    if ip:
        _DNS_CACHE[hostname] = (ip, now + DNS_CACHE_TTL)
    return ip or hostname


class FrameReader:
    def __init__(self, reader):
        self.reader = reader
        self.buf = b""

    async def _fill(self, n, timeout):
        if len(self.buf) >= n:
            return True
        dl = time.time() + timeout
        while len(self.buf) < n:
            rem = dl - time.time()
            if rem <= 0:
                return False
            try:
                chunk = await asyncio.wait_for(
                    self.reader.read(65536), timeout=rem)
            except asyncio.TimeoutError:
                return False
            if not chunk:
                return False
            self.buf += chunk
        return True

    async def next_frame(self, timeout=1.5):
        if not await self._fill(5, timeout):
            return None
        op = self.buf[:2]
        ln = int.from_bytes(self.buf[2:5], "big")
        if ln <= 0 or ln > 65535:
            self.buf = self.buf[1:]
            return None
        if not await self._fill(5 + ln, timeout):
            return None
        payload = self.buf[5:5 + ln]
        self.buf = self.buf[5 + ln:]
        return op, payload


_IP_RE    = re.compile(rb'((?:\d{1,3}\.){3}\d{1,3}:\d{1,5})')
_HEX32_RE = re.compile(rb'([0-9a-fA-F]{32})')
_JWT_RE   = re.compile(rb'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+')

_HEX32 = set("0123456789abcdefABCDEF")

def _is_hex32(s):
    return (isinstance(s, str) and len(s) == 32
            and all(c in _HEX32 for c in s))

def _is_mask(s):
    return (isinstance(s, str) and len(s) == 5 and s.isdigit()
            and sorted(s) == sorted("01234"))

def _walk_find(obj, pred):
    if isinstance(obj, dict):
        for v in obj.values():
            r = _walk_find(v, pred)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for x in obj:
            r = _walk_find(x, pred)
            if r is not None:
                return r
    else:
        if pred(obj):
            return obj
    return None

def _scan_ips(payload):
    out = []
    for m in _IP_RE.finditer(payload):
        s = m.group(1).decode("ascii", "ignore")
        try:
            h, p = s.rsplit(":", 1)
            if all(0 <= int(x) <= 255 for x in h.split(".")) and 0 < int(p) < 65536:
                if s not in out:
                    out.append(s)
        except Exception:
            pass
    return out


def extract_448_fields(payload):
    """Fields of the 0300 response that the client copies into cmd 448.
    Independent of how the rest of parse_0300 found the server/key/token."""
    out = {}
                                                                       
    def walk(d, parent):
        if not isinstance(d, dict): return None
        k = to_str(first(d, 3))
        if _is_hex32(k): return d, parent
        for v in d.values():
            for item in (v if isinstance(v, list) else [v]):
                r_ = walk(item, d)
                if r_: return r_
        return None
    for off in range(0, min(65, len(payload))):
        try: outer = parse_proto(payload[off:])
        except Exception: continue
        if not outer: continue
        found = walk(outer, None)
        if not found: continue
        sub, parent = found
        for key_, f_ in (("a0", 6), ("mode_id", 7), ("slot_byte", 8)):
            v_ = to_int(first(sub, f_), -1)
            if v_ >= 0: out[key_] = v_
        u_ = to_str(first(sub, 39))
        if u_.startswith("http"): out["hot_update_url"] = u_
        x_ = to_int(first(parent or outer, 2), -1) if parent else to_int(first(outer, 2), -1)
        if x_ >= 0: out["room_x"] = x_
        if len(out) >= 4: return out
                                                                                       
    m = re.search(rb'\x30([\x01-\x7f])\x38([\x01-\x7f])\x40([\x01-\x7f])\x68', payload)
    if m:
        out.setdefault("a0", m.group(1)[0]); out.setdefault("mode_id", m.group(2)[0])
        out.setdefault("slot_byte", m.group(3)[0])
    m = re.search(rb'\x10([\x01-\x7f])\x20([\x01-\x7f])\x2a', payload[:80])
    if m: out.setdefault("room_x", m.group(1)[0])
    m = re.search(rb'https://dl[\x21-\x7e]+', payload)
    if m: out.setdefault("hot_update_url", m.group(0).decode())
    return out

def parse_0300(payload: bytes, fallback_account_id: int = 0):
    account_id = 0
    match_id = 0
    server = udp_key = token = mask = ""
    extra448 = {}

    def _take(d):
        nonlocal account_id, match_id, server, udp_key, token, mask

        if not match_id:
            match_id = to_int(first(d, 1))

        s = to_str(first(d, 2))
        if s and ":" in s and not server:
            server = s

        k = to_str(first(d, 3))
        if _is_hex32(k) and not udp_key:
            udp_key = k

        t = to_str(first(d, 4))
        if isinstance(t, str) and t.count(".") == 2 and len(t) > 50 and not token:
            token = t

        m = to_str(first(d, 42))
        if _is_mask(m) and not mask:
            mask = m

    for off in range(0, min(65, len(payload))):
        try:
            outer = parse_proto(payload[off:])
        except Exception:
            continue

        if not outer:
            continue

        oid = to_int(first(outer, 1))
        if oid and not account_id:
            account_id = oid

        sub = first(outer, 5)
        if isinstance(sub, dict):
            _take(sub)
                                                   
            if not extra448:
                for key_, f_ in (("a0", 6), ("mode_id", 7), ("slot_byte", 8)):
                    v_ = to_int(first(sub, f_), -1)
                    if v_ >= 0: extra448[key_] = v_
                u_ = to_str(first(sub, 39))
                if u_.startswith("http"): extra448["hot_update_url"] = u_
                x_ = to_int(first(outer, 2), -1)
                if x_ >= 0: extra448["room_x"] = x_

        if not (server and udp_key and token):

            if not udp_key:
                cand = _walk_find(
                    outer,
                    lambda v: _is_hex32(v) if isinstance(v, str) else False
                )
                if cand:
                    udp_key = cand

            if not mask:
                cand = _walk_find(
                    outer,
                    lambda v: _is_mask(v) if isinstance(v, str) else False
                )
                if cand:
                    mask = cand

            if not server:
                cand = _walk_find(
                    outer,
                    lambda v: isinstance(v, str)
                    and ":" in v
                    and "." in v.split(":")[0]
                    and v.split(":")[-1].isdigit()
                )
                if cand:
                    server = cand

            if not token:
                cand = _walk_find(
                    outer,
                    lambda v: isinstance(v, str)
                    and v.count(".") == 2
                    and len(v) > 50
                    and v.startswith("eyJ")
                )
                if cand:
                    token = cand

        if server and udp_key and token:
            break

    if not (server and udp_key and token):
        cands = _scan_ips(payload)
        mk = _HEX32_RE.search(payload)
        mj = _JWT_RE.search(payload)

        if cands and mk and mj:
            if not server:
                server = cands[0]

            if not udp_key:
                udp_key = mk.group(1).decode()

            if not token:
                token = mj.group(0).decode()

    if not (server and udp_key and token):
        warn("Match Data Parsing Failed")
        return None

    if not _is_mask(mask):
        mask = ""

    if not account_id:
        try:
            p = token.split(".")[1]
            p += "=" * (-len(p) % 4)

            c = json.loads(
                base64.urlsafe_b64decode(p)
            )

            for k in ("account_id", "uid", "sub"):
                if c.get(k):
                    account_id = int(c[k])
                    break

        except Exception:
            pass

    if not account_id:
        account_id = fallback_account_id

    if not match_id:
        match_id = account_id

    return {
        "account_id": account_id,
        "match_id": match_id,
        "token": token,
        "server": server,
        "udp_key": udp_key,
        "mask": mask,
        "extra448": extra448 or extract_448_fields(payload),
    }


def _region_byte(region):
    r = str(region).upper()

    if r == "BD":
        return 0x19

    if r == "IND":
        return 0x14

    return 0x15


def build_tcp_ping(session_key, session_iv):
    body = aes_encrypt(
        b"\x08\x20",
        session_key,
        session_iv
    )

    return (
        bytes.fromhex("0e14")
        + len(body).to_bytes(4, "big")
        + body
    )


async def tcp_open_and_auth(
    online,
    session_key,
    session_iv,
    jwt,
    jwt_uid,
    kts,
    region,
    match_start_plaintext
):
    host, port = online.rsplit(":", 1)

    ip = await resolve_host_cloudflare(host)

    reader, writer = await asyncio.open_connection(
        ip,
        int(port)
    )

    sock = writer.get_extra_info("socket")

    if sock:
        try:
            sock.setsockopt(
                socket.IPPROTO_TCP,
                socket.TCP_NODELAY,
                1
            )

            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_KEEPALIVE,
                1
            )

        except Exception:
            pass

    fr = FrameReader(reader)

    auth_enc = aes_encrypt(
        jwt.encode(),
        session_key,
        session_iv
    )

    auth_pkt = (
        bytes([0x83, _region_byte(region)])
        + int(jwt_uid).to_bytes(8, "big")
        + int(kts).to_bytes(4, "big")
        + b"\x00\x00\x00\x00"
        + len(auth_enc).to_bytes(4, "big")
        + auth_enc
    )

    writer.write(auth_pkt)
    await writer.drain()

    ack = await fr.next_frame(timeout=3)

    if not ack:
        warn("TCP Authentication Response Not Received")
        return None, None

    info("TCP Authentication Successful")

    match_enc = aes_encrypt(
        match_start_plaintext,
        session_key,
        session_iv
    )

    match_pkt = (
        bytes.fromhex("0314")
        + len(match_enc).to_bytes(4, "big")
        + match_enc
    )

    writer.write(match_pkt)
    await writer.drain()

    return writer, fr


async def tcp_heartbeat_loop(
    writer,
    session_key,
    session_iv,
    stop_event,
    interval=1.0
):
    pkt = build_tcp_ping(
        session_key,
        session_iv
    )

    while not stop_event.is_set():

        try:
            if writer.is_closing():
                break

            writer.write(pkt)
            await writer.drain()

        except Exception:
            break

        try:
            await asyncio.wait_for(
                stop_event.wait(),
                timeout=interval
            )

            break

        except asyncio.TimeoutError:
            pass


async def tcp_wait_for_0300(
    writer,
    fr,
    session_key,
    session_iv
):
    t0 = time.time()

    while time.time() - t0 < TCP_WAIT_0300:

        frame = await fr.next_frame(timeout=2)

        if not frame:
            continue

        opcode, payload = frame
        hex_op = opcode.hex()

        if hex_op not in (
            "0300",
            "0b00",
            "0c00",
            "1e00"
        ):
            continue

        if hex_op == "0300":

            if len(payload) < 300:
                continue

            try:
                open('last_0300.hex', 'w').write(opcode.hex() + len(payload).to_bytes(3,'big').hex() + payload.hex())
            except Exception: pass
            m = parse_0300(payload)

            if not m:
                err("Match Data Received But Parsing Failed")
                return None

            if not m["mask"]:
                err("Match Data Invalid")
                return None

            info("Match Found Successfully")

            return m

        elif hex_op in ("0b00", "0c00", "1e00"):
            warn("Server Disconnected")
            return None

    warn("Match Response Timeout")

    return None


def oauth(uid, password):
    hdr("STEP 0a · OAuth")
    r = requests.post(OAUTH_URL, data={
        "uid": uid, "password": password, "response_type": "token",
        "client_type": "2", "client_secret": CLIENT_SECRET,
        "client_id": APP_ID,
    }, headers={
        "User-Agent": "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;en;IN;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Connection": "close",
    }, timeout=20, verify=False)
    info(f"POST {OAUTH_URL}  ->  HTTP {r.status_code}")
    if r.status_code != 200:
        raise RuntimeError(f"OAuth HTTP {r.status_code}: {r.text[:200]}")
    j = r.json()
    oid, at = j.get("open_id"), j.get("access_token")
    if not oid or not at:
        raise RuntimeError(f"missing fields: {j}")
    ok(f"open_id      = {oid}")
    ok(f"access_token = {at[:40]}…")
    return oid, at

def _build_major_login(open_id, access_token, platform="4"):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return serialize({
        3: now,
        4: "free fire",
        5: 1,
        7: "2.133.21",
        8: "Android OS 10 / API-29 (QP1A.190711.020/1617006012)",
        9: "Handheld",
        10: "Vi India",
        11: "WIFI",
        12: 1600,
        13: 720,
        14: "320",
        15: "ARM64 FP ASIMD AES | 2301 | 8",
        16: 2799,
        17: "PowerVR Rogue GE8320",
        18: "OpenGL ES 3.2 build 1.11@5425693",
        19: "Google|9f7d6b8b-b10c-454a-852d-06332cd498eb",
        20: "27.59.76.116",
        21: "en",
        22: open_id,
        23: str(platform),
        24: "Handheld",
        25: "realme RMX2189",
        26: "IND",
        29: access_token,
        30: 1,
        41: "Vi India",
        42: "WIFI",
        57: "1ac4b80ecf0478a44203bf8fac6120f5",
        60: 19799,
        61: 398,
        62: 5056,
        64: 630,
        65: 19999,
        66: 398,
        67: 19799,
        73: 1,
        74: "/data/app/com.dts.freefiremax-wM_nCGkPxQvCg13Ysj9JlQ==/lib/arm64",
        76: 2,
        77: "38f4751a330688ab124c2c804cec90a5|/data/app/com.dts.freefiremax-wM_nCGkPxQvCg13Ysj9JlQ==/base.apk",
        78: 2,
        79: 2,
        81: "64",
        83: "2019118527",
        85: 3,
        86: "OpenGLES3",
        87: 3071,
        88: 4,
        92: 26920,
        93: "android_max",
        94: "KqsHT6NSaJMIoBpF19ueWylT2LLilQWlyDB5nQyQ2jsLu3lEd8JXKTxMx65YpoRiQkxpKiSBnUtmwpxCc5vDg6wfBGbnRWlykj7m2+kr9/ErkBD9",
        95: 111207,
        96: '{"cur_rate":null,"support_etc2":true}',
        97: 1,
        99: str(platform),
        100: str(platform),
        102: {},
        104: 13135,
        105: 1,
        106: "https://dl-tata.freefireind.in/live/ABHotUpdates/|https://core-tata.freefireind.in/live/ABHotUpdates/|b6756df94c9ff39b46f783f0998378a7",
        107: "1.ba9dc3de1bf701c3",
    })

def _extract_major(raw):
    candidates = []
    dec = aes_decrypt(raw)
    if dec:
        candidates.append(dec)
    if len(raw) > 64:
        candidates.append(raw[64:])
        d2 = aes_decrypt(raw[64:])
        if d2:
            candidates.append(d2)
    candidates.append(raw)
    for buf in candidates:
        root = parse_proto(buf)
        jwt_v = first(root, 8)
        if isinstance(jwt_v, bytes):
            try:
                jwt_v = jwt_v.decode("utf-8", "ignore")
            except Exception:
                jwt_v = None
        if not (isinstance(jwt_v, str) and jwt_v.count(".") == 2
                and len(jwt_v) > 100):
            continue

        def _b(f):
            v = first(root, f)
            if isinstance(v, (bytes, bytearray)) and len(v) == 16:
                return bytes(v)
            if isinstance(v, str) and len(v) == 32:
                try:
                    return bytes.fromhex(v)
                except Exception:
                    pass
            return None

        key, iv = _b(22), _b(23)
        if not key or not iv:
            continue
        acc_id = to_int(first(root, 1))
        srv_t  = to_int(first(root, 21), int(time.time()))
        return jwt_v, key, iv, acc_id, srv_t
    raise RuntimeError("JWT / session keys not found in MajorLogin response")

def RishuxMajoLogin(open_id, access_token, platform="4"):
    hdr("STEP 0b · MajorLogin")
    body = aes_encrypt(_build_major_login(open_id, access_token, platform))
    r = requests.post(MAJOR_LOGIN_URL, data=body, headers={
        "Host": "loginbp.ppmainecoonghj.com",
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*", "X-GA-SV": str(int(time.time())),
        "Authorization": "Bearer ", "X-GA": "v1 1",
        "ReleaseVersion": RELEASE_VERSION,
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1",
        "Content-Length": str(len(body)),
    }, timeout=30, verify=False)
    info(f"POST {MAJOR_LOGIN_URL}  ->  HTTP {r.status_code}")
    if r.status_code != 200:
        raise RuntimeError(f"MajorLogin HTTP {r.status_code}")
    return _extract_major(r.content)


def major_login(open_id, access_token, platform="4"):
    return RishuxMajoLogin(open_id, access_token, platform)


def get_login_data(jwt, open_id, platform="4"):
    hdr("STEP 0c · GetLoginData")
    body = aes_encrypt(serialize({
        3: time.strftime("%Y-%m-%d %H:%M:%S"),
        4: "free fire", 5: 1, 7: CLIENT_VERSION,
        8: "Android OS 15 / API-35", 9: "Handheld",
        10: "airtel", 11: "CarrierDataNetwork",
        12: 2400, 13: 1080, 14: "400",
        15: "ARM64 FP ASIMD AES | 4800 | 8", 16: 7461,
        17: "Adreno (TM) 710", 18: "OpenGL ES 3.2",
        19: "Google|0ea5b865-94e6-42dd-9f40-f52a63378bc7",
        20: "27.59.76.15", 21: "en",
        22: open_id, 23: str(platform), 24: "Handheld",
        25: "motorola moto g96 5G", 26: REGION,
        29: jwt, 30: 1, 41: "airtel", 42: "4G",
        57: "1ac4b80ecf0478a44203bf8fac6120f5",
        60: 111316, 61: 73226, 62: 690, 64: 73354,
        65: 111316, 66: 73354, 67: 111316, 73: 3,
        74: "/data/app/arm64", 76: 2, 77: "apk", 78: 2, 79: 2,
        81: "64", 83: "2019118527", 85: 3, 86: "OpenGLES3",
        87: 4095, 88: 4, 90: "New Delhi", 91: "DL", 92: 12573,
        93: "android_max",
        94: "KqsHT0wswggWbev04P17TGvl/w+c875HviaAj4qL+YhymI7Psonj/aQgNTNLf+4nm1LzYE6DxxzpZH9FX0Kt119zYuGdivC/V7aWpj4/HNhVAwJy",
        95: 111107, 96: '{"cur_rate":[60,90,120,144],"support_etc2":true}',
        97: 1, 99: "0", 100: str(platform), 102: "",
        104: 95926, 105: 1,
        106: "https://dl.cdn.freefiremobile.com/live/ABHotUpdates/|https://dl-core.cdn.freefiremobile.com/live/ABHotUpdates/|a4332cb1c1a84e51dd77441e4856ed5a",
        107: "1.7a99d677ab872769",
    }))
    r = requests.post(f"https://{GETLOGIN_HOST}/GetLoginData", data=body, headers={
        "Host": GETLOGIN_HOST,
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*", "X-GA-SV": str(int(time.time())),
        "Authorization": f"Bearer {jwt}",
        "X-GA": "v1 1", "ReleaseVersion": RELEASE_VERSION,
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1",
        "Content-Length": str(len(body)),
    }, timeout=20, verify=False)
    info(f"POST https://{GETLOGIN_HOST}/GetLoginData  ->  HTTP {r.status_code}")
    if r.status_code != 200:
        raise RuntimeError(f"GetLoginData HTTP {r.status_code}")
    raw = r.content
    for off in (0, 64):
        if len(raw) <= off:
            continue
        root = parse_proto(raw[off:])
        online = to_str(first(root, 14))
        if online and ":" in online:
            return {"online": online,
                    "region": to_str(first(root, 3), REGION).upper(),
                    "nickname": to_str(first(root, 4), "")}
    raise RuntimeError("no online_ip_port in GetLoginData")

def patch_account_id(hex_str, new_uid):
    raw = bytearray(bytes.fromhex(hex_str))
    for marker in (b"INDIA_NOTINIT?", b"BD_NOTINIT?", b"US_NOTINIT?"):
        idx = raw.find(marker)
        if idx < 0:
            continue
        start = idx + len(marker)
        end = start
        while end < len(raw) and 0x30 <= raw[end] <= 0x39:
            end += 1
        old = raw[start:end].decode("ascii", "ignore")
        new = str(new_uid).encode("ascii")
        if old == new_uid:
            return bytes(raw)
        delta = len(new) - (end - start)
        raw = raw[:start] + new + raw[end:]
        if idx >= 2 and raw[idx - 2] == 0x0a and raw[idx - 1] < 0x80:
            n = raw[idx - 1] + delta
            if 0 <= n < 0x80:
                raw[idx - 1] = n
        return bytes(raw)
    return bytes(raw)
import asyncio, sys, argparse, socket, secrets, time

from RishuxImp import (
    MATCH_START_DECRYPTED_HEX, HANDSHAKE_STEP_DELAY, CLIENT_VERSION,
    TCP_HEARTBEAT_INTERVAL, PING_ENABLED, PING_INTERVAL, PING_TICK_BASE,
    UDP_CLIENT_VERSION,
)
from RishuXMaJor import (
    hdr, ok, info, warn, err, read_varint,
    decode_header, cmd_name,
    pkt_hello, pkt_ack, pkt_auth447, pkt_auth448, pkt_ping,
    udp_decrypt_body, _udp_unpad, resolve_host_cloudflare,
    tcp_open_and_auth, tcp_heartbeat_loop, tcp_wait_for_0300,
    oauth, RishuxMajoLogin, get_login_data, patch_account_id,
)


def _zz_decode(v): return (v >> 1) ^ -(v & 1)


def parse_server_pos(h, pkt, key):
    if h["cmd"] != 2001: return None
    off  = h["header_len"] + h.get("extra", 0)
    body = pkt[off:off + h["length"]]
    if h["flags"] & 1:
        if key is None: return None
        body = _udp_unpad(udp_decrypt_body(body, key)) or b""
    if len(body) < 9 or body[0] != 0 or not 1 <= body[1] <= 8 or not 1 <= body[2] <= 32:
        return None
    try:
        x, i = read_varint(body, 3)
        y, i = read_varint(body, i)
        z, i = read_varint(body, i)
    except IndexError:
        return None
    return {"x": _zz_decode(x), "y": _zz_decode(y),
            "z": _zz_decode(z), "slot": body[2], "team": body[1]}


async def udp_session(host, port, key_hex, token, player_id, match_id, mask, *,
                      extra448=None, mode_override=None):
    hdr("STEP 5 · UDP socket + handshake")
    try: key = bytes.fromhex(key_hex)
    except Exception: err("bad udp key"); return
    if len(key) != 16: err("udp key must be 16 B"); return
    if token.count(".") != 2: err("bad JWT"); return

    resolved = await resolve_host_cloudflare(host)
    ok(f"target={host}:{port}  mask={mask}")

    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try: sock.bind(("0.0.0.0", 0))
    except OSError as e: warn(f"bind: {e}")
    try: sock.connect((resolved, port))
    except OSError as e: err(f"connect: {e}"); return

    st = {
        "recv": 0, "spawn": {}, "entity": None,
        "spawn_known": asyncio.Event(), "t_448": 0.0,
        "recv_q": asyncio.Queue(maxsize=4000),
        "stop_recv": asyncio.Event(), "stop_bg": asyncio.Event(),
        "ack_next": 0, "ack_sent": 0, "recv_orders": set(),
        "t0": time.time(), "joined": asyncio.Event(), "n100": 0, "last_ack_t": 0.0,
    }

    suffix = str(10000 + secrets.randbelow(90000))
    hello = pkt_hello(str(player_id), suffix, key, mask)
    a447  = pkt_auth447(token, key, mask, order_id=0)
                                                                        
                                                                                            
    from RishuxImp import PRESET_73
    kw = dict(PRESET_73); kw.update({k: v for k, v in (extra448 or {}).items() if k != 'hot_update_url'})
    if mode_override is not None: kw["mode_id"] = mode_override
    info(f"cmd 448 fields from 0300: {kw}")
    if not extra448: warn("0300 gave no 448 fields -> using the mode-73 capture preset (PRESET_73 in RishuxImp.py)")
    a448  = pkt_auth448(token, key, mask, player_id, match_id,
                        UDP_CLIENT_VERSION, order_id=1, **kw)

    async def send(pkt, label):
        try: await loop.sock_sendall(sock, pkt)
        except OSError as e: warn(f"send: {e}"); return False
        if label: print(f"  -> {label:<40} ({len(pkt):>4} B)")
        return True

    def note_order(h):
        oid = h.get("orderId")
        if oid is None or h["cmd"] == 2: return
        st["recv_orders"].add(oid)
        while st["ack_next"] in st["recv_orders"]: st["ack_next"] += 1

    def note_server_pos(h, pkt):
        sp = parse_server_pos(h, pkt, key)
        if not sp: return
        if not st["spawn_known"].is_set():
            st["spawn"] = dict(sp)
            st["entity"] = (sp["team"] << 24) | sp["slot"]
            st["spawn_known"].set()
            info(f"[CMD 2001] team={sp['team']} slot={sp['slot']} x={sp['x']} y={sp['y']} z={sp['z']}")

    async def handle(pkt, label=""):
        h = decode_header(pkt, key, mask)
        if not h: return None
        cmd = h["cmd"]; oid = h.get("orderId")
        el = time.time() - st["t0"]
        print(f"  < [{el:6.2f}s] cmd={cmd:<5}({cmd_name(cmd):<12}) "
              f"flags={h['flags']} order={oid} len={h['length']:>4} {label}")
        dup = oid is not None and cmd != 2 and oid in st["recv_orders"]
        note_order(h)
                                                                                     
                                                                       
        if oid is not None and cmd != 2 and (h.get("sendOption") == 2 or (h["flags"] & 1)):
            if st["ack_next"] > st["ack_sent"] or dup:
                st["ack_sent"] = st["ack_next"]
                await send(pkt_ack(st["ack_next"], key, mask, "regular"), None)
        if cmd == 100:
            try:
                off_ = h["header_len"] + h.get("extra", 0)
                dec_ = _udp_unpad(udp_decrypt_body(pkt[off_:off_ + h["length"]], key)) or b""
                if st["n100"] < 2: print(f"      cmd100 body ({len(dec_)} B): {dec_.hex()}")
            except Exception: pass
            st["n100"] += 1
            if st["n100"] == 3:
                warn("server keeps repeating cmd 100 -> it is not accepting cmd 448 "
                     "(check mode/slot/url from 0300, device id/hash, version)")
        elif cmd in (99, 176, 849) and not st["joined"].is_set():
            st["joined"].set()
        if cmd == 1: await send(pkt_ack(1, key, mask, "short"), "ACK HELLO")
        elif cmd == 2001: note_server_pos(h, pkt)
        return cmd

    async def recv_loop():
        while not st["stop_recv"].is_set():
            try:
                pkt, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 65536), timeout=0.5)
            except asyncio.TimeoutError: continue
            except OSError: break
            st["recv"] += 1
            try: st["recv_q"].put_nowait(pkt)
            except asyncio.QueueFull: pass

    async def consume():
        while not st["stop_bg"].is_set():
            try:
                pkt = await asyncio.wait_for(st["recv_q"].get(), timeout=0.2)
            except asyncio.TimeoutError: continue
            try: await handle(pkt, label="(bg)")
            except Exception as e: warn(f"handle: {e}")

    recv_task = asyncio.create_task(recv_loop())
    consume_task = None

    async def handshake(pkt, label, expect, name, timeout=HANDSHAKE_STEP_DELAY):
        start = time.time()
        await send(pkt, label)
        while True:
            rem = timeout - (time.time() - start)
            if rem <= 0: break
            try: got = await asyncio.wait_for(st["recv_q"].get(), timeout=min(0.3, rem))
            except asyncio.TimeoutError: continue
            cmd = await handle(got, label=f"({name})")
            if cmd in expect:
                ok(f"  OK cmd={cmd} in {time.time()-start:.2f}s")
                return True
        warn(f"  XX {name}: no reply")
        return False

    try:
        if not await handshake(hello, f"HELLO suffix={suffix}", {1, 2, 11}, "HELLO"): return
        if not await handshake(a447, "AUTH#1", {2}, "447"): return
        st["t_448"] = time.time()
        if not await handshake(a448, "AUTH#2", {2, 99, 100, 176, 849, 2001}, "448"):
            warn("AUTH#2 no reply — continuing")

        consume_task = asyncio.create_task(consume())

                                                                                                
                                                                              
        try:
            await asyncio.wait_for(st["joined"].wait(), timeout=15.0)
            print("\nPlayer has Joined Successfully ✅  (server is sending match data)")
        except asyncio.TimeoutError:
            warn("no cmd 99/176/849 within 15 s after cmd 448 - keeping the connection anyway")

        if st["spawn_known"].is_set():
            spawn, ent_id = st["spawn"], st["entity"]
            print(f"\n[CMD 2001] team={spawn['team']} slot={spawn['slot']} "
                  f"x={spawn['x']} y={spawn['y']} z={spawn['z']} entity={ent_id}")

        if PING_ENABLED:
            info(f"\n[SENDING UDP PING cmd=3 EVERY {PING_INTERVAL:.0f}s]")
            ping_t0 = time.time()
            while not st["stop_bg"].is_set():
                el_ms = int((time.time() - ping_t0) * 1000)
                tick = (PING_TICK_BASE - 2 * el_ms) & 0xFFFFFFFF
                pkt = pkt_ping(tick, key, mask)
                try:
                    await loop.sock_sendall(sock, pkt)
                except OSError as e:
                    warn(f"ping: {e}"); break
                await asyncio.sleep(PING_INTERVAL)
        else:
            while not st["stop_bg"].is_set():
                await asyncio.sleep(1.0)
    finally:
        st["stop_bg"].set(); st["stop_recv"].set()
        for t in (recv_task, consume_task):
            if t:
                try: t.cancel()
                except: pass
        try: sock.close()
        except: pass


def parse_addr(s):
    if not s: return None, None
    s = str(s).strip()
    if ":" in s:
        h, p = s.rsplit(":", 1)
        try: return h, int(p)
        except ValueError: return h, None
    return s, None

def is_placeholder_host(h):
    if not h or h in ("localhost", "0.0.0.0", "::1", ""): return True
    for pref in ("127.", "10.", "192.168.", "169.254."):
        if h.startswith(pref): return True
    if h.startswith("172."):
        try:
            if 16 <= int(h.split(".")[1]) <= 31: return True
        except: pass
    return False


async def run_pipeline(uid, password, *, server_override="", mode_override=None):

    oid, at = oauth(uid, password)
    ok("Authentication Success -- Access Token")

    info("Sending Major Login")
    jwt, sk, siv, acc_id, kts = RishuxMajoLogin(oid, at, "4")

    info("Sending Get Login Data")
    gld = get_login_data(jwt, oid, "4")

    ok("Login Data Received Successfully")
    ok(f"Account ID: {acc_id}")
    ok(f"Region: {gld['region']}")

    ms_plain = patch_account_id(
        MATCH_START_DECRYPTED_HEX, str(acc_id)
    )

    writer, fr = await tcp_open_and_auth(
        gld['online'], sk, siv, jwt, acc_id,
        kts, gld['region'], ms_plain
    )

    stop_tcp = asyncio.Event()

    hb_task = asyncio.create_task(
        tcp_heartbeat_loop(
            writer, sk, siv, stop_tcp,
            TCP_HEARTBEAT_INTERVAL
        )
    )

    try:
        info("Connecting To Match Server")

        found = await tcp_wait_for_0300(
            writer, fr, sk, siv
        )

        if not found:
            err("Match Not Found")
            return

        ok("Match Found Successfully")

        if server_override:
            found["server"] = server_override

        host, port = parse_addr(found["server"])

        if is_placeholder_host(host):
            if not server_override:
                err(f"placeholder {host!r}")
                return
            host, port = parse_addr(server_override)

        if not port:
            port = 10018

        await udp_session(
            host=host,
            port=port,
            key_hex=found["udp_key"],
            token=found["token"],
            player_id=int(acc_id),
            match_id=int(found["match_id"]),
            mask=found["mask"],
            extra448=found.get("extra448"),
            mode_override=mode_override
        )

    finally:
        stop_tcp.set()

        try:
            await asyncio.wait_for(hb_task, timeout=2.0)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            hb_task.cancel()

        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass


def _clean(s): return (s or "").strip().replace("\n","").replace("\r","").replace(" ","")
import os
def _prompt():
    os.system("cls" if os.name == "nt" else "clear")
    print("\033[96m")
    print(r"""
██████╗ ██╗███████╗██╗  ██╗██╗   ██╗
██╔══██╗██║██╔════╝██║  ██║██║   ██║
██████╔╝██║███████╗███████║██║   ██║
██╔══██╗██║╚════██║██╔══██║██║   ██║
██║  ██║██║███████║██║  ██║╚██████╔╝
╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝
""")

    print("\033[92m")
    print("        R I S H U X   U D P ")
    print("  ═════════════════════════════════════")
    print("          CS RANK UDP CONNECTION")
    print("  ═════════════════════════════════════")
    print("\033[0m")

    uid = _clean(input("\033[96m[+] UID      : \033[0m"))
    if not uid:
        print("\033[91m[!] UID required\033[0m")
        sys.exit(1)

    pw = _clean(input("\033[96m[+] PASSWORD : \033[0m"))
    if not pw:
        print("\033[91m[!] Password required\033[0m")
        sys.exit(1)

    return uid, pw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default="")
    ap.add_argument("--mode", default=None, help="override cmd-448 mode id (default: from 0300, e.g. 62)")
    args = ap.parse_args()

    try: mode_override = int(args.mode, 0) & 0xFF if args.mode else None
    except ValueError: mode_override = None

    uid, pw = _prompt()

    try:
        asyncio.run(run_pipeline(uid, pw,
                                 server_override=args.server,
                                 mode_override=mode_override))
    except KeyboardInterrupt:
        print("\nstopped (Ctrl-C)")


if __name__ == "__main__":
    main()
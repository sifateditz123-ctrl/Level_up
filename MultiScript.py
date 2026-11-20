
import asyncio, sys, time, secrets, socket

from RishuxImp import (
    MATCH_START_DECRYPTED_HEX, HANDSHAKE_STEP_DELAY,
    TCP_HEARTBEAT_INTERVAL, PING_ENABLED, PING_INTERVAL, PING_TICK_BASE,
    UDP_CLIENT_VERSION, UDP_WAIT_JOIN,
)
from RishuXMaJor import (
    hdr, ok, info, warn, err, read_varint, decode_header, cmd_name,
    pkt_hello, pkt_ack, pkt_auth447, pkt_auth448, pkt_ping,
    udp_decrypt_body, _udp_unpad, resolve_host_cloudflare,
    tcp_open_and_auth, tcp_heartbeat_loop, tcp_wait_for_0300,
    oauth, major_login, get_login_data, patch_account_id,
)

try:
    from RishuxImp import PRESET_73
except ImportError:
    PRESET_73 = {}

MATCH_CYCLE_INTERVAL = 3.0     
MATCH_IDLE_TIMEOUT   = 15.0   
MAX_PARALLEL_MATCHES = 100    


# ── helpers ─────────────────────────────────────────────────────
def _zz(v): return (v >> 1) ^ -(v & 1)

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
        except Exception: pass
    return False

def _parse_server_pos(h, pkt, key):
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
    except IndexError: return None
    return {"x": _zz(x), "y": _zz(y), "z": _zz(z), "slot": body[2], "team": body[1]}


# ── UDP session (async, keeps pinging until idle / cancelled) ──
async def udp_session(host, port, key_hex, token, player_id, match_id, mask, *,
                      extra448=None, mode_override=None,
                      on_join=None, duration=0.0, match_label=""):
    hdr(f"UDP session · {match_label}")
    try: key = bytes.fromhex(key_hex)
    except Exception: err("bad udp key"); return False
    if len(key) != 16: err("udp key must be 16 B"); return False
    if token.count(".") != 2: err("bad JWT"); return False

    resolved = await resolve_host_cloudflare(host)
    ok(f"target={host}:{port}  mask={mask}")

    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
    except OSError: pass
    sock.setblocking(False)
    try: sock.bind(("0.0.0.0", 0))
    except OSError as e: warn(f"bind: {e}")
    try: sock.connect((resolved, port))
    except OSError as e: err(f"connect: {e}"); return False

    st = {
        "recv": 0, "spawn": {}, "entity": None,
        "spawn_known": asyncio.Event(),
        "recv_q": asyncio.Queue(maxsize=4000),
        "stop_recv": asyncio.Event(), "stop_bg": asyncio.Event(),
        "ack_next": 0, "ack_sent": 0, "recv_orders": set(),
        "t0": time.time(), "joined": asyncio.Event(),
        "n100": 0, "last_rx": time.time(), "t_join": 0.0,
    }

    suffix = str(10000 + secrets.randbelow(90000))
    hello = pkt_hello(str(player_id), suffix, key, mask)
    a447  = pkt_auth447(token, key, mask, order_id=0)
    kw    = dict(PRESET_73)
    kw.update({k: v for k, v in (extra448 or {}).items() if k != "hot_update_url"})
    if mode_override is not None: kw["mode_id"] = mode_override
    a448  = pkt_auth448(token, key, mask, player_id, match_id,
                        UDP_CLIENT_VERSION, order_id=1, **kw)

    async def send(pkt, label=None):
        try: await loop.sock_sendall(sock, pkt)
        except OSError as e: warn(f"send: {e}"); return False
        if label: print(f"  -> {label:<40} ({len(pkt):>4} B)")
        return True

    def note_order(h):
        oid = h.get("orderId")
        if oid is None or h["cmd"] == 2: return
        st["recv_orders"].add(oid)
        while st["ack_next"] in st["recv_orders"]: st["ack_next"] += 1

    def _mark_joined():
        if st["joined"].is_set(): return
        st["joined"].set(); st["t_join"] = time.time()
        ok(f"★ JOINED · {match_label} ★")
        if on_join:
            try: on_join()
            except Exception as e: warn(f"on_join: {e}")

    async def handle(pkt, label=""):
        h = decode_header(pkt, key, mask)
        if not h: return None
        cmd, oid = h["cmd"], h.get("orderId")
        st["last_rx"] = time.time()
        print(f"  < [{time.time()-st['t0']:6.2f}s] cmd={cmd:<5}({cmd_name(cmd):<12}) "
              f"flags={h['flags']} order={oid} len={h['length']:>4} {label}")
        dup = oid is not None and cmd != 2 and oid in st["recv_orders"]
        note_order(h)
        if oid is not None and cmd != 2 and (h.get("sendOption") == 2 or (h["flags"] & 1)):
            if st["ack_next"] > st["ack_sent"] or dup:
                st["ack_sent"] = st["ack_next"]
                await send(pkt_ack(st["ack_next"], key, mask, "regular"))
        if cmd == 100:
            st["n100"] += 1
            if st["n100"] == 3:
                warn("server repeating cmd 100 → 448 rejected")
        elif cmd in (99, 176, 849):
            _mark_joined()
        elif cmd == 1:
            await send(pkt_ack(1, key, mask, "short"))
        elif cmd == 2001:
            sp = _parse_server_pos(h, pkt, key)
            if sp and not st["spawn_known"].is_set():
                st["spawn"] = dict(sp)
                st["entity"] = (sp["team"] << 24) | sp["slot"]
                st["spawn_known"].set()
                info(f"spawn team={sp['team']} slot={sp['slot']} "
                     f"x={sp['x']} y={sp['y']} z={sp['z']}")
                _mark_joined()
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
            try: pkt = await asyncio.wait_for(st["recv_q"].get(), timeout=0.2)
            except asyncio.TimeoutError: continue
            try: await handle(pkt, label="(bg)")
            except Exception as e: warn(f"handle: {e}")

    async def handshake(pkt, label, expect, name, timeout=HANDSHAKE_STEP_DELAY):
        start = time.time(); await send(pkt, label)
        while True:
            rem = timeout - (time.time() - start)
            if rem <= 0: break
            try: got = await asyncio.wait_for(st["recv_q"].get(), timeout=min(0.3, rem))
            except asyncio.TimeoutError: continue
            cmd = await handle(got, label=f"({name})")
            if cmd in expect:
                ok(f"  OK cmd={cmd} in {time.time()-start:.2f}s"); return True
        warn(f"  XX {name}: no reply"); return False

    recv_task = asyncio.create_task(recv_loop())
    consume_task = ping_task = None

    try:
        if not await handshake(hello, f"HELLO suffix={suffix}", {1, 2, 11}, "HELLO"):
            return False
        if not await handshake(a447, "AUTH#1", {2}, "447"): return False
        if not await handshake(a448, "AUTH#2", {2, 99, 100, 176, 849, 2001}, "448"):
            warn("AUTH#2 no reply — continuing")

        consume_task = asyncio.create_task(consume())

        try:
            await asyncio.wait_for(st["joined"].wait(), timeout=15.0)
        except asyncio.TimeoutError:
            warn(f"{match_label}: no join within 15 s — keeping session anyway")
            if on_join:
                try: on_join()
                except Exception: pass

        async def ping_loop():
            ping_t0 = time.time()
            while not st["stop_bg"].is_set():
                el_ms = int((time.time() - ping_t0) * 1000)
                tick  = (PING_TICK_BASE - 2 * el_ms) & 0xFFFFFFFF
                try: await loop.sock_sendall(sock, pkt_ping(tick, key, mask))
                except OSError as e: warn(f"ping: {e}"); break
                await asyncio.sleep(PING_INTERVAL)

        if PING_ENABLED:
            ping_task = asyncio.create_task(ping_loop())

        # ── keep-alive / idle / duration watchdog ───────────────
        while not st["stop_bg"].is_set():
            await asyncio.sleep(0.5)
            if not st["joined"].is_set(): continue
            if duration > 0:
                if time.time() - st["t_join"] >= duration:
                    ok(f"{match_label}: duration {duration:.0f}s reached"); break
            else:
                if time.time() - st["last_rx"] > MATCH_IDLE_TIMEOUT:
                    ok(f"{match_label}: idle timeout {MATCH_IDLE_TIMEOUT:.0f}s"); break

        return st["joined"].is_set()
    finally:
        st["stop_bg"].set(); st["stop_recv"].set()
        for t in (recv_task, consume_task, ping_task):
            if t:
                try: t.cancel()
                except Exception: pass
        try: sock.close()
        except Exception: pass


# ── one match = TCP auth + 0314 + 0300 + spawn UDP ─────────────
async def run_one_match(gld, jwt, sk, siv, acc_id, kts, ms_plain,
                        server_override, mode_override,
                        cycle_interval, duration, match_label=""):
    hdr(f"TCP · auth + 0314 + 0300   ({match_label})")
    writer = fr = None
    stop_hb = asyncio.Event()
    hb_task = udp_task = None
    joined_evt = asyncio.Event()

    try:
        try:
            writer, fr = await tcp_open_and_auth(
                gld["online"], sk, siv, jwt, acc_id, kts, gld["region"], ms_plain)
        except Exception as e:
            warn(f"tcp_open_and_auth raised: {e}"); return None, False
        if writer is None:
            warn("TCP auth failed"); return None, False
        ok("TCP authed + 0314 sent")

        hb_task = asyncio.create_task(
            tcp_heartbeat_loop(writer, sk, siv, stop_hb, TCP_HEARTBEAT_INTERVAL))
        ok("TCP 0e14 heartbeat started")

        found = await tcp_wait_for_0300(writer, fr, sk, siv)
        if not found:
            warn("no 0300 received"); return None, False
        ok(f"0300 received · server={found['server']}  mask={found['mask']}")

        if server_override:
            found["server"] = server_override
            warn(f"--server override → {server_override}")

        host, port = parse_addr(found["server"])
        if is_placeholder_host(host):
            if not server_override:
                err(f"placeholder host {host!r}"); return None, False
            host, port = parse_addr(server_override)
        if not port: port = 10018

        def _on_join():
            info(f"{match_label}: JOINED — stopping TCP heartbeat, UDP ping continues")
            stop_hb.set()
            joined_evt.set()

        udp_task = asyncio.create_task(udp_session(
            host=host, port=port,
            key_hex=found["udp_key"], token=found["token"],
            player_id=int(acc_id), match_id=int(found["match_id"]),
            mask=found["mask"],
            extra448=found.get("extra448"),
            mode_override=mode_override,
            on_join=_on_join, duration=duration,
            match_label=match_label))

        try:
            await asyncio.wait_for(joined_evt.wait(), timeout=UDP_WAIT_JOIN + 30)
            ok(f"{match_label}: JOINED")
        except asyncio.TimeoutError:
            warn(f"{match_label}: join timeout ({UDP_WAIT_JOIN + 30:.0f}s)")

        info(f"{match_label}: waiting {cycle_interval:.1f}s before sending next 0314")
        await asyncio.sleep(cycle_interval)
        return udp_task, joined_evt.is_set()
    finally:
        stop_hb.set()
        if hb_task:
            try: await asyncio.wait_for(hb_task, timeout=2.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                try: hb_task.cancel()
                except Exception: pass
        if writer:
            try:
                writer.close(); await writer.wait_closed()
            except Exception: pass
            info(f"{match_label}: TCP closed (UDP keeps running)")


# ── master loop ────────────────────────────────────────────────
async def amain(uid, password, *, num_matches=0,
                cycle_interval=MATCH_CYCLE_INTERVAL,
                duration=0.0, server_override="", mode_override=None,
                max_parallel=MAX_PARALLEL_MATCHES):
    hdr("Multi-match cycle")
    print(f"  UID           : {uid}")
    print(f"  matches       : {'∞' if num_matches == 0 else num_matches}")
    print(f"  cycle interval: {cycle_interval:.1f}s after join")
    print(f"  per-match dur : {'idle-timeout (15 s)' if duration == 0 else f'{duration:.0f}s'}")
    print(f"  max parallel  : {max_parallel}")

    hdr("Login (once)")
    oid, at = oauth(uid, password); ok("OAuth OK")
    jwt, sk, siv, acc_id, kts = major_login(oid, at, "4")
    ok(f"JWT: {jwt[:40]}…  ({len(jwt)} chars)")
    ok(f"account={acc_id}  server_time={kts}")
    gld = get_login_data(jwt, oid, "4")
    ok(f"region={gld['region']}  nickname={gld['nickname']}")
    ok(f"online={gld['online']}")

    ms_plain = patch_account_id(MATCH_START_DECRYPTED_HEX, str(acc_id))
    info(f"0314 plaintext: {len(ms_plain)} bytes")

    match_no = joined_count = 0
    active_udp = []

    try:
        while num_matches == 0 or match_no < num_matches:
            active_udp = [t for t in active_udp if not t.done()]

            while max_parallel and len(active_udp) >= max_parallel:
                info(f"at capacity {len(active_udp)}/{max_parallel} — waiting for slot")
                await asyncio.wait(active_udp,
                                   return_when=asyncio.FIRST_COMPLETED, timeout=60)
                active_udp = [t for t in active_udp if not t.done()]

            match_no += 1
            label = f"MATCH #{match_no}" + (f"/{num_matches}" if num_matches else "")
            try:
                udp_task, joined = await run_one_match(
                    gld, jwt, sk, siv, acc_id, kts, ms_plain,
                    server_override, mode_override,
                    cycle_interval, duration, match_label=label)
                if udp_task is not None:
                    active_udp.append(udp_task)
                if joined: joined_count += 1
            except (KeyboardInterrupt, asyncio.CancelledError):
                raise
            except Exception as e:
                warn(f"{label}: error — {type(e).__name__}: {e}")
                await asyncio.sleep(cycle_interval)

        remaining = [t for t in active_udp if not t.done()]
        if remaining:
            info(f"waiting for {len(remaining)} live UDP session(s)…")
            await asyncio.gather(*remaining, return_exceptions=True)
    except (KeyboardInterrupt, asyncio.CancelledError):
        info("cancelling all UDP sessions")
        for t in active_udp:
            if not t.done(): t.cancel()
        if active_udp:
            await asyncio.gather(*active_udp, return_exceptions=True)
        raise
    finally:
        ok(f"done — joined {joined_count}/{match_no} matches")


# ── CLI ───────────────────────────────────────────────────────
def _prompt():
    print("\n" + "=" * 60)
    print("  Lw_Head — Multi-Match Cycle (3s wait after join)")
    print("=" * 60)
    uid = input("UID       : ").strip().replace(" ", "")
    if not uid: sys.exit(1)
    pw = input("Password  : ").strip().replace(" ", "")
    if not pw: sys.exit(1)
    return uid, pw


def _parse_args():
    import argparse
    ap = argparse.ArgumentParser(
        description="Multi-match cycle: after joining, wait N seconds and start a new match")
    ap.add_argument("--server", default="", help="force UDP ip:port")
    ap.add_argument("--matches", type=int, default=0, help="0 = forever")
    ap.add_argument("--cycle-interval", type=float, default=MATCH_CYCLE_INTERVAL,
                    help=f"wait this many seconds after join, then start next match "
                         f"(default {MATCH_CYCLE_INTERVAL})")
    ap.add_argument("--duration", type=float, default=0.0,
                    help="lifetime of each UDP session in seconds (0 = idle-timeout 15 s)")
    ap.add_argument("--max-parallel", type=int, default=MAX_PARALLEL_MATCHES,
                    help=f"max concurrent UDP sessions (default {MAX_PARALLEL_MATCHES})")
    ap.add_argument("--mode", default=None, help="override cmd-448 mode id")
    return ap.parse_args()


def main():
    args = _parse_args()
    mode_override = None
    if args.mode is not None:
        try: mode_override = int(args.mode, 0) & 0xFF
        except ValueError: pass

    uid, pw = _prompt()
    try:
        asyncio.run(amain(
            uid=uid, password=pw,
            num_matches=args.matches,
            cycle_interval=args.cycle_interval,
            duration=args.duration,
            server_override=args.server.strip(),
            mode_override=mode_override,
            max_parallel=args.max_parallel,
        ))
    except KeyboardInterrupt:
        print("\nstopped (Ctrl-C)")


if __name__ == "__main__":
    main()
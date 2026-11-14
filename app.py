import os, re, time, json, hashlib, hmac, secrets, mimetypes, base64, threading, queue, sqlite3, socket, ipaddress
from concurrent.futures import ThreadPoolExecutor
from collections import OrderedDict
from contextlib import contextmanager
from html.parser import HTMLParser
from urllib.parse import quote, unquote, urlparse, urljoin
import requests
from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from itsdangerous import URLSafeTimedSerializer
from flask import (Flask, g, request, session, redirect, flash, get_flashed_messages,
                   render_template_string, Response, jsonify)

# ---- config (same Bunny API conventions as Bunny Interactive) ----
API = os.environ.get("BUNNY_API", "https://cutebunny.io").rstrip("/")
H_LOGIN = "Login-Content"
H_FILENAME = "File-Name"
HWID_SALT = os.environ.get("HWID_SALT", "change-me")  # must equal the salt used by Bunny Interactive
VERIFY = os.environ.get("VERIFY_TLS", "1") == "1"
DATA_DIR = os.environ.get("DATA_DIR", "/data")
AUTOWIPE_HOURS = float(os.environ.get("AUTOWIPE_HOURS", "48"))  # 0 disables the idle auto-wipe
JANITOR_SECONDS = int(os.environ.get("JANITOR_SECONDS", "300"))
VAPID_SUBJECT = os.environ.get("VAPID_SUBJECT", API)
KEYFILE = ".bunnyc"
MAX_TEXT = 4000
MAX_ATT = 10
WIPE_LOCK = 5  # seconds nobody can write after a wipe
GIPHY_KEY = os.environ.get("GIPHY_API_KEY", "").strip()  # GIF picker is off without it
GIPHY_RATING = os.environ.get("GIPHY_RATING", "pg-13").strip().lower()  # also used for Klipy
if GIPHY_RATING not in ("g", "pg", "pg-13", "r"):
    GIPHY_RATING = "pg-13"
KLIPY_KEY = os.environ.get("KLIPY_API_KEY", "").strip()  # optional; either, both or no GIF key may be set
KLIPY_URL = re.compile(r"https://static\.klipy\.com/[A-Za-z0-9/_.\-]{1,200}\.(?:webp|gif)")
SSE_MAX_AGE = int(os.environ.get("SSE_MAX_AGE", "300"))  # live streams are renewed this often (frees dead connections)


def hwid(email):  # 64 alphanumeric chars, stable per email
    return hashlib.sha256((HWID_SALT + email.lower()).encode()).hexdigest().upper()


app = Flask(__name__)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_NAME"] = "bunnychat_session"  # cookies are shared across ports: don't clash with Interactive
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)


class AuthError(Exception):  # not signed in / Bunny rejected the credentials
    pass


class BunnyError(Exception):  # Bunny unreachable or failing: the user stays signed in
    pass


def reason(r):
    try:
        try:
            j = r.json()
            if isinstance(j, dict):
                return next((str(v) for k, v in j.items() if k.lower() == "reason"), str(j))
        except ValueError:
            pass
        return r.text or f"HTTP {r.status_code}"
    except Exception:
        r.close()
        return f"Server error (HTTP {r.status_code})"


# ---- Bunny sessions ----
# One Bunny session per ACCOUNT, shared by every browser/device of that account. Several devices logging in as
# the same account would otherwise invalidate each other's token and log each other out.
SESS = {}  # browser session id -> {email, name, last, chk, stay}
POOL = {}  # account email -> {token, ext, creds, lock}
IDLE = 24 * 3600  # browser sessions without "stay signed in" end after 24h unused
_login_lock = threading.Lock()


def bunny_login(creds):
    body = {"license": creds["license"], "hwid": hwid(creds["email"]), "email": creds["email"], "password": creds["password"]}
    return requests.get(f"{API}/api/license/login", headers={H_LOGIN: json.dumps(body)}, verify=VERIFY, timeout=30)


def token_of(r):
    try:
        t = r.json().get("session")
    except ValueError:
        t = None
    if not t:
        raise BunnyError("No session in response: " + r.text[:200])
    return t


def pool_set(creds, token):
    key = creds["email"].lower()
    p = POOL.get(key)
    if p:
        p.update(token=token, ext=time.time(), creds=creds)
    else:
        POOL[key] = {"token": token, "ext": time.time(), "creds": creds, "lock": threading.Lock()}


def pool_token(email, bad=None, verify=False):
    """Valid token of this account. Extends it every 20 min and re-logs in when Bunny dropped it.
    AuthError only when Bunny rejects the stored credentials; `bad` = a token that just failed."""
    key = email.lower()
    p = POOL.get(key)
    if not p:
        raise AuthError
    with p["lock"]:
        if bad and p["token"] != bad:
            return p["token"]  # another request already refreshed it
        if not bad and not verify and time.time() - p["ext"] < 20 * 60:
            return p["token"]
        if not bad:
            try:
                e = requests.post(f"{API}/api/license/extend", headers={"Auth-Token": p["token"]}, timeout=30, verify=VERIFY)
            except requests.RequestException:
                raise BunnyError("The Bunny server is not reachable")
            if e.ok:
                p["ext"] = time.time()
                return p["token"]
        try:
            r = bunny_login(p["creds"])
        except requests.RequestException:
            raise BunnyError("The Bunny server is not reachable")
        if r.ok:
            p["token"], p["ext"] = token_of(r), time.time()
            return p["token"]
        if r.status_code >= 500:
            raise BunnyError(reason(r))
        POOL.pop(key, None)
        raise AuthError


def new_session(email, stay=False):
    sid = secrets.token_hex(16)
    now = time.time()
    SESS[sid] = {"email": email.lower(), "name": email.split("@")[0][:32], "last": now, "chk": now, "stay": stay}
    session["sid"] = sid
    return sid


def release(sid):
    s = SESS.pop(sid, None)
    if s and not any(x["email"] == s["email"] for x in SESS.values()):
        POOL.pop(s["email"], None)  # last browser of this account left: forget its Bunny session


def drop():
    release(session.pop("sid", None))


def remember(resp, creds):  # license + email only; the password stays with the browser's password manager
    for k, v in (("bc_lic", creds["license"]), ("bc_em", creds["email"])):
        resp.set_cookie(k, v, max_age=365 * 86400, httponly=True, samesite="Lax")
    return resp


# ---- "stay signed in": credentials kept encrypted on the server, looked up via a random cookie token ----
STAY_DAYS = 90
_store_lock = threading.Lock()
_fernet = None
AUTO = {}  # sha256(rt token) -> sid of the session auto-login created


def fernet():
    global _fernet
    if _fernet is None:
        key = os.environ.get("REMEMBER_KEY", "").encode()
        if not key:
            os.makedirs(DATA_DIR, exist_ok=True)
            path = os.path.join(DATA_DIR, "remember.key")
            if not os.path.exists(path):
                with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
                    f.write(Fernet.generate_key())
            key = open(path, "rb").read()
        _fernet = Fernet(key)
    return _fernet


def _h(tok):
    return hashlib.sha256(tok.encode()).hexdigest()


def _load():
    try:
        with open(os.path.join(DATA_DIR, "remember.json")) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save(d):
    os.makedirs(DATA_DIR, exist_ok=True)
    path = os.path.join(DATA_DIR, "remember.json")
    with open(path + ".tmp", "w") as f:
        json.dump(d, f)
    os.replace(path + ".tmp", path)


def stay_save(creds):
    tok, now = secrets.token_urlsafe(32), time.time()
    with _store_lock:
        d = {k: v for k, v in _load().items() if v["exp"] > now}
        d[_h(tok)] = {"exp": now + STAY_DAYS * 86400, "c": fernet().encrypt(json.dumps(creds).encode()).decode()}
        _save(d)
    return tok


def stay_get(tok):
    entry = _load().get(_h(tok)) if tok else None
    if not entry or entry["exp"] < time.time():
        return None
    try:
        return json.loads(fernet().decrypt(entry["c"].encode()))
    except InvalidToken:
        return None


def stay_forget(tok):
    if not tok:
        return
    AUTO.pop(_h(tok), None)
    with _store_lock:
        d = _load()
        if d.pop(_h(tok), None):
            _save(d)


def auto_login(bad_sid=None):
    """New browser session from this browser's 'bc_rt' cookie (stored credentials); None if not possible."""
    tok = request.cookies.get("bc_rt")
    creds = stay_get(tok)
    if not creds:
        return None
    h = _h(tok)
    with _login_lock:
        sid = AUTO.get(h)
        if sid in SESS and sid != bad_sid:  # another request already created it
            session["sid"] = sid
            return SESS[sid]
        release(bad_sid)
        try:
            try:
                pool_token(creds["email"])  # the account already has a live Bunny session
            except (AuthError, BunnyError):
                r = bunny_login(creds)
                if not r.ok:
                    return None
                pool_set(creds, token_of(r))
        except Exception:
            return None
        AUTO[h] = new_session(creds["email"], stay=True)
    touch_activity()
    return SESS[AUTO[h]]


def auth():
    """The signed-in browser session, or None."""
    sid = session.get("sid")
    s = SESS.get(sid)
    now = time.time()
    if s and not s["stay"] and now - s["last"] > IDLE:
        release(sid)
        s = None
    if not s:
        s = auto_login(sid)
    if s and now - s["chk"] > 20 * 60:  # now and then check the account still works
        try:
            pool_token(s["email"])
            s["chk"] = now
        except AuthError:
            drop()
            return None
        except BunnyError:
            pass
    if s:
        s["last"] = now
    return s


def api(method, path, **kw):
    s = auth()
    if not s:
        raise AuthError
    headers = kw.pop("headers", {})
    timeout = kw.pop("timeout", 30)
    replay = not hasattr(kw.get("data"), "__next__")  # a streamed body can't be sent twice
    tok = pool_token(s["email"], verify=not replay)  # check right before a big upload starts
    for attempt in (0, 1):
        r = requests.request(method, f"{API}{path}", headers={"Auth-Token": tok, **headers},
                             timeout=timeout, verify=VERIFY, **kw)
        if r.status_code not in (401, 403):
            return r
        r.close()
        tok = pool_token(s["email"], bad=tok)
        if not replay or attempt:
            break
    raise BunnyError("Bunny rejected the request, please try again")


def upload_bytes(name, content):
    boundary = secrets.token_hex(16)
    head = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"; '
            f"filename*=UTF-8''{quote(name)}\r\nContent-Type: application/octet-stream\r\n\r\n").encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    return api("POST", "/api/upload", data=head + content + tail, timeout=(30, 120), headers={
        "File-Size": str(len(content)), "Content-Type": f"multipart/form-data; boundary={boundary}"})


# ---- crypto: blanket AES key (from .bunnyc on the Bunny server) + one random AES key per message ----
def seal(key, data):
    n = os.urandom(12)
    return n + AESGCM(key).encrypt(n, data, None)


def unseal(key, blob):
    return AESGCM(key).decrypt(blob[:12], blob[12:], None)


_master = None
_mlock = threading.Lock()


def master():
    """The blanket key. Derived from the seed stored in .bunnyc (created on first use), cached in memory."""
    global _master
    if _master:
        return _master
    with _mlock:
        if _master:
            return _master
        if meta_get("pending"):  # an auto-wipe left Bunny-side clean-up to do (media files + old key file)
            try:
                remote_cleanup(lambda n: api("GET", "/api/delete", headers={H_FILENAME: n}).status_code)
            except (BunnyError, requests.RequestException):
                pass
        r = api("GET", "/api/read")
        if not r.ok:
            raise RuntimeError(reason(r))
        have = any(str(next((v for k, v in d.items() if k.lower() == "filename"), "")) == KEYFILE for d in r.json())
        if not have:
            r = upload_bytes(KEYFILE, base64.b64encode(os.urandom(32)))
            if not r.ok:
                raise RuntimeError(reason(r))
        r = api("GET", "/api/download", headers={H_FILENAME: KEYFILE})
        if not r.ok:
            raise RuntimeError(reason(r))
        seed = r.content.strip()
        if len(seed) < 16:
            raise RuntimeError(f"{KEYFILE} on the server is empty or too short")
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"bunnychat/blanket/v1").derive(seed)
        check_db(key)
        _master = key
        return key


def uid_of(email):  # stable pseudonymous id of a sender, used for "own message" / delete permission
    return hmac.new(master(), email.lower().encode(), hashlib.sha256).hexdigest()[:16]


# ---- database ----
DB_PATH = os.path.join(DATA_DIR, "chat.db")


@contextmanager
def conn():
    c = sqlite3.connect(DB_PATH, timeout=15)
    c.execute("PRAGMA secure_delete=ON")  # deleted rows are zeroed, not just unlinked
    try:
        with c:
            yield c
    finally:
        c.close()


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=15)
    c.execute("PRAGMA journal_mode=WAL")
    c.executescript("""
        CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
            uid TEXT NOT NULL, mkey BLOB NOT NULL, body BLOB NOT NULL);
        CREATE TABLE IF NOT EXISTS media(ref TEXT PRIMARY KEY, msg_id INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS media_msg ON media(msg_id);
        CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v BLOB NOT NULL);
        CREATE TABLE IF NOT EXISTS nicks(uid TEXT PRIMARY KEY, nick BLOB NOT NULL);
        CREATE TABLE IF NOT EXISTS hearts(msg_id INTEGER NOT NULL, uid TEXT NOT NULL, PRIMARY KEY(msg_id, uid));
        CREATE TABLE IF NOT EXISTS push(eid TEXT PRIMARY KEY, uid TEXT NOT NULL, sub BLOB NOT NULL);""")
    c.execute("INSERT OR IGNORE INTO meta VALUES('activity', ?)", (str(int(time.time())).encode(),))
    c.commit()
    c.close()


def meta_get(k):
    with conn() as c:
        row = c.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
    return bytes(row[0]).decode() if row else None


def meta_set(k, v):
    with conn() as c:
        c.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (k, str(v).encode()))


def meta_del(k):
    with conn() as c:
        c.execute("DELETE FROM meta WHERE k=?", (k,))


def check_db(key):
    with conn() as c:
        row = c.execute("SELECT v FROM meta WHERE k='check'").fetchone()
        if row:
            try:
                unseal(key, bytes(row[0]))
            except InvalidTag:
                raise RuntimeError(f"The key in {KEYFILE} does not match the existing chat database.")
        else:
            c.execute("INSERT INTO meta VALUES('check', ?)", (seal(key, b"bunnychat"),))


def wipe_db():
    """Rewrite the database file so nothing of the deleted rows is left in free pages or the WAL."""
    c = sqlite3.connect(DB_PATH, timeout=30)
    try:
        c.execute("PRAGMA secure_delete=ON")
        c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        c.execute("VACUUM")
        c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        c.close()


def wipe_checkpoint():
    c = sqlite3.connect(DB_PATH, timeout=15)
    try:
        c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        c.close()


def nick_map(m):  # uid -> nickname (stored encrypted with the blanket key)
    out = {}
    with conn() as c:
        for uid, blob in c.execute("SELECT uid, nick FROM nicks"):
            try:
                out[uid] = unseal(m, blob).decode()
            except (InvalidTag, UnicodeDecodeError):
                pass
    return out


COLS = "id,ts,uid,mkey,body"


def open_row(m, row, nk):
    id_, ts, uid, mkey, body = row
    try:
        p = json.loads(unseal(unseal(m, mkey), unseal(m, body)))
    except (InvalidTag, ValueError):
        return None
    return {"id": id_, "ts": ts, "u": uid, "s": nk.get(uid) or p.get("s", ""), "t": p.get("t", ""),
            "a": p.get("a", []), "r": p.get("r"), "g": p.get("g")}


def quote_of(m, rid, nk):
    """What a reply shows of its original, resolved when read: a deleted original leaves nothing behind."""
    with conn() as c:
        row = c.execute(f"SELECT {COLS} FROM messages WHERE id=?", (rid,)).fetchone()
    o = open_row(m, row, nk) if row else None
    if not o:
        return {"id": rid, "gone": True}
    t = o["t"].strip()
    if len(t) > 140:
        t = t[:140].rstrip() + "…"
    a = o["a"][0] if o["a"] else {}
    return {"id": rid, "s": o["s"], "u": o["u"], "t": t, "k": a.get("k", "") or ("gif" if o.get("g") else ""), "n": a.get("n", "")}


def decode_rows(m, rows, nk):
    items = [x for x in (open_row(m, r, nk) for r in rows) if x]
    hs = {}
    if items:
        with conn() as c:
            ids = [x["id"] for x in items]
            for i in range(0, len(ids), 500):
                part = ids[i:i + 500]
                for mid, uid in c.execute(f"SELECT msg_id, uid FROM hearts WHERE msg_id IN ({','.join('?' * len(part))}) ORDER BY rowid", part):
                    hs.setdefault(mid, []).append(uid)
    for x in items:
        x["h"] = hs.get(x["id"], [])
        rid = x.pop("r", None)
        if rid:
            x["q"] = quote_of(m, rid, nk)
    return items


init_db()

# ---- live updates (server-sent events) ----
SUBS = {}  # queue -> {uid, cid, visible}
_slock = threading.Lock()
WIPE_UNTIL = 0.0


def publish(ev):
    with _slock:
        subs = list(SUBS)
    for q in subs:
        try:
            q.put_nowait(ev)
        except queue.Full:  # slow client: dropped, it re-syncs when it reconnects
            with _slock:
                SUBS.pop(q, None)


def alive(sid):
    s = SESS.get(sid)
    if not s:
        return False
    s["last"] = time.time()  # an open chat page counts as use
    try:
        pool_token(s["email"])
    except AuthError:
        release(sid)
        return False
    except BunnyError:
        pass
    return True


# ---- activity, idle auto-wipe ----
_last_touch = 0.0
_wipe_lock = threading.Lock()


def touch_activity(force=False):
    global _last_touch
    now = time.time()
    if force or now - _last_touch > 60:
        _last_touch = now
        try:
            meta_set("activity", int(now))
        except Exception:
            pass


def remote_cleanup(delete):
    """Delete what the auto-wipe left on the Bunny server (media + the key file). delete(name) -> HTTP status."""
    refs = json.loads(meta_get("orphans") or "[]")
    for name in refs + [KEYFILE]:
        if delete(name) in (401, 403):
            return False
    meta_del("orphans")
    meta_del("pending")
    return True


def autowipe_check():
    global _master
    if AUTOWIPE_HOURS <= 0:
        return
    with _slock:
        live = bool(SUBS)
    if live:  # somebody has the chat open
        touch_activity(True)
        return
    last = meta_get("activity") or str(int(time.time()))
    if time.time() - int(last) < AUTOWIPE_HOURS * 3600 or meta_get("idle_done") == last:
        return
    with _wipe_lock:
        with conn() as c:
            refs = [r for (r,) in c.execute("SELECT ref FROM media")]
            old = json.loads(meta_get("orphans") or "[]")
            for t in ("media", "hearts", "messages", "nicks", "push"):
                c.execute(f"DELETE FROM {t}")
            c.execute("DELETE FROM meta WHERE k='check'")
            for k, v in (("orphans", json.dumps(old + refs)), ("pending", "1"), ("idle_done", last)):
                c.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (k, v.encode()))
        wipe_db()
        pv_clear()
        _master = None  # the key file goes too: a new one is created at the next login


def janitor_remote():
    if not meta_get("pending"):
        return
    tok = next((p["token"] for p in list(POOL.values())), None)
    if not tok:  # nobody online: use a stay-signed-in credential to reach the Bunny server
        for entry in list(_load().values()):
            try:
                creds = json.loads(fernet().decrypt(entry["c"].encode()))
                r = bunny_login(creds)
                if r.ok:
                    tok = token_of(r)
                    break
            except Exception:
                continue
    if tok:
        remote_cleanup(lambda n: requests.get(f"{API}/api/delete", headers={"Auth-Token": tok, H_FILENAME: n},
                                              timeout=30, verify=VERIFY).status_code)


def janitor():
    while True:
        time.sleep(JANITOR_SECONDS)
        try:
            autowipe_check()
            janitor_remote()
        except Exception:
            pass


# ---- web push (RFC 8030 / 8291 / 8292) ----
_vapid = None
_vlock = threading.Lock()
PUSH_HOSTS = ("googleapis.com", "mozilla.com", "push.apple.com", "notify.windows.com")
PUSHPOOL = ThreadPoolExecutor(max_workers=6)


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def vapid():
    global _vapid
    with _vlock:
        if _vapid is None:
            path = os.path.join(DATA_DIR, "vapid.pem")
            if not os.path.exists(path):
                pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
                with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
                    f.write(pem)
            key = serialization.load_pem_private_key(open(path, "rb").read(), None)
            pub = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            _vapid = (key, b64u(pub))
        return _vapid


def vapid_jwt(aud):
    key, _ = vapid()
    j = lambda d: b64u(json.dumps(d, separators=(",", ":")).encode())
    msg = f'{j({"typ": "JWT", "alg": "ES256"})}.{j({"aud": aud, "exp": int(time.time()) + 12 * 3600, "sub": VAPID_SUBJECT})}'
    r, s = asym_utils.decode_dss_signature(key.sign(msg.encode(), ec.ECDSA(hashes.SHA256())))
    return f"{msg}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def push_encrypt(sub, payload, as_priv=None, salt=None):  # aes128gcm content coding, RFC 8291
    ua_pub, auth_secret = unb64u(sub["keys"]["p256dh"]), unb64u(sub["keys"]["auth"])
    as_priv = as_priv or ec.generate_private_key(ec.SECP256R1())
    as_pub = as_priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    secret = as_priv.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_pub))
    salt = salt or os.urandom(16)
    ikm = HKDF(algorithm=hashes.SHA256(), length=32, salt=auth_secret, info=b"WebPush: info\0" + ua_pub + as_pub).derive(secret)
    cek = HKDF(algorithm=hashes.SHA256(), length=16, salt=salt, info=b"Content-Encoding: aes128gcm\0").derive(ikm)
    nonce = HKDF(algorithm=hashes.SHA256(), length=12, salt=salt, info=b"Content-Encoding: nonce\0").derive(ikm)
    return salt + (4096).to_bytes(4, "big") + bytes([len(as_pub)]) + as_pub + AESGCM(cek).encrypt(nonce, payload + b"\x02", None)


def push_ok_endpoint(url):
    u = urlparse(url)
    h = (u.hostname or "").lower()
    return u.scheme == "https" and any(h == d or h.endswith("." + d) for d in PUSH_HOSTS)


def push_send(sub, payload):
    u = urlparse(sub["endpoint"])
    r = requests.post(sub["endpoint"], data=push_encrypt(sub, payload), timeout=15, headers={
        "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", "TTL": "3600", "Urgency": "normal",
        "Authorization": f"vapid t={vapid_jwt(f'{u.scheme}://{u.netloc}')}, k={vapid()[1]}"})
    return r.status_code


def notify(sender_uid, name, atts, text, gif=False):
    """Push to every subscribed device of users who are not looking at the chat right now. Runs in a worker thread."""
    m = _master
    if not m:
        return
    with _slock:
        here = {i["uid"] for i in SUBS.values() if i["visible"]}
    with conn() as c:
        rows = c.execute("SELECT eid, uid, sub FROM push").fetchall()
    what = "sent a message"
    if gif and not text and not atts:
        what = "sent a GIF"
    elif atts and not text:
        what = {"image": "sent a photo", "video": "sent a video", "audio": "sent an audio file"}.get(atts[0]["k"], "sent a file")
    payload = json.dumps({"title": "Bunny Tale", "body": f"{name} {what}"}).encode()
    for eid, uid, blob in rows:
        if uid == sender_uid or uid in here:
            continue
        try:
            sub = json.loads(unseal(m, bytes(blob)))
            if push_send(sub, payload) in (404, 410):  # subscription is gone
                with conn() as c:
                    c.execute("DELETE FROM push WHERE eid=?", (eid,))
        except Exception:
            continue


# ---- link previews: fetched by the server, thumbnails proxied, kept in memory only (never on disk) ----
PV_UA = "Mozilla/5.0 (compatible; BunnyChatLinkPreview/1.0)"
PV_TTL, PV_FAIL_TTL, IMG_TTL, IMG_MAX_TOTAL = 3600, 300, 4000, 60 * 1024 * 1024
_pv, _imgs = OrderedDict(), OrderedDict()
_pvlock = threading.Lock()
_img_total = 0
_stripes = [threading.Lock() for _ in range(32)]
YT_RE = re.compile(r"^https?://(?:www\.|m\.|music\.)?(?:youtube\.com/(?:watch\?(?:[^#]*&)?v=|shorts/|embed/|live/)|youtu\.be/)([\w-]{11})")
TT_RE = re.compile(r"^https?://(?:www\.|m\.)?tiktok\.com/@[\w.\-]+/video/(\d{6,25})")
IG_RE = re.compile(r"^https?://(?:www\.)?instagram\.com/(?:[\w.]+/)?(p|reel|reels|tv)/([\w-]{5,20})")
IMG_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif", "image/avif"}


def pv_get(url):
    with _pvlock:
        e = _pv.get(url)
        if e and e[0] > time.time():
            _pv.move_to_end(url)
            return e[1]
        _pv.pop(url, None)
    return None


def pv_put(url, data):
    with _pvlock:
        _pv[url] = (time.time() + (PV_TTL if data.get("ok") else PV_FAIL_TTL), data)
        while len(_pv) > 500:
            _pv.popitem(last=False)


def img_put(ctype, data):
    global _img_total
    tok = secrets.token_urlsafe(12)
    with _pvlock:
        _imgs[tok] = (time.time() + IMG_TTL, ctype, data)
        _img_total += len(data)
        while _imgs and (len(_imgs) > 200 or _img_total > IMG_MAX_TOTAL):
            _, v = _imgs.popitem(last=False)
            _img_total -= len(v[2])
    return tok


def img_get(tok):
    with _pvlock:
        e = _imgs.get(tok)
    return (e[1], e[2]) if e and e[0] > time.time() else None


def pv_clear():
    global _img_total
    with _pvlock:
        _pv.clear()
        _imgs.clear()
        _img_total = 0


def public_host(host):
    """True only if every address of the host is a normal public one (no loopback, LAN, link-local, ...)."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    for i in infos:
        ip = ipaddress.ip_address(i[4][0].split("%")[0])
        ip = getattr(ip, "ipv4_mapped", None) or ip
        if not ip.is_global:
            return False
    return bool(infos)


def safe_get(url, max_bytes, hdrs=None, hops=4):
    """GET a public web page/file: only http(s) on 80/443, every redirect hop re-checked, size and time capped."""
    for _ in range(hops + 1):
        u = urlparse(url)
        if u.scheme not in ("http", "https") or not u.hostname or u.port not in (None, 80, 443) or not public_host(u.hostname):
            raise ValueError("blocked")
        r = requests.get(url, headers={"User-Agent": PV_UA, "Accept-Language": "en", **(hdrs or {})},
                         timeout=(4, 6), allow_redirects=False, stream=True)
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location")
            r.close()
            if not loc:
                raise ValueError("bad redirect")
            url = urljoin(url, loc)
            continue
        body, t0 = b"", time.time()
        try:
            for chunk in r.iter_content(16384):
                body += chunk
                if len(body) >= max_bytes or time.time() - t0 > 10:
                    break
        finally:
            r.close()
        return url, r.status_code, r.headers, body
    raise ValueError("too many redirects")


class _Meta(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.m, self.title, self._t = {}, "", False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "meta":
            k, v = (a.get("property") or a.get("name") or "").lower(), a.get("content")
            if k and v and k not in self.m:
                self.m[k] = v
        elif tag == "title":
            self._t = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._t = False

    def handle_data(self, d):
        if self._t:
            self.title += d


def og_data(url):
    u, st, hd, body = safe_get(url, 400_000, {"Accept": "text/html,application/xhtml+xml"})
    if st != 200 or "html" not in hd.get("Content-Type", "").lower():
        return {}
    cs = re.search(r"charset=([\w-]+)", hd.get("Content-Type", ""), re.I)
    try:
        text = body.decode(cs[1] if cs else "utf-8", "replace")
    except LookupError:
        text = body.decode("utf-8", "replace")
    p = _Meta()
    try:
        p.feed(text)
    except Exception:
        pass
    g = lambda *ks: next((p.m[k].strip() for k in ks if p.m.get(k, "").strip()), "")
    img = g("og:image", "twitter:image", "twitter:image:src")
    return {"site": g("og:site_name") or (urlparse(u).hostname or "").removeprefix("www."),
            "title": g("og:title", "twitter:title") or p.title.strip(), "desc": g("og:description", "twitter:description", "description"),
            "img": urljoin(u, img) if img else None}


def oembed(endpoint, url):
    try:
        _, st, _, body = safe_get(f"{endpoint}?format=json&url={quote(url, safe='')}", 100_000)
        return json.loads(body) if st == 200 else None
    except Exception:
        return None


def build_preview(url):
    final = url
    if (urlparse(url).hostname or "").lower().endswith("tiktok.com") and not TT_RE.match(url):
        final = safe_get(url, 60_000)[0]  # short links: follow the redirects to the real video address
    out = {"ok": False, "site": "", "title": "", "desc": "", "img": None, "embed": None}
    img_url, y, tt, ig = None, YT_RE.match(final), TT_RE.match(final), IG_RE.match(final)
    if y:
        out.update(site="YouTube", title="YouTube video", embed={"k": "youtube", "src": f"https://www.youtube-nocookie.com/embed/{y[1]}?autoplay=1&rel=0"})
        img_url = f"https://i.ytimg.com/vi/{y[1]}/hqdefault.jpg"
        j = oembed("https://www.youtube.com/oembed", final)
        if j:
            out["title"], out["desc"] = j.get("title") or out["title"], j.get("author_name") or ""
            img_url = j.get("thumbnail_url") or img_url
    elif tt:
        out.update(site="TikTok", title="TikTok video", embed={"k": "tiktok", "src": f"https://www.tiktok.com/embed/v2/{tt[1]}"})
        img_url = None
        j = oembed("https://www.tiktok.com/oembed", final)
        if j:
            out["title"], out["desc"] = j.get("title") or out["title"], j.get("author_name") or ""
            img_url = j.get("thumbnail_url")
    elif ig:
        kind = {"reels": "reel"}.get(ig[1], ig[1])
        out.update(site="Instagram", title={"reel": "Instagram reel", "tv": "Instagram video"}.get(kind, "Instagram post"),
                   embed={"k": "instagram", "src": f"https://www.instagram.com/{kind}/{ig[2]}/embed/"})
        img_url = None
        try:  # Instagram usually answers with a login page; use its data only when it really describes the post
            d = og_data(final)
            if d.get("title") and d["title"].strip().lower() not in ("instagram", "login • instagram") and not d["title"].lower().startswith("login"):
                out["title"], out["desc"], img_url = d["title"], d.get("desc", ""), d.get("img")
        except Exception:
            pass
    else:
        img_url = None
        d = og_data(final)
        out.update(site=d.get("site", ""), title=d.get("title", ""), desc=d.get("desc", ""))
        img_url = d.get("img")
    if img_url:
        try:
            _, st, hd, body = safe_get(img_url, 2_500_000, {"Accept": "image/*"})
            ct = hd.get("Content-Type", "").split(";")[0].strip().lower()
            if st == 200 and ct in IMG_TYPES and 0 < len(body) < 2_500_000:
                out["img"] = "/preview/img/" + img_tok(ct, body)
        except Exception:
            pass
    out["title"], out["desc"] = out["title"][:200], out["desc"][:300]
    out["ok"] = bool(out["title"] or out["desc"] or out["img"] or out["embed"])
    return out


img_tok = img_put


@app.route("/preview")
def preview():
    if not auth():
        return "", 401
    url = request.args.get("u", "")[:2048]
    if not re.match(r"^https?://", url):
        return jsonify({"ok": False})
    got = pv_get(url)
    if got is None:
        with _stripes[hash(url) % len(_stripes)]:  # one fetch per link even when many people open it at once
            got = pv_get(url)
            if got is None:
                try:
                    got = build_preview(url)
                except Exception:
                    got = {"ok": False}
                pv_put(url, got)
    return jsonify(got)


@app.route("/preview/img/<tok>")
def preview_img(tok):
    if not auth():
        return "", 401
    e = img_get(tok)
    if not e:
        return "", 404
    return Response(e[1], mimetype=e[0], headers={"Cache-Control": "private, max-age=3600", "X-Content-Type-Options": "nosniff",
                                                  "Content-Security-Policy": "sandbox"})


# ---- helpers / UI ----
KINDS = {
    "image": "jpg jpeg png gif webp bmp avif svg",
    "video": "mp4 webm m4v mov ogv",
    "audio": "mp3 m4a aac ogg opus wav flac weba",
}
mimetypes.add_type("audio/webm", ".weba")  # voice messages recorded as audio-only WebM
MEDIA_PREFIX = ".bunnyc."  # lets file clients hide chat files; older "bc-..." names stay valid
MEDIA_RE = re.compile(r"^(?:\.bunnyc\.)?bc-[0-9a-f]{24}\.[a-z0-9]{1,8}$")


def kind_of(name):
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return next((k for k, v in KINDS.items() if ext in v.split()), "file")


ICONS = {
    "file": '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>',
    "bunny": '<ellipse cx="8.6" cy="6" rx="2.2" ry="4.2"/><ellipse cx="15.4" cy="6" rx="2.2" ry="4.2"/><ellipse cx="12" cy="15" rx="6.5" ry="5.5"/><path d="M9.5 14.5h.01M14.5 14.5h.01"/><path d="M10.8 17.4q1.2 1 2.4 0"/>',
    "trash": '<path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M10 11v6M14 11v6"/>',
    "x": '<path d="M18 6 6 18M6 6l12 12"/>',
    "image": '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="m21 15-5-5L5 21"/>',
    "mic": '<rect x="9" y="2" width="6" height="12" rx="3"/><path d="M5 11a7 7 0 0 0 14 0M12 18v4"/>',
    "stop": '<rect x="6" y="6" width="12" height="12" rx="2" fill="currentColor"/>',
    "clip": '<path d="m21.44 11.05-9.19 9.19a6 6 0 0 1-8.49-8.49l8.57-8.57A4 4 0 1 1 18 8.84l-8.59 8.57a2 2 0 0 1-2.83-2.83l8.49-8.48"/>',
    "send": '<path d="m22 2-7 20-4-9-9-4z"/><path d="M22 2 11 13"/>',
    "user": '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
    "down": '<path d="M12 5v14M19 12l-7 7-7-7"/>',
    "download": '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5M12 15V3"/>',
    "heart": '<path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/>',
    "reply": '<path d="M9 14 4 9l5-5"/><path d="M20 20v-7a4 4 0 0 0-4-4H4"/>',
    "sliders": '<path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6"/>',
    "chev": '<path d="m6 9 6 6 6-6"/>',
    "play": '<path d="M7 4.5v15l12-7.5z" fill="currentColor"/>',
    "bell": '<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>',
}
app.jinja_env.globals["logo"] = ICONS["bunny"]
app.jinja_env.globals["I"] = ICONS

LAYOUT = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1,viewport-fit=cover,interactive-widget=resizes-content">
<title>Bunny Tale</title><link rel=icon href="/favicon.ico?v={{iv}}"><link rel=manifest href="/manifest.webmanifest?v={{iv}}"><meta name=theme-color content="#09090b"><link rel=apple-touch-icon href="/icon-maskable.png?v={{iv}}"><meta name=apple-mobile-web-app-capable content=yes><style>
:root{--bg:#09090b;--card:#111113;--line:#1f1f23;--text:#e4e4e7;--mute:#71717a;--acc:#8b5cf6;color-scheme:dark}
*{box-sizing:border-box;scrollbar-width:thin;scrollbar-color:#2e2e34 transparent;-webkit-tap-highlight-color:transparent}
button,.btn,.acts,.hp{user-select:none;-webkit-user-select:none;-webkit-touch-callout:none}
button:focus:not(:focus-visible){outline:none}[hidden]{display:none!important}
::-webkit-scrollbar{width:10px;height:10px}::-webkit-scrollbar-track,::-webkit-scrollbar-corner{background:transparent}
::-webkit-scrollbar-thumb{background:#27272a;border-radius:10px;border:2px solid var(--bg)}::-webkit-scrollbar-thumb:hover{background:#3f3f46}
textarea::-webkit-scrollbar-thumb{border-color:#0c0c0e}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 Inter,system-ui,-apple-system,sans-serif}
a{color:var(--text)}svg{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;flex:none}
.brand{display:flex;align-items:center;gap:10px;font-weight:600;font-size:17px}
.dot{width:30px;height:30px;border-radius:9px;display:grid;place-items:center;color:#fff;background:linear-gradient(135deg,var(--acc),#38bdf8)}.dot svg{width:20px;height:20px;stroke-width:2}
input,textarea{background:#0c0c0e;color:var(--text);border:1px solid var(--line);border-radius:10px;padding:11px 14px;font:inherit;outline:0;width:100%;transition:.15s}
input:focus,textarea:focus{border-color:var(--acc);box-shadow:0 0 0 3px #8b5cf622}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;background:var(--acc);color:#fff;border:0;border-radius:10px;padding:10px 16px;font:inherit;font-weight:500;cursor:pointer;text-decoration:none;transition:.15s}
.btn:hover{filter:brightness(1.15)}.btn.ghost{background:transparent;color:var(--text);border:1px solid var(--line)}
.btn.ghost:hover{border-color:#3f3f46;background:#18181b;filter:none}.btn.sm{padding:7px 10px}
.btn:disabled{opacity:.4;cursor:default;filter:none}.btn.danger:hover{color:#f87171;border-color:#5b1f27;background:#2a121566}
.btn.ghost.on{color:#c4b5fd;border-color:#8b5cf666}.btn.red{background:#dc2626}
.chk{display:flex;align-items:center;gap:8px;color:var(--mute);font-size:14px;cursor:pointer}
.chk input{width:auto;padding:0;accent-color:var(--acc)}
.msgs,.tst{position:fixed;top:16px;right:16px;display:grid;gap:8px;z-index:90}
.alert{background:#2a1215;border:1px solid #5b1f27;color:#fca5a5;padding:10px 14px;border-radius:10px;max-width:360px}
body.auth{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px;
background:radial-gradient(600px 300px at 50% -10%,#8b5cf633,transparent),var(--bg)}
.card{width:100%;max-width:360px;background:var(--card);border:1px solid var(--line);border-radius:16px;padding:32px}
.card h1{font-size:22px;margin:24px 0 4px}.card .sub{color:var(--mute);margin:0 0 20px}
form{display:grid;gap:12px}
.bar{display:flex;justify-content:space-between;align-items:center;max-width:880px;margin:0 auto;padding:20px 16px}
.rt{display:flex;align-items:center;gap:10px}
.st{width:8px;height:8px;border-radius:50%;background:#52525b;transition:.2s}.st.on{background:#34d399}
html{height:100%}
body.chatpg{position:fixed;top:0;left:0;right:0;height:100vh;height:100dvh;overflow:hidden;display:flex;flex-direction:column}
.chatpg .bar{flex:none;width:100%;padding:12px 16px}
.wrap{position:relative;flex:1;min-height:0;display:flex;border-top:1px solid var(--line)}
.scroll{flex:1;overflow-y:auto;overflow-x:hidden;overscroll-behavior:contain}
.inner{max-width:880px;margin:0 auto;padding:36px 16px 16px}
#older{display:flex;margin:-24px auto 14px}
.empty{text-align:center;color:var(--mute);padding:48px 0}
.mrow{position:relative;display:flex;margin:6px 0}.mrow.own{justify-content:flex-end}.mrow.hh{margin-bottom:17px}
.bub{position:relative;touch-action:manipulation;will-change:transform;max-width:min(82%,560px);min-width:0;background:var(--card);border:1px solid var(--line);border-radius:16px 16px 16px 6px;padding:8px 12px}
.own .bub{background:var(--acc);border-color:transparent;border-radius:16px 16px 6px 16px;color:#fff}
.who{font-size:12px;font-weight:600;color:#c4b5fd;margin-bottom:2px}
.txt{white-space:pre-wrap;overflow-wrap:anywhere}.txt a{color:#93c5fd}.own .txt a{color:#fff}
.txt code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.92em;background:#ffffff1f;padding:1px 5px;border-radius:5px}
.txt pre{margin:4px 0;padding:8px 10px;background:#00000059;border-radius:8px;overflow-x:auto;white-space:pre}.txt pre code{background:none;padding:0}
.txt ul,.txt ol{margin:2px 0;padding-left:22px;white-space:normal}
.txt .q{border-left:3px solid #8b5cf6;padding-left:8px;margin:2px 0;opacity:.85}
.meta{display:flex;align-items:center;justify-content:flex-end;gap:6px;font-size:11px;color:var(--mute);margin-top:2px}.own .meta{color:#ffffffb3}
.quote{display:block;border-left:3px solid var(--acc);background:#ffffff0d;border-radius:8px;padding:4px 8px;margin:0 0 6px;cursor:pointer;min-width:0}
.own .quote{border-left-color:#fff9;background:#00000026}
.qwho{font-size:12px;font-weight:600;color:#c4b5fd}.own .qwho{color:#fff}
.qtxt{font-size:13px;opacity:.85;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;overflow-wrap:anywhere}
.quote.gone{cursor:default;font-style:italic;opacity:.7;font-size:13px}
.swi{position:absolute;top:50%;width:32px;height:32px;margin-top:-16px;border-radius:50%;display:grid;place-items:center;background:var(--card);border:1px solid var(--line);color:var(--mute);opacity:0;pointer-events:none;transition:background .12s,color .12s}
.swi svg{width:16px;height:16px}.swi.hit{background:var(--acc);border-color:var(--acc);color:#fff}
.acts{position:absolute;top:-31px;display:none;gap:2px;padding:3px;background:var(--card);border:1px solid var(--line);border-radius:10px;z-index:4;box-shadow:0 6px 18px #0009;color:var(--text)}
.mrow.own .acts{right:8px}.mrow:not(.own) .acts{left:8px}
@media(hover:hover){.mrow:hover .acts{display:flex}}
.mrow.sel .acts{display:flex}
.acts button{background:transparent;border:0;color:var(--text);padding:5px 6px;border-radius:7px;cursor:pointer;display:inline-flex}
.acts button:hover{background:#27272a}.acts .on{color:#f43f5e}.acts .on svg{fill:currentColor}
.hp{position:absolute;bottom:-12px;display:inline-flex;align-items:center;gap:4px;background:var(--card);border:1px solid var(--line);color:#f43f5e;border-radius:12px;padding:1px 7px;font:inherit;font-size:12px;cursor:pointer;line-height:1.5}
.hp svg{width:13px;height:13px;fill:currentColor;stroke:currentColor}.hp span{color:var(--text)}.hp.mine{border-color:#f43f5e66}
.mrow:not(.own) .hp{right:10px}.mrow.own .hp{left:10px}
@keyframes fl{0%,100%{box-shadow:none}30%{box-shadow:0 0 0 3px #8b5cf688}}.flash .bub{animation:fl 1.2s}
.att img,.att video{display:block;max-width:100%;max-height:320px;border-radius:10px;margin:2px 0 6px;background:#000}.att img{cursor:zoom-in}
.att audio{display:block;width:280px;max-width:100%;min-width:200px;height:40px;margin:2px 0 6px}
.fchip{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:10px;background:#0000002e;color:inherit!important;text-decoration:none;margin:2px 0 6px;min-width:0}
.fchip .nm{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.fchip .sz{font-size:12px;opacity:.7;flex:none}
.pvbox:empty{height:1px}
.pv{margin-top:8px;border:1px solid var(--line);border-left:4px solid var(--acc);border-radius:10px;background:#0c0c0e;padding:10px 12px;min-width:0;overflow:hidden}
.own .pv{background:#00000030;border-color:#ffffff30;border-left-color:#fff}
.pvs{font-size:12px;color:var(--mute)}.own .pvs{color:#ffffffb3}
.pvh{display:flex;align-items:center;gap:6px;width:100%;min-width:0;background:transparent;border:0;color:inherit;padding:0;font:inherit;cursor:pointer;text-align:left}
.pvh svg{width:14px;height:14px;opacity:.7;transition:transform .15s}.pvh .pvs{flex:none}
.pvct{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px;font-weight:600}
.pv:not(.col) .pvct{display:none}.pv.col .pvh svg{transform:rotate(-90deg)}.pv.col .pvbody{display:none}.pv.col{padding-top:7px;padding-bottom:7px}
.pvbody{margin-top:4px}
.pvt{display:block;font-weight:600;color:#93c5fd;text-decoration:none;overflow-wrap:anywhere;margin:2px 0}.own .pvt{color:#fff}
.pvd{font-size:13px;opacity:.8;display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden;overflow-wrap:anywhere}
.pvm{position:relative;display:block;margin-top:8px;border-radius:8px;overflow:hidden;background:#000;cursor:pointer}
.pvm img{display:block;width:100%;max-height:320px;object-fit:cover}
.pvm .pp{position:absolute;inset:0;display:grid;place-items:center}
.pvm .pp span{width:54px;height:54px;border-radius:50%;background:#000b;color:#fff;display:grid;place-items:center}.pvm .pp svg{width:24px;height:24px;margin-left:3px;stroke:none}
.pvm.ph{display:grid;place-items:center;aspect-ratio:16/9;background:linear-gradient(135deg,#1c1c22,#2a2a32)}
.pvm.ph.tiktok{aspect-ratio:3/4;max-height:340px}.pvm.ph.instagram{aspect-ratio:1/1;max-height:300px}
.pvf{display:block;border:0;border-radius:8px;background:#000;max-width:100%}
.pvf.youtube{width:100%;aspect-ratio:16/9}.pvf.tiktok{width:325px;height:580px}.pvf.instagram{width:100%;max-width:400px;height:560px;background:#fff}
#pill{position:absolute;left:50%;bottom:12px;transform:translateX(-50%);box-shadow:0 8px 24px #000a;z-index:5}
.comp{flex:none;border-top:1px solid var(--line);background:var(--bg);padding:10px 16px calc(10px + env(safe-area-inset-bottom))}
.compin{max-width:880px;margin:0 auto}
#cform{display:flex;align-items:flex-end;gap:8px}
#ta{resize:none;max-height:140px;min-height:44px;height:44px;line-height:1.4;padding:10px 14px}
textarea:disabled{opacity:.45;cursor:not-allowed}
#cform .btn{height:44px;padding:0 13px;flex:none}
.amenu{position:absolute;left:0;bottom:52px;z-index:6;display:grid;min-width:180px;padding:4px;background:var(--card);border:1px solid var(--line);border-radius:12px;box-shadow:0 10px 30px #000b}
.amenu button{display:flex;align-items:center;gap:10px;padding:11px 12px;background:transparent;border:0;color:var(--text);font:inherit;border-radius:8px;cursor:pointer;text-align:left}
.amenu button:hover{background:#27272a}.amenu svg{width:20px;height:20px}
.recbar{display:flex;align-items:center;gap:10px;margin-bottom:8px;padding:8px 10px;background:#0c0c0e;border:1px solid var(--line);border-radius:12px}
.recbar .rt{flex:1;min-width:0;font-variant-numeric:tabular-nums}.recbar audio{flex:1;min-width:0;height:36px}.recbar .btn{flex:none}
.rdot{flex:none;width:10px;height:10px;border-radius:50%;background:#ef4444;animation:rp 1s infinite}@keyframes rp{50%{opacity:.25}}
.gb{display:inline-grid;place-items:center;width:20px;height:20px;font-size:8px;font-weight:800;letter-spacing:.2px;border:1.5px solid currentColor;border-radius:5px}
#cform{position:relative}
.gifp{display:flex;flex-direction:column;height:min(420px,55vh);margin-bottom:8px;border:1px solid var(--line);border-radius:12px;background:#0c0c0e;overflow:hidden}
.gifh{display:flex;gap:8px;padding:8px}
.gift{display:flex;gap:6px;padding:0 8px 8px}
.gt{padding:5px 14px;border-radius:16px;border:1px solid var(--line);background:transparent;color:var(--mute);font:inherit;font-size:13px;cursor:pointer}
.gt.on{background:var(--acc);border-color:var(--acc);color:#fff}
@media(max-width:640px){ /* phones: the picker takes over the window, the messages are out of reach anyway while picking */
 body.gifopen .wrap{flex:0 0 0;height:0;min-height:0;overflow:hidden;border-top:0}
 body.gifopen .comp{flex:1;min-height:0;display:flex}
 body.gifopen .compin{flex:1;min-height:0;display:flex;flex-direction:column;width:100%}
 body.gifopen .gifp{flex:1;height:auto;min-height:0}
}.gifg{flex:1;min-height:0;overflow-y:auto;padding:0 8px 4px}
.gifin{display:flex;gap:6px;align-items:flex-start}.gcol{flex:1;min-width:0;display:flex;flex-direction:column;gap:6px}
.gi{display:block;width:100%;margin:0;padding:0;border:0;background:#1a1a1f;border-radius:8px;overflow:hidden;cursor:pointer}
.gi img{display:block;width:100%;height:auto}.gds{text-align:center;color:var(--mute);font-size:13px;padding:10px}.gds:empty{display:none}
.gpw{padding:5px 10px;border-top:1px solid var(--line);font-size:11px;font-weight:600;letter-spacing:.3px;color:var(--mute);text-align:right}
.gifm{position:relative;display:block;margin:2px 0 6px;line-height:0}
.gifm img{display:block;width:220px;max-width:100%;height:auto;border-radius:10px;background:#00000040;cursor:zoom-in}
.gifm .via{position:absolute;left:6px;bottom:6px;padding:1px 6px;border-radius:6px;background:#000a;color:#fff;font-size:10px;line-height:1.5}
.lockmsg{text-align:center;color:var(--mute);font-size:13px;margin-bottom:8px}.lockmsg b{color:var(--text)}
.rbar{display:flex;align-items:center;gap:8px;margin-bottom:8px;padding:6px 6px 6px 10px;background:#0c0c0e;border:1px solid var(--line);border-left:3px solid var(--acc);border-radius:10px;font-size:13px}
.rbar .rbt{flex:1;min-width:0}.rbar b{display:block;color:#c4b5fd;font-size:12px}.rbar span{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;opacity:.8}
.pend{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px}
.chip{position:relative;display:flex;align-items:center;gap:8px;max-width:230px;padding:7px 6px 9px 10px;background:#0c0c0e;border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:13px}
.chip .nm{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}.chip.err{border-color:#5b1f27;color:#fca5a5}
.chip .pb{position:absolute;left:0;bottom:0;height:3px;width:0;background:linear-gradient(90deg,var(--acc),#38bdf8);transition:width .1s}
.chip .del,.rbar .del{background:transparent;border:0;color:inherit;opacity:.6;cursor:pointer;padding:4px;display:inline-flex;border-radius:6px}.chip .del:hover,.rbar .del:hover{opacity:1}
#drop{position:fixed;inset:0;background:#000c;display:none;place-items:center;font-size:20px;border:2px dashed var(--acc);z-index:40;pointer-events:none}
body.drag #drop{display:grid}
.lb{position:fixed;inset:0;background:#000e;z-index:70;overflow:hidden;touch-action:none;user-select:none;-webkit-user-select:none}
.lb img{position:absolute;left:0;top:0;transform-origin:0 0;max-width:none;max-height:none;cursor:grab;will-change:transform}.lb img:active{cursor:grabbing}
.lbx{position:absolute;top:calc(12px + env(safe-area-inset-top));right:12px;z-index:2;background:#000a}
.modal{position:fixed;inset:0;background:#000b;display:grid;place-items:center;z-index:80;padding:16px}
.mcard{width:100%;max-width:360px;background:var(--card);border:1px solid var(--line);border-radius:16px;padding:24px}
.mcard.set{max-width:420px}.mcard.set h3{margin-bottom:8px}
.srow{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:14px 0;border-top:1px solid var(--line)}
.srow.first{border-top:0}.srow.col{display:grid;gap:8px}.srow .tx{display:grid;gap:2px;min-width:0}.srow b{font-weight:600}.srow .ds{color:var(--mute);font-size:13px}
.nrow{display:flex;gap:8px}.nrow .btn{flex:none}
.sw{position:relative;width:44px;height:26px;flex:none;display:block}
.sw input{position:absolute;inset:0;width:100%;height:100%;margin:0;padding:0;opacity:0;cursor:pointer;z-index:1;border:0}
.sw i{position:absolute;inset:0;background:#2a2a30;border-radius:26px;transition:.2s}
.sw i::after{content:"";position:absolute;top:3px;left:3px;width:20px;height:20px;border-radius:50%;background:#fff;transition:.2s}
.sw input:checked+i{background:var(--acc)}.sw input:checked+i::after{transform:translateX(18px)}.sw input:disabled+i{opacity:.5}
.mcard h3{margin:0 0 6px;font-size:18px}.mcard p{margin:0 0 20px;color:var(--mute)}.macts{display:flex;gap:8px;justify-content:flex-end}
@media(max-width:640px){body{font-size:14px}.bub{max-width:90%}  .rt{gap:6px}}
</style>
<body class="{{cls}}"><div class=msgs>{% for m in msgs %}<div class=alert>{{m}}</div>{% endfor %}</div>
{{body|safe}}<script>setTimeout(()=>{const m=document.querySelector('.msgs');if(m)m.remove()},7000);if('serviceWorker' in navigator)navigator.serviceWorker.register('/sw.js')</script>"""


def page(tpl, cls="", **ctx):
    return render_template_string(LAYOUT, cls=cls, msgs=get_flashed_messages(), iv=ICON_V,
                                  body=render_template_string(tpl, **ctx))


BRAND = '<div class=brand><span class=dot><svg viewBox="0 0 24 24">{{logo|safe}}</svg></span>Bunny Tale</div>'

LOGIN = """<div class=card>""" + BRAND + """
<h1>Welcome back</h1><p class=sub>Sign in to join the chat</p><form method=post>
<input type=hidden name=next value="{{nxt}}">
<input name=license placeholder="License ID" value="{{lic}}" required>
<input name=email type=email placeholder=Email value="{{em}}" autocomplete=username required>
<input name=password type=password placeholder=Password autocomplete=current-password {% if em %}autofocus{% endif %} required>
<label class=chk><input type=checkbox name=stay>Stay signed in</label>
<button class=btn>Sign in</button></form></div>"""

ERR = """<div class=card>""" + BRAND + """
<h1>Something went wrong</h1><p class=sub>{{err}}</p>
<div style="display:flex;gap:8px"><a class=btn href=/>Retry</a><a class="btn ghost" href=/logout>Logout</a></div></div>"""

OFFLINE = """<div class=card>""" + BRAND + """
<h1>You're offline</h1><p class=sub>Bunny Tale needs a connection.</p>
<button class=btn onclick=location.reload()>Retry</button></div>"""

CHAT = """<header class=bar>""" + BRAND + """<div class=rt><span id=st class=st title=Live></span>
<button id=setb class="btn ghost sm" title="Settings"><svg viewBox="0 0 24 24">{{I.sliders|safe}}</svg></button>
<button id=wipeb class="btn ghost sm danger" title="Wipe chat"><svg viewBox="0 0 24 24">{{I.trash|safe}}</svg></button>
<a class="btn ghost sm" href=/logout>Logout</a></div></header>
<div class=wrap><div class=scroll id=scroll><div class=inner>
<button id=older class="btn ghost sm" hidden>Load older</button><div id=msgs></div><div id=empty class=empty hidden>No messages yet. Say hi!</div></div></div>
<button id=pill class=btn hidden><svg viewBox="0 0 24 24">{{I.down|safe}}</svg>New messages</button></div>
<div class=comp><div class=compin>
<div id=gifp class=gifp hidden><div class=gifh><input id=gifq placeholder="Search GIPHY" autocomplete=off><button type=button id=gifx class="btn ghost sm" title=Close><svg viewBox="0 0 24 24">{{I.x|safe}}</svg></button></div>
<div class=gift><button type=button id=tabr class=gt>Recent</button><button type=button id=tabt class=gt>Trending</button></div>
<div id=gifg class=gifg><div id=gifin class=gifin></div><div id=gifmsg class=gds></div></div><div class=gpw id=gpw></div></div>
<div id=lockmsg class=lockmsg hidden>Chat wiped. You can write again in <b id=lockn>5</b>s</div>
<div id=rbar class=rbar hidden></div><div id=recbar class=recbar hidden></div><div id=pend class=pend hidden></div>
<form id=cform onsubmit="return false"><input type=file id=file multiple hidden><input type=file id=media accept="image/*,video/*" multiple hidden>
<button type=button id=attach class="btn ghost" title=Attach><svg viewBox="0 0 24 24">{{I.clip|safe}}</svg></button>
<div id=amenu class=amenu hidden><button type=button id=mmedia><svg viewBox="0 0 24 24">{{I.image|safe}}</svg>Attach media</button>
<button type=button id=mfile><svg viewBox="0 0 24 24">{{I.clip|safe}}</svg>Attach file</button>
<button type=button id=mgif><span class=gb>GIF</span>Send a GIF</button>
<button type=button id=mrec><svg viewBox="0 0 24 24">{{I.mic|safe}}</svg>Record voice</button></div>
<textarea id=ta rows=1 maxlength=4000 placeholder="Message" autocomplete=off></textarea>
<button type=button id=sendb class=btn title=Send disabled><svg viewBox="0 0 24 24">{{I.send|safe}}</svg></button></form></div></div>
<div id=drop>Drop files to attach</div><div id=toasts class=tst></div>
<script>window.ME={{me|tojson}};window.IC={{I|tojson}}</script><script src="/app.js?v={{ver}}"></script>"""

CHAT_JS = r"""(()=>{
const $=s=>document.querySelector(s);
const scroller=$('#scroll'),msgs=$('#msgs'),ta=$('#ta'),sendb=$('#sendb'),attachb=$('#attach'),pendEl=$('#pend'),older=$('#older'),pill=$('#pill'),st=$('#st'),fileIn=$('#file'),mediaIn=$('#media'),empty=$('#empty'),rbar=$('#rbar'),lockEl=$('#lockmsg'),lockN=$('#lockn');
const ME=window.ME,IC=window.IC,JH={'Content-Type':'application/json'};
const amenu=$('#amenu'),gifp=$('#gifp'),gifq=$('#gifq'),gifg=$('#gifg'),gifin=$('#gifin'),gifmsg=$('#gifmsg'),GS=ME.gif||{},GPS=['giphy','klipy'].filter(p=>GS[p]),GP=GPS.length>0;
const rows=new Map();
let oldest=0,stick=true,busy=false,opened=false,pend=[],reconnecting=false,reply=null,locked=false,lockTimer=null,es=null,lastEv=Date.now(),kbd=false,wasOpen=false;
const vv=()=>window.visualViewport?visualViewport.height:innerHeight;
let vvMax=vv(),vvW=innerWidth;
const coarse=()=>matchMedia('(pointer:coarse)').matches;
const kbdOpen=()=>vv()<vvMax-100; // the on-screen keyboard is really showing (a focused field alone doesn't mean that)
const cid=Math.random().toString(36).slice(2)+Date.now().toString(36);
const el=(t,c,x)=>{const e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e};
const svg=n=>{const s=document.createElementNS('http://www.w3.org/2000/svg','svg');s.setAttribute('viewBox','0 0 24 24');s.innerHTML=IC[n]||IC.file;return s};
const toast=m=>{const d=el('div','alert',m);$('#toasts').appendChild(d);setTimeout(()=>d.remove(),6000)};
const relogin=()=>{location.href='/login?next=/'};
const toBottom=()=>{scroller.scrollTop=scroller.scrollHeight;stick=true;pill.hidden=true};
const human=n=>{const u=['B','KB','MB','GB'];let i=0;while(n>=1024&&i<3){n/=1024;i++}return (i?n.toFixed(1):n)+' '+u[i]};
const fmt=ts=>{const d=new Date(ts),t=d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});return d.toDateString()===new Date().toDateString()?t:d.toLocaleDateString([],{day:'numeric',month:'short'})+' '+t};
scroller.addEventListener('scroll',()=>{stick=scroller.scrollHeight-scroller.scrollTop-scroller.clientHeight<80;if(stick)pill.hidden=true});
pill.onclick=toBottom;

/* ---- dialogs ---- */
function confirmBox(title,text,ok){
 return new Promise(res=>{
  const o=el('div','modal'),c=el('div','mcard'),a=el('div','macts'),no=el('button','btn ghost','Cancel'),yes=el('button','btn red',ok);
  no.type=yes.type='button';
  const k=e=>{if(e.key==='Escape')done(false)};
  const done=v=>{o.remove();removeEventListener('keydown',k);res(v)};
  no.onclick=()=>done(false);yes.onclick=()=>done(true);o.onclick=e=>{if(e.target===o)done(false)};
  addEventListener('keydown',k);
  c.appendChild(el('h3','',title));c.appendChild(el('p','',text));a.appendChild(no);a.appendChild(yes);c.appendChild(a);o.appendChild(c);
  document.body.appendChild(o);yes.focus();
 });
}

/* ---- image viewer: wheel zoom at the cursor, drag to move, double-click, pinch ---- */
function lightbox(url){
 const o=el('div','lb'),i=el('img'),x=el('button','btn ghost sm lbx');x.type='button';x.appendChild(svg('x'));
 o.appendChild(i);o.appendChild(x);document.body.appendChild(o);
 let s=1,fit=1,tx=0,ty=0,nw=0,nh=0,moved=0,pd=0;const P=new Map();
 const apply=()=>{i.style.transform='translate('+tx+'px,'+ty+'px) scale('+s+')'};
 const clamp=()=>{const W=o.clientWidth,H=o.clientHeight,w=nw*s,h=nh*s,m=60;
  tx=w<=W?(W-w)/2:Math.min(Math.max(tx,W-w-m),m);ty=h<=H?(H-h)/2:Math.min(Math.max(ty,H-h-m),m)};
 const center=()=>{const W=o.clientWidth,H=o.clientHeight;fit=Math.min(1,W*.96/nw,H*.94/nh);s=fit;tx=(W-nw*s)/2;ty=(H-nh*s)/2;apply()};
 const zoomAt=(cx,cy,ns)=>{ns=Math.min(Math.max(ns,fit),Math.max(fit,1)*8);const r=ns/s;tx=cx-(cx-tx)*r;ty=cy-(cy-ty)*r;s=ns;clamp();apply()};
 const pos=e=>{const r=o.getBoundingClientRect();return [e.clientX-r.left,e.clientY-r.top]};
 const k=e=>{if(e.key==='Escape')close()},close=()=>{o.remove();removeEventListener('keydown',k);removeEventListener('resize',onr)};
 const onr=()=>{if(nw){const z=s/fit;center();if(z>1.001)zoomAt(o.clientWidth/2,o.clientHeight/2,fit*z)}};
 i.draggable=false;
 i.onload=()=>{nw=i.naturalWidth;nh=i.naturalHeight;i.style.width=nw+'px';i.style.height=nh+'px';center()};
 i.src=url;
 o.addEventListener('wheel',e=>{e.preventDefault();const [cx,cy]=pos(e),d=e.deltaMode===1?e.deltaY*16:e.deltaY;zoomAt(cx,cy,s*Math.exp(-d*.0015))},{passive:false});
 i.addEventListener('dblclick',e=>{const [cx,cy]=pos(e);if(s>fit*1.05){center()}else zoomAt(cx,cy,Math.max(fit*2.5,1))});
 o.addEventListener('pointerdown',e=>{if(e.target.closest('.lbx'))return;o.setPointerCapture(e.pointerId);P.set(e.pointerId,{x:e.clientX,y:e.clientY});moved=0;
  if(P.size===2){const [a,b]=[...P.values()];pd=Math.hypot(a.x-b.x,a.y-b.y)}});
 o.addEventListener('pointermove',e=>{const p=P.get(e.pointerId);if(!p)return;
  if(P.size===2){p.x=e.clientX;p.y=e.clientY;const [a,b]=[...P.values()],d=Math.hypot(a.x-b.x,a.y-b.y),r=o.getBoundingClientRect();
   if(pd)zoomAt((a.x+b.x)/2-r.left,(a.y+b.y)/2-r.top,s*d/pd);pd=d;moved=99;return}
  const dx=e.clientX-p.x,dy=e.clientY-p.y;p.x=e.clientX;p.y=e.clientY;moved+=Math.abs(dx)+Math.abs(dy);tx+=dx;ty+=dy;clamp();apply()});
 const up=e=>{if(!P.has(e.pointerId))return;P.delete(e.pointerId);if(!P.size&&moved<5&&e.target===o)close()};
 o.addEventListener('pointerup',up);o.addEventListener('pointercancel',e=>P.delete(e.pointerId));
 x.onclick=close;addEventListener('keydown',k);addEventListener('resize',onr);
}

/* ---- messages ---- */
/* basic markdown, built with DOM nodes only: `code`, ```blocks```, **bold**, *italic* / _italic_, ~~strike~~, [text](url), > quote, links */
const MDI=/(`[^`\n]+`)|(\*\*[^\n]+?\*\*)|(~~[^\n]+?~~)|(\*[^\s*][^*\n]*?\*)|(\b_[^\s_][^_\n]*?_\b)|\[([^\]\n]+)\]\((https?:\/\/[^\s)<>"]+)\)|(https?:\/\/[^\s<>"]+)/g;
function mdLink(node,url,label){const a=el('a','',label||url);a.href=url;a.target='_blank';a.rel='noopener noreferrer';node.appendChild(a)}
function mdInline(node,s){
 const re=new RegExp(MDI.source,'g');let i=0,m;
 while((m=re.exec(s))){
  if(m.index>i)node.appendChild(document.createTextNode(s.slice(i,m.index)));
  i=re.lastIndex;
  if(m[1])node.appendChild(el('code','',m[1].slice(1,-1)));
  else if(m[2]){const e=el('b');mdInline(e,m[2].slice(2,-2));node.appendChild(e)}
  else if(m[3]){const e=el('s');mdInline(e,m[3].slice(2,-2));node.appendChild(e)}
  else if(m[4]||m[5]){const e=el('i');mdInline(e,(m[4]||m[5]).slice(1,-1));node.appendChild(e)}
  else if(m[6])mdLink(node,m[7],m[6]);
  else{let p=m[8],tail='';const t=p.match(/[.,;:!?)\]*_~]+$/);if(t){tail=t[0];p=p.slice(0,-tail.length)}
   mdLink(node,p);if(tail)node.appendChild(document.createTextNode(tail))}
 }
 if(i<s.length)node.appendChild(document.createTextNode(s.slice(i)));
}
function linkify(node,text){
 text.split(/```(?:[\w+-]*\n)?([\s\S]*?)```/g).forEach((part,k)=>{
  if(k%2){const pre=el('pre');pre.appendChild(el('code','',part.replace(/\n$/,'')));node.appendChild(pre);return}
  let prev='',lst=null; // 'n' = plain line, 'b' = block (quote, list), so no stray blank lines appear
  part.split('\n').forEach((ln,j,arr)=>{
   if(k&&j===0&&ln==='')return; // newline right after a code block
   const li=/^\s{0,3}([-*+]|\d{1,9}[.)])\s+(\S.*)$/.exec(ln);
   if(li){const tag=/\d/.test(li[1])?'ol':'ul';
    if(!lst||lst.t!==tag){lst=el(tag);if(tag==='ol'&&parseInt(li[1])!==1)lst.start=parseInt(li[1]);node.appendChild(lst)}
    const e=el('li');mdInline(e,li[2]);lst.appendChild(e);prev='b';return}
   if(lst&&ln.trim()===''&&arr.slice(j+1).some(x=>/^\s{0,3}([-*+]|\d{1,9}[.)])\s+\S/.test(x)))return; // a blank line between items keeps the list (and its numbering) going
   lst=null;
   const q=/^>\s?(.*)$/.exec(ln);
   if(q){const d=el('div','q');mdInline(d,q[1]);node.appendChild(d);prev='b';return}
   if(prev==='n')node.appendChild(document.createTextNode('\n'));
   mdInline(node,ln);prev='n';
  });
 });
}
function media(a){
 const url='/media/'+a.r,box=el('div','att');
 if(a.k==='image'){const i=el('img');i.loading='lazy';i.alt=a.n;i.src=url;i.onload=()=>{if(stick)toBottom()};i.onclick=()=>lightbox(url);box.appendChild(i)}
 else if(a.k==='video'){const v=el('video');v.controls=true;v.preload='metadata';v.playsInline=true;v.src=url;v.onloadedmetadata=()=>{if(stick)toBottom()};box.appendChild(v)}
 else if(a.k==='audio'){const u=el('audio');u.controls=true;u.preload='none';u.src=url;fixDur(u);box.appendChild(u)}
 else{const l=el('a','fchip');l.href=url+'?dl=1&n='+encodeURIComponent(a.n);l.appendChild(svg('file'));l.appendChild(el('span','nm',a.n));l.appendChild(el('span','sz',human(a.z||0)));l.appendChild(svg('download'));box.appendChild(l)}
 return box;
}
const snip=o=>o.t?o.t:({image:'Photo',video:'Video',audio:'Audio',gif:'GIF'}[o.k]||o.n||'File');
function quoteEl(q){
 const d=el('div','quote');d.dataset.q=q.id;
 if(q.gone){d.classList.add('gone');d.textContent='Message deleted';return d}
 const w=el('div','qwho',q.s);w.dataset.u=q.u;d.appendChild(w);d.appendChild(el('div','qtxt',snip(q)));
 d.onclick=()=>{const r=rows.get(q.id);if(r){r.scrollIntoView({block:'center',behavior:'smooth'});r.classList.add('flash');setTimeout(()=>r.classList.remove('flash'),1300)}};
 return d;
}
function paintHearts(row){
 const h=row._h||[],mine=h.includes(ME.uid);
 row._hp.hidden=!h.length;row._hp.classList.toggle('mine',mine);
 row._hp.replaceChildren(svg('heart'),...(h.length>1?[el('span','',String(h.length))]:[]));
 row.classList.toggle('hh',h.length>0);row._hb.classList.toggle('on',mine);
}
function actBtn(icon,title,fn){const b=el('button');b.type='button';b.title=title;b.appendChild(svg(icon));b.onclick=e=>{e.stopPropagation();clearSel();fn();setTimeout(keep,0)};return b}
/* ---- GIF picker: GIPHY / Klipy are called straight from this browser, messages keep only a reference (GIPHY: id; Klipy: slug + two image URLs) ---- */
const GN={giphy:'GIPHY',klipy:'Klipy'};
const gp=g=>g&&g.p==='klipy'?'klipy':'giphy';
const KU=/^https:\/\/static\.klipy\.com\/[A-Za-z0-9\/_.\-]{1,200}\.(webp|gif)$/;
const gifOk=g=>{if(!g||typeof g.id!=='string')return false;return gp(g)==='klipy'?/^[A-Za-z0-9_\-]{3,160}$/.test(g.id)&&KU.test(g.u||'')&&KU.test(g.f||''):/^[A-Za-z0-9]{5,32}$/.test(g.id)};
const gifUrl=(id,f)=>'https://media.giphy.com/media/'+id+'/'+f;
const gThumb=g=>gp(g)==='klipy'?g.u:gifUrl(g.id,'200w.gif');
const gFull=g=>gp(g)==='klipy'?g.f:gifUrl(g.id,'giphy.gif');
const gSrc=()=>{let s='';try{s=localStorage.getItem('bc_gsrc')||''}catch(_){}return GPS.includes(s)?s:GPS[0]};
function gifEl(g){
 const box=el('div','gifm'),i=el('img');
 i.alt=g.t||'GIF';i.loading='lazy';i.src=gThumb(g);
 if(g.w&&g.h)i.style.aspectRatio=g.w+'/'+g.h;
 i.onerror=()=>{if(!i._f){i._f=1;i.src=gFull(g)}};
 i.onload=()=>{if(stick)toBottom()};
 i.onclick=()=>lightbox(gFull(g));
 box.appendChild(i);box.appendChild(el('span','via',GN[gp(g)]));return box;
}
let gOff=0,gMore=false,gSeq=0,gBusy=false,gTimer=0,gifStick=true,gTab='recent',gShown='';
function gLabels(){ // search placeholder and credit follow the chosen source
 if(!GP)return;const n=GN[gSrc()];gifq.placeholder='Search '+n;$('#gpw').textContent='Powered by '+n;
}
function setGifSource(s){ // from Settings
 try{localStorage.setItem('bc_gsrc',s)}catch(_){}
 gLabels();gShown='';
 if(!gifp.hidden){gifq.value='';gTab=gRecents().length?'recent':'trending';paintTabs();gShow()}
}
function setGif(open){
 if(open&&gifp.hidden)gifStick=stick;
 gifp.hidden=!open;document.body.classList.toggle('gifopen',open);
 if(gifStick)toBottom();
}
/* recent / frequent GIFs: kept on this device only (no provider request needed to show them); the picker lists those of the chosen source */
const gAll=()=>{try{const a=JSON.parse(localStorage.getItem('bc_gifs')||'[]');return Array.isArray(a)?a.filter(gifOk):[]}catch(_){return[]}};
const gRecents=()=>gAll().filter(x=>gp(x)===gSrc());
function recordGif(g){
 try{
  const a=gAll(),x=a.find(y=>y.id===g.id&&gp(y)===gp(g));
  if(x){x.n=(x.n||1)+1;x.ts=Date.now();x.w=g.w;x.h=g.h;x.t=g.t}else a.push({...g,n:1,ts:Date.now()});
  a.sort((p,q)=>((q.n||1)-(p.n||1))||(q.ts-p.ts));
  localStorage.setItem('bc_gifs',JSON.stringify(a.slice(0,60)));gShown='';
 }catch(_){}
}
function gifBtn(g,src,fb){
 const b=el('button','gi'),i=el('img');b.type='button';b.title=g.t||'';
 i.loading='lazy';i.alt=g.t||'GIF';i.src=src;if(g.w&&g.h)i.style.aspectRatio=g.w+'/'+g.h;
 if(fb)i.onerror=()=>{if(!i._f){i._f=1;i.src=fb}};
 b.appendChild(i);b.onclick=()=>sendGif(g);return b;
}
let gCols=[],gColH=[],gSeen=new Set();
function gReset(){ // empty grid with fresh columns (3 on wide screens, else 2)
 gifin.replaceChildren();gCols=[];gColH=[];gSeen=new Set();
 const n=gifg.clientWidth>=480?3:2;
 for(let i=0;i<n;i++){const c=el('div','gcol');gifin.appendChild(c);gCols.push(c);gColH.push(0)}
}
function gAppend(id,b,w,h){ // new items go to the shortest column; nothing already shown ever moves
 if(gSeen.has(id))return false;gSeen.add(id);
 let k=0;for(let i=1;i<gColH.length;i++)if(gColH[i]<gColH[k])k=i;
 gCols[k].appendChild(b);gColH[k]+=(w&&h)?h/w:1;return true;
}
function renderRecent(){
 gSeq++;gBusy=false;gOff=0;gMore=false;gShown='recent';
 gReset();gifmsg.textContent='';
 const a=gRecents();
 a.forEach(x=>{const g={id:x.id,w:x.w,h:x.h,t:x.t};if(gp(x)==='klipy'){g.p='klipy';g.u=x.u;g.f=x.f}gAppend(x.id,gifBtn(g,gThumb(g),gFull(g)),x.w,x.h)});
 if(!a.length)gifmsg.textContent='Nothing here yet. The GIFs you send show up here.';
}
function paintTabs(){
 const q=gifq.value.trim().length>=2;
 $('#tabr').classList.toggle('on',!q&&gTab==='recent');$('#tabt').classList.toggle('on',!q&&gTab==='trending');
}
function gShow(){ // search when there is a query, otherwise the selected tab
 const q=gifq.value.trim();paintTabs();
 if(q.length>=2){gLoad(true);return}
 if(q.length===1)return;
 if(gTab==='recent')renderRecent();else gLoad(true);
}
function setTab(t){gTab=t;gifq.value='';gShow()}
async function gLoad(reset){
 if(!GP||(gBusy&&!reset))return;
 const q=gifq.value.trim(),src=gSrc(),P=GS[src],N=GN[src];
 if(q&&q.length<2)return;
 const seq=++gSeq;
 if(reset){gOff=0;gMore=false;gReset();gShown=q?'search':'trending'}
 gifmsg.textContent='';gBusy=true;
 try{
  let u;
  if(src==='klipy'){ // gOff counts pages here
   u=new URL('https://api.klipy.com/api/v1/'+encodeURIComponent(P.key)+'/gifs/'+(q?'search':'trending'));
   u.searchParams.set('per_page','24');u.searchParams.set('page',String(gOff+1));u.searchParams.set('rating',P.rating);
  }else{
   u=new URL('https://api.giphy.com/v1/gifs/'+(q?'search':'trending'));
   u.searchParams.set('api_key',P.key);u.searchParams.set('limit','24');u.searchParams.set('offset',String(gOff));u.searchParams.set('rating',P.rating);
  }
  if(q)u.searchParams.set('q',q);
  const r=await fetch(u);
  if(seq!==gSeq)return;
  if(r.status===429){gShown='';gifmsg.textContent=N+' request limit reached for now. Try again later.';return}
  if(!r.ok){gShown='';gifmsg.textContent=N+' did not answer ('+r.status+').';return}
  const j=await r.json();if(seq!==gSeq)return;
  let n=0;
  if(src==='klipy'){
   const L=(j.data&&j.data.data)||[];n=L.length;
   L.forEach(d=>{
    const F=d.file||d.files||{},pick=s=>{const v=F[s];return v&&(v.webp||v.gif)};
    const t=pick('sm')||pick('md')||pick('hd'),f=pick('hd')||pick('md')||t;
    if(!t||!f)return;
    const g={p:'klipy',id:d.slug,u:t.url,f:f.url,w:+t.width||200,h:+t.height||200,t:(d.title||'').slice(0,100)};
    if(!gifOk(g))return;
    gAppend(g.id,gifBtn(g,g.u,g.f),g.w,g.h);
   });
   gOff++;gMore=!!(j.data&&j.data.has_next)&&n>0;
  }else{
   (j.data||[]).forEach(d=>{
    const f=d.images&&d.images.fixed_width;if(!f||!gifOk({id:d.id}))return;
    const b=el('button','gi'),i=el('img');b.type='button';b.title=d.title||'';
    i.loading='lazy';i.alt=d.title||'GIF';i.src=f.url;if(f.width&&f.height)i.style.aspectRatio=f.width+'/'+f.height;
    b.appendChild(i);b.onclick=()=>sendGif({id:d.id,w:+f.width||200,h:+f.height||200,t:(d.title||'').slice(0,100)});gAppend(d.id,b,+f.width,+f.height);
   });
   n=(j.data||[]).length;gOff+=n;gMore=gOff<((j.pagination&&j.pagination.total_count)||0);
  }
  if(!gifin.querySelector('.gi'))gifmsg.textContent='No GIFs found.';
 }catch(_){if(seq===gSeq){gShown='';gifmsg.textContent='Could not reach '+N+'.'}}
 finally{if(seq===gSeq)gBusy=false}
}
async function sendGif(g){
 if(locked||busy)return;busy=true;upd();
 try{
  const r=await fetch('/send',{method:'POST',headers:JH,body:JSON.stringify({text:'',gif:g,reply:reply?reply.id:null,media:[]})});
  if(r.status===401)return relogin();
  if(r.status===409){setReply(null);return toast(await r.text())}
  if(!r.ok)return toast(await r.text()||'Send failed');
  const m=await r.json();recordGif(g);setReply(null);setGif(false);add(m);toBottom();
 }catch(_){toast('Send failed')}
 finally{busy=false;upd()}
}
if(GP){
 gLabels();
 const toggleGif=()=>{
  const open=gifp.hidden;setGif(open);if(!open)return;
  if(!gifq.value.trim()){gTab=gRecents().length?'recent':'trending';paintTabs();if(gShown!==gTab)gShow()}else paintTabs();
  if(!coarse())gifq.focus();
 };
 $('#mgif').onclick=()=>{amenu.hidden=true;toggleGif()};
 $('#gifx').onclick=()=>setGif(false);
 gifq.addEventListener('input',()=>{paintTabs();clearTimeout(gTimer);gTimer=setTimeout(gShow,500)});
 $('#tabr').onclick=()=>setTab('recent');$('#tabt').onclick=()=>setTab('trending');
 gifg.addEventListener('scroll',()=>{if(gifg.scrollTop+gifg.clientHeight>gifg.scrollHeight-200&&gMore)gLoad(false)});
 addEventListener('keydown',e=>{if(e.key==='Escape'&&!gifp.hidden)setGif(false)});
}

/* ---- link previews: cards from the server, players only after a tap ---- */
const pvOn=()=>{try{return localStorage.getItem('bc_pv')!=='0'}catch(_){return true}};
const pvCol=()=>{try{return localStorage.getItem('bc_pvc')==='1'}catch(_){return false}};
const PVC=new Map(),pvQ=[];let pvActive=0;
function pvPump(){while(pvActive<3&&pvQ.length){const [u,res]=pvQ.shift();pvActive++;
 fetch('/preview?u='+encodeURIComponent(u)).then(r=>r.ok?r.json():null).catch(()=>null).then(j=>{pvActive--;res(j);pvPump()})}}
const pvFetch=u=>{if(!PVC.has(u))PVC.set(u,new Promise(res=>{pvQ.push([u,res]);pvPump()}));return PVC.get(u)};
const pvIO=new IntersectionObserver(es=>es.forEach(e=>{if(e.isIntersecting){pvIO.unobserve(e.target);e.target._go()}}),{root:scroller,rootMargin:'300px'});
const urlsOf=t=>{const out=[];for(let u of (t.match(/https?:\/\/[^\s<>"]+/g)||[])){u=u.replace(/[.,;:!?)\]]+$/,'');if(!out.includes(u))out.push(u);if(out.length>=2)break}return out};
const PLAYER_OK=/^https:\/\/(www\.youtube-nocookie\.com\/embed\/|www\.tiktok\.com\/embed\/v2\/|www\.instagram\.com\/(p|reel|tv)\/)/;
function player(e,box){
 if(!PLAYER_OK.test(e.src))return;
 const f=document.createElement('iframe');
 f.src=e.src;f.className='pvf '+e.k;f.allow='autoplay; encrypted-media; picture-in-picture; fullscreen; clipboard-write';
 f.allowFullscreen=true;f.referrerPolicy='strict-origin-when-cross-origin';
 f.setAttribute('sandbox','allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox allow-presentation');
 box.onclick=null;box.className='';box.replaceChildren(f);
}
function card(j,u,collapsed){
 const c=el('div','pv'+(collapsed?' col':'')),h=el('button','pvh'),body=el('div','pvbody');
 h.type='button';h.title='Show / hide';
 h.appendChild(svg('chev'));h.appendChild(el('span','pvs',j.site||'Link'));h.appendChild(el('span','pvct',j.title||u));
 const fill=()=>{ // (re)builds the card content; a loaded player is dropped by calling this again
  body.replaceChildren();
  if(j.title){const a=el('a','pvt',j.title);a.href=u;a.target='_blank';a.rel='noopener noreferrer';body.appendChild(a)}
  if(j.desc)body.appendChild(el('div','pvd',j.desc));
  if(j.embed){
   const m=el('div','pvm'+(j.img?'':' ph '+j.embed.k));
   if(j.img){const i=el('img');i.alt='';i.loading='lazy';i.src=j.img;i.onerror=()=>{i.remove();m.classList.add('ph',j.embed.k)};m.appendChild(i)}
   const pp=el('div','pp'),sp=el('span');sp.appendChild(svg('play'));pp.appendChild(sp);m.appendChild(pp);
   m.onclick=()=>player(j.embed,m);body.appendChild(m);
  }else if(j.img){
   const a=el('a','pvm');a.href=u;a.target='_blank';a.rel='noopener noreferrer';
   const i=el('img');i.alt='';i.loading='lazy';i.src=j.img;i.onerror=()=>a.remove();a.appendChild(i);body.appendChild(a);
  }
 };
 fill();
 h.onclick=e=>{e.stopPropagation();const nowCol=c.classList.toggle('col');if(nowCol&&body.querySelector('iframe'))fill();if(stick)toBottom()};
 c.appendChild(h);c.appendChild(body);return c;
}
function addPreview(host,u){
 const box=el('div','pvbox');host.appendChild(box);
 box._go=async()=>{const j=await pvFetch(u);if(!j||!j.ok)return;box.appendChild(card(j,u,pvCol()));if(stick)toBottom()};
 pvIO.observe(box);
}
function build(m){
 const own=m.u===ME.uid,row=el('div','mrow'+(own?' own':'')),b=el('div','bub');
 row.dataset.id=m.id;row._h=m.h||[];row._m=m;
 if(!own){const w=el('div','who',m.s);w.dataset.u=m.u;b.appendChild(w)}
 if(m.q)b.appendChild(quoteEl(m.q));
 if(m.g&&gifOk(m.g))b.appendChild(gifEl(m.g));
 (m.a||[]).forEach(a=>b.appendChild(media(a)));
 if(m.t){const t=el('div','txt');linkify(t,m.t);b.appendChild(t);if(pvOn())urlsOf(m.t).forEach(u=>addPreview(b,u))}
 b.appendChild(el('div','meta',fmt(m.ts)));
 const acts=el('div','acts');
 row._hb=actBtn('heart','Heart',()=>heart(m.id));acts.appendChild(row._hb);
 acts.appendChild(actBtn('reply','Reply',()=>setReply(m)));
 if(own)acts.appendChild(actBtn('trash','Delete',()=>del(m.id)));
 b.appendChild(acts);
 row._hp=el('button','hp');row._hp.type='button';row._hp.onclick=e=>{e.stopPropagation();heart(m.id)};b.appendChild(row._hp);
 row.appendChild(b);paintHearts(row);return row;
}
function add(m){
 const have=rows.get(m.id);
 if(have){if(m.h){have._h=m.h;paintHearts(have)}return false}
 const e=build(m);rows.set(m.id,e);
 let ref=null;
 for(let n=msgs.lastElementChild;n;n=n.previousElementSibling){if(+n.dataset.id<m.id){ref=n;break}}
 msgs.insertBefore(e,ref?ref.nextSibling:msgs.firstChild);
 oldest=oldest?Math.min(oldest,m.id):m.id;empty.hidden=true;return true;
}
function remove(id){
 const e=rows.get(id);if(e){e.remove();rows.delete(id)}
 document.querySelectorAll('.quote[data-q="'+id+'"]').forEach(q=>{q.classList.add('gone');q.onclick=null;q.textContent='Message deleted'});
 if(reply&&reply.id===id)setReply(null);
 empty.hidden=rows.size>0;
}
function clearAll(){rows.clear();msgs.textContent='';oldest=0;older.hidden=true;empty.hidden=false;setReply(null)}
async function fetchPage(before){
 const r=await fetch('/messages'+(before?'?before='+before:''));
 if(r.status===401){relogin();return null}
 if(!r.ok){toast(await r.text());return null}
 return r.json();
}
async function loadOlder(){
 const j=await fetchPage(oldest);if(!j)return;
 const h=scroller.scrollHeight,t=scroller.scrollTop;
 j.msgs.forEach(add);older.hidden=!j.more;
 scroller.scrollTop=t+(scroller.scrollHeight-h);
}
older.onclick=loadOlder;
async function sync(){
 const j=await fetchPage();if(!j)return;
 const ids=new Set(j.msgs.map(m=>m.id)),min=j.more&&j.msgs.length?j.msgs[0].id:0;
 for(const [id,e] of [...rows])if(id>=min&&!ids.has(id))remove(id);
 const was=stick;let fresh=false;j.msgs.forEach(m=>{if(add(m))fresh=true});
 empty.hidden=rows.size>0;if(fresh&&was)toBottom();
 if(j.lock>0)lockInput(j.lock);
}
async function del(id){
 if(!await confirmBox('Delete message?','It will be removed for everyone.','Delete'))return;
 const r=await fetch('/delete',{method:'POST',headers:JH,body:JSON.stringify({id})});
 if(r.status===401)return relogin();
 if(!r.ok)return toast(await r.text()||'Delete failed');
 remove(id);
}
async function heart(id){
 const r=await fetch('/heart',{method:'POST',headers:JH,body:JSON.stringify({id})});
 if(r.status===401)return relogin();
 if(!r.ok)return;
 const j=await r.json(),row=rows.get(j.id);if(row){row._h=j.h;paintHearts(row)}
 keep();
}
function clearSel(){document.querySelectorAll('.mrow.sel').forEach(r=>r.classList.remove('sel'))}
/* ---- swipe a message left or right to reply to it (touch only) ---- */
let sw=null;
const SW_HIT=70,calm=matchMedia('(prefers-reduced-motion:reduce)').matches;
function swMove(d){
 const a=Math.abs(d),sign=d<0?-1:1,shift=sign*Math.min(a<SW_HIT?a:SW_HIT+(a-SW_HIT)*.25,115),p=Math.min(1,a/SW_HIT);
 sw.b.style.transform='translateX('+shift+'px)';
 const i=sw.i;i.style.left=sign>0?'6px':'auto';i.style.right=sign<0?'6px':'auto';
 i.style.opacity=String(p);i.style.transform='scale('+(.6+.4*p)+')';
 const hit=p>=1;i.classList.toggle('hit',hit);
 if(hit&&!sw.hit&&navigator.vibrate)try{navigator.vibrate(10)}catch(_){}
 sw.hit=hit;
}
function swEnd(ok){
 if(!sw)return;const s=sw;sw=null;
 if(!s.on)return;
 const t=calm?'none':'transform .24s cubic-bezier(.2,.9,.3,1.25)';
 s.b.style.transition=t;s.b.style.transform='';
 s.i.style.transition='opacity .2s';s.i.style.opacity='0';
 setTimeout(()=>{s.b.style.transition='';s.i.remove()},300);
 if(ok&&s.hit&&s.row._m)setReply(s.row._m);
}
msgs.addEventListener('touchstart',e=>{
 if(e.touches.length!==1||e.target.closest('video,audio,iframe,input,textarea,.acts,.pv,.gifm img,.att img')){sw=null;return}
 const row=e.target.closest('.mrow');if(!row){sw=null;return}
 const t=e.touches[0];sw={row,b:row.querySelector('.bub'),x:t.clientX,y:t.clientY,on:false,hit:false,i:null};
},{passive:true});
msgs.addEventListener('touchmove',e=>{
 if(!sw)return;const t=e.touches[0],dx=t.clientX-sw.x,dy=t.clientY-sw.y;
 if(!sw.on){
  if(Math.abs(dy)>10&&Math.abs(dy)>Math.abs(dx)){sw=null;return}   // it is a scroll
  if(!(Math.abs(dx)>12&&Math.abs(dx)>Math.abs(dy)*1.4))return;
  sw.on=true;sw.x=t.clientX;clearSel();getSelection().removeAllRanges();
  sw.b.style.transition='none';
  sw.i=el('div','swi');sw.i.appendChild(svg('reply'));sw.row.appendChild(sw.i);
  return;
 }
 if(e.cancelable)e.preventDefault();
 swMove(t.clientX-sw.x);
},{passive:false});
msgs.addEventListener('touchend',()=>swEnd(true));
msgs.addEventListener('touchcancel',()=>swEnd(false));
let lastTap={id:0,t:0};
msgs.addEventListener('click',e=>{
 const row=e.target.closest('.mrow');if(!row)return;
 if(e.target.closest('a,button,img,video,audio,.quote,.pv'))return;
 const id=+row.dataset.id,now=Date.now();
 if(lastTap.id===id&&now-lastTap.t<320){lastTap={id:0,t:0};getSelection().removeAllRanges();clearSel();heart(id);return}
 lastTap={id,t:now};
 if(matchMedia('(hover:none)').matches){const was=row.classList.contains('sel');clearSel();if(!was)row.classList.add('sel')}
 setTimeout(keep,0);
});
document.addEventListener('click',e=>{if(!e.target.closest('.mrow'))clearSel()});
/* keep the mobile keyboard open while tapping messages, hearts, reply */
document.addEventListener('pointerdown',()=>{kbd=document.activeElement===ta&&kbdOpen()},true);
document.addEventListener('mousedown',e=>{
 if(kbd&&coarse()&&!e.target.closest('textarea,input,video,audio,a,.modal,.lb'))e.preventDefault();
});
function keep(){if(kbd&&!locked&&document.activeElement!==ta)ta.focus({preventScroll:true})}

/* ---- composer ---- */
function setReply(m){
 reply=m?{id:m.id,s:m.s,t:snip(m.a&&m.a[0]?{t:m.t,k:m.a[0].k,n:m.a[0].n}:m.g?{t:m.t,k:'gif'}:{t:m.t})}:null;
 rbar.replaceChildren();rbar.hidden=!reply;
 if(reply){
  const b=el('div','rbt'),x=el('button','del');x.type='button';x.appendChild(svg('x'));x.onclick=()=>setReply(null);
  b.appendChild(el('b','','Replying to '+reply.s));b.appendChild(el('span','',reply.t.slice(0,120)));
  rbar.appendChild(b);rbar.appendChild(x);if(!locked)ta.focus({preventScroll:true});
 }
}
function upd(){
 pendEl.hidden=!pend.length;
 const up=pend.some(p=>!p.ref&&!p.err);
 sendb.disabled=locked||busy||up||!(ta.value.trim()||pend.some(p=>p.ref));
}
function resize(){ta.style.height='auto';ta.style.height=Math.min(ta.scrollHeight,140)+'px'}
function lockInput(sec){
 clearInterval(lockTimer);
 const end=Date.now()+sec*1000;locked=true;ta.disabled=true;attachb.disabled=true;amenu.hidden=true;setGif(false);lockEl.hidden=false;
 const tick=()=>{const left=Math.ceil((end-Date.now())/1000);
  if(left<=0){clearInterval(lockTimer);locked=false;ta.disabled=false;attachb.disabled=false;lockEl.hidden=true;upd();return}
  lockN.textContent=left};
 tick();lockTimer=setInterval(tick,200);upd();
}
function dropPending(p){
 if(p.xhr&&!p.ref&&!p.err)p.xhr.abort();
 if(p.ref)fetch('/media/discard',{method:'POST',headers:JH,body:JSON.stringify({ref:p.ref})}).catch(()=>{});
 pend=pend.filter(x=>x!==p);p.chip.remove();upd();
}
function addFiles(list){
 if(locked){toast('The chat was just wiped, please wait a moment');return}
 for(const f of list){
  if(pend.length>=10){toast('Up to 10 attachments per message');break}
  const p={name:f.name||'file',size:f.size,ref:null,err:false};pend.push(p);
  const chip=el('div','chip'),bar=el('i','pb'),x=el('button','del');
  x.type='button';x.appendChild(svg('x'));x.onclick=()=>dropPending(p);
  chip.appendChild(svg('file'));chip.appendChild(el('span','nm',p.name));chip.appendChild(x);chip.appendChild(bar);
  pendEl.appendChild(chip);p.chip=chip;
  const xhr=new XMLHttpRequest();p.xhr=xhr;
  xhr.open('POST','/media/upload');xhr.setRequestHeader('X-File-Name',encodeURIComponent(p.name));
  xhr.upload.onprogress=e=>{if(e.lengthComputable)bar.style.width=(e.loaded/e.total*100)+'%'};
  xhr.onload=()=>{
   if(xhr.status===401)return relogin();
   let j=null;try{j=JSON.parse(xhr.responseText)}catch(_){}
   if(xhr.status===200&&j){p.ref=j.ref;bar.style.width='100%'}
   else{p.err=true;chip.classList.add('err');toast(xhr.responseText||'Upload failed')}
   upd();
  };
  xhr.onerror=()=>{p.err=true;chip.classList.add('err');toast('Upload failed');upd()};
  xhr.send(f);
 }
 upd();
}
async function send(){
 if(busy||sendb.disabled)return;
 const text=ta.value.trim(),ready=pend.filter(p=>p.ref);
 const had=kbd||document.activeElement===ta&&!coarse(); // keyboard was open: keep it open
 if(had)ta.focus({preventScroll:true});
 busy=true;upd();
 try{
  const r=await fetch('/send',{method:'POST',headers:JH,
   body:JSON.stringify({text,reply:reply?reply.id:null,media:ready.map(p=>({ref:p.ref,name:p.name,size:p.size}))})});
  if(r.status===401)return relogin();
  if(r.status===409){setReply(null);return toast(await r.text())}
  if(!r.ok)return toast(await r.text()||'Send failed');
  const m=await r.json();
  ta.value='';resize();setReply(null);
  pend.forEach(p=>p.chip.remove());pend=[];
  add(m);toBottom();
 }catch(_){toast('Send failed')}
 finally{busy=false;upd();if(!locked&&had)ta.focus({preventScroll:true})}
}
sendb.onclick=send;
sendb.addEventListener('mousedown',e=>e.preventDefault()); // don't steal focus from the text field
ta.addEventListener('input',()=>{resize();upd()});
ta.addEventListener('keydown',e=>{
 if(e.key==='Enter'&&!e.shiftKey&&!e.isComposing&&!matchMedia('(pointer:coarse)').matches){e.preventDefault();send()}
});
ta.addEventListener('paste',e=>{const fs=[...(e.clipboardData&&e.clipboardData.files||[])];if(fs.length){e.preventDefault();addFiles(fs)}});
const CANREC=!!(window.MediaRecorder&&navigator.mediaDevices&&navigator.mediaDevices.getUserMedia);
$('#mgif').hidden=!GP;$('#mrec').hidden=!CANREC;
attachb.onclick=()=>{amenu.hidden=!amenu.hidden}; // small menu: media (gallery), file, GIF, voice
$('#mrec').onclick=()=>{amenu.hidden=true;recStart()};
$('#mfile').onclick=()=>{amenu.hidden=true;fileIn.click()};
$('#mmedia').onclick=()=>{amenu.hidden=true;mediaIn.click()};
document.addEventListener('click',e=>{if(!e.target.closest('#amenu,#attach'))amenu.hidden=true});
addEventListener('keydown',e=>{if(e.key==='Escape')amenu.hidden=true});
fileIn.onchange=()=>{addFiles(fileIn.files);fileIn.value=''};
mediaIn.onchange=()=>{addFiles(mediaIn.files);mediaIn.value=''};
const hasFiles=e=>e.dataTransfer&&[...e.dataTransfer.types].includes('Files');
addEventListener('dragover',e=>{if(hasFiles(e)){e.preventDefault();document.body.classList.add('drag')}});
addEventListener('dragleave',e=>{if(!e.relatedTarget)document.body.classList.remove('drag')});
addEventListener('drop',e=>{document.body.classList.remove('drag');if(hasFiles(e)){e.preventDefault();addFiles(e.dataTransfer.files)}});

/* ---- header actions ---- */
async function saveNick(v){
 const r=await fetch('/nick',{method:'POST',headers:JH,body:JSON.stringify({nick:v})});
 if(r.status===401){relogin();return null}
 if(!r.ok){toast(await r.text()||'Could not change nickname');return null}
 ME.name=(await r.json()).name;return ME.name;
}
async function wipe(){
 if(!await confirmBox('Wipe chat?','This permanently deletes all messages and media for everyone. It cannot be undone.','Yes, wipe'))return;
 const b=$('#wipeb');b.disabled=true;
 try{
  const r=await fetch('/wipe',{method:'POST'});
  if(r.status===401)return relogin();
  if(!r.ok)return toast(await r.text()||'Wipe failed');
  clearAll();lockInput(5);
 }finally{b.disabled=false}
}
$('#wipeb').onclick=wipe;

/* ---- push notifications (opt-in) ---- */
const canPush='serviceWorker' in navigator&&'PushManager' in window&&'Notification' in window&&!!ME.vapid;
const u8=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
let pushOn=false;
async function pushRefresh(){
 if(!canPush)return false;
 const reg=await navigator.serviceWorker.ready,sub=await reg.pushManager.getSubscription();
 pushOn=!!sub&&Notification.permission==='granted';
 if(pushOn)fetch('/push/subscribe',{method:'POST',headers:JH,body:JSON.stringify(sub.toJSON())}).catch(()=>{}); // keeps the server in sync
 return pushOn;
}
async function pushSet(want){ // returns the state that is really active afterwards
 const reg=await navigator.serviceWorker.ready;let sub=await reg.pushManager.getSubscription();
 if(!want){
  if(sub){
   await fetch('/push/unsubscribe',{method:'POST',headers:JH,body:JSON.stringify({endpoint:sub.endpoint})}).catch(()=>{});
   await sub.unsubscribe();
  }
  return pushRefresh();
 }
 if(Notification.permission==='denied'){toast('Notifications are blocked for this site in your browser settings');return pushRefresh()}
 if(await Notification.requestPermission()!=='granted')return pushRefresh();
 try{
  sub=await reg.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:u8(ME.vapid)});
  const r=await fetch('/push/subscribe',{method:'POST',headers:JH,body:JSON.stringify(sub.toJSON())});
  if(!r.ok){await sub.unsubscribe();throw new Error(await r.text())}
 }catch(e){toast('Could not turn on notifications')}
 return pushRefresh();
}

/* ---- voice messages: record, listen, then send (it goes out as a normal audio attachment) ---- */
const recbar=$('#recbar');let rec=null;
const recMime=()=>['audio/webm;codecs=opus','audio/webm','audio/mp4','audio/ogg;codecs=opus'].find(t=>MediaRecorder.isTypeSupported(t))||'';
const recExt=t=>/mp4|aac/.test(t)?'m4a':/ogg/.test(t)?'ogg':'weba';
const mmss=ms=>{const s=Math.floor(ms/1000);return Math.floor(s/60)+':'+String(s%60).padStart(2,'0')};
function fixDur(a){ // recorded WebM reports no length until it has been scanned once
 a.addEventListener('loadedmetadata',()=>{if(a.duration===Infinity){a.currentTime=1e101;a.addEventListener('timeupdate',function f(){a.removeEventListener('timeupdate',f);a.currentTime=0})}},{once:true});
}
function recClose(){
 if(rec){const R=rec;rec=null;R.cancel=true;clearInterval(R.tm);try{if(R.mr&&R.mr.state!=='inactive')R.mr.stop()}catch(_){}
  if(R.stream)R.stream.getTracks().forEach(t=>t.stop());if(R.url)URL.revokeObjectURL(R.url)}
 recbar.hidden=true;recbar.replaceChildren();
}
const recBtn=(icon,title,cls,fn)=>{const b=el('button','btn '+cls);b.type='button';b.title=title;b.appendChild(svg(icon));b.onclick=fn;return b};
async function recStart(){
 if(rec||locked)return;
 let stream;
 try{stream=await navigator.mediaDevices.getUserMedia({audio:true})}catch(e){return toast('Microphone not available ('+((e&&e.name)||'error')+')')}
 let mr;const mime=recMime(),chunks=[];
 try{mr=new MediaRecorder(stream,mime?{mimeType:mime}:undefined)}catch(_){stream.getTracks().forEach(t=>t.stop());return toast('Recording is not supported here')}
 const R=rec={mr,stream,t0:Date.now()};
 mr.ondataavailable=e=>{if(e.data&&e.data.size)chunks.push(e.data)};
 mr.onstop=()=>{
  stream.getTracks().forEach(t=>t.stop());clearInterval(R.tm);
  if(R.cancel||rec!==R)return;
  const type=(mr.mimeType||mime||'audio/webm').split(';')[0],blob=new Blob(chunks,{type});
  if(!blob.size){recClose();return toast('Nothing was recorded')}
  recReview(R,blob,type);
 };
 const tm=el('span','rt','0:00');
 recbar.replaceChildren(el('i','rdot'),tm,recBtn('x','Cancel','ghost',recClose),recBtn('stop','Stop','',()=>{if(mr.state!=='inactive')mr.stop()}));
 recbar.hidden=false;mr.start();
 R.tm=setInterval(()=>{const d=Date.now()-R.t0;tm.textContent=mmss(d);if(d>=300000&&mr.state!=='inactive')mr.stop()},250); // 5 minutes at most
 if(stick)toBottom();
}
function recReview(R,blob,type){
 R.url=URL.createObjectURL(blob);
 const au=el('audio');au.controls=true;au.src=R.url;fixDur(au);
 const send=recBtn('send','Send','',()=>{
  const d=new Date(),z=n=>String(n).padStart(2,'0');
  const f=new File([blob],'voice-'+d.getFullYear()+z(d.getMonth()+1)+z(d.getDate())+'-'+z(d.getHours())+z(d.getMinutes())+z(d.getSeconds())+'.'+recExt(type),{type});
  const n=pend.length;recClose();addFiles([f]);
  if(pend.length===n)return;
  const p=pend[pend.length-1],t0=Date.now(),w=setInterval(()=>{ // send as soon as the upload is through
   if(p.err||!pend.includes(p)||Date.now()-t0>180000){clearInterval(w);return}
   if(p.ref){clearInterval(w);send_()}},250);
 });
 recbar.replaceChildren(recBtn('trash','Discard','ghost',recClose),au,send);
 if(stick)toBottom();
}
const send_=()=>send();

/* ---- settings ---- */
function switchRow(title,desc,checked,change,first){
 const r=el('div','srow'+(first?' first':'')),t=el('div','tx'),lab=el('label','sw'),i=el('input'),k=el('i');
 i.type='checkbox';i.checked=checked;
 t.appendChild(el('b','',title));t.appendChild(el('span','ds',desc));
 lab.appendChild(i);lab.appendChild(k);r.appendChild(t);r.appendChild(lab);
 i.onchange=async()=>{i.disabled=true;try{i.checked=await change(i.checked)}catch(_){i.checked=!i.checked}i.disabled=false};
 return r;
}
function settings(){
 const o=el('div','modal'),c=el('div','mcard set');
 const k=e=>{if(e.key==='Escape')close()},close=()=>{o.remove();removeEventListener('keydown',k)};
 c.appendChild(el('h3','','Settings'));
 const nr=el('div','srow col first'),f=el('div','nrow'),inp=el('input'),sv=el('button','btn','Save');
 inp.value=ME.name;inp.maxLength=24;inp.placeholder='Nickname';inp.autocomplete='off';sv.type='button';
 sv.onclick=async()=>{sv.disabled=true;const n=await saveNick(inp.value);if(n!==null)inp.value=n;sv.disabled=false};
 inp.onkeydown=e=>{if(e.key==='Enter')sv.click()};
 nr.appendChild(el('b','','Nickname'));f.appendChild(inp);f.appendChild(sv);nr.appendChild(f);
 nr.appendChild(el('span','ds','Leave empty to use your default name.'));c.appendChild(nr);
 if(canPush)c.appendChild(switchRow('Notifications','Get notified about new messages while you are not looking at the chat.',pushOn,on=>pushSet(on)));
 else{const r=el('div','srow');const t=el('div','tx');t.appendChild(el('b','','Notifications'));t.appendChild(el('span','ds','Not available here. On iPhone, add the app to your home screen first.'));r.appendChild(t);c.appendChild(r)}
 c.appendChild(switchRow('Link previews','Show cards for links. The server fetches them for you; a player only loads, straight from its site, when you tap it.',pvOn(),async on=>{try{localStorage.setItem('bc_pv',on?'1':'0')}catch(_){}return on}));
 c.appendChild(switchRow('Auto-collapse embeds','Link cards start collapsed. Tap a card\'s header to open or close it.',pvCol(),async on=>{try{localStorage.setItem('bc_pvc',on?'1':'0')}catch(_){}return on}));
 if(GPS.length>1){
  const gr=el('div','srow col'),gb=el('div','nrow'),cur=gSrc(),bs={};
  gr.appendChild(el('b','','GIF source'));
  GPS.forEach(s=>{const b=el('button',s===cur?'btn sm':'btn ghost sm',GN[s]);b.type='button';bs[s]=b;
   b.onclick=()=>{setGifSource(s);GPS.forEach(x=>bs[x].className=x===s?'btn sm':'btn ghost sm')};gb.appendChild(b)});
  gr.appendChild(gb);gr.appendChild(el('span','ds','Where the GIF picker gets its GIFs, on this device only.'));c.appendChild(gr);
 }
 c.appendChild(switchRow('Fake error screen','Show a fake "502 Bad Gateway" page whenever this device opens the app. Tap its icon 3 times to continue.',!!ME.gate,async on=>{
  const r=await fetch('/gate/setting',{method:'POST',headers:JH,body:JSON.stringify({on})});
  if(r.status===401){relogin();return !on}
  if(!r.ok){toast('Could not change this setting');return !on}
  ME.gate=on;return on;
 }));
 const a=el('div','macts'),done=el('button','btn ghost','Done');done.type='button';done.onclick=close;a.appendChild(done);
 const w=el('div','srow');w.appendChild(a);w.style.justifyContent='flex-end';c.appendChild(w);
 o.onclick=e=>{if(e.target===o)close()};addEventListener('keydown',k);o.appendChild(c);document.body.appendChild(o);
}
$('#setb').onclick=settings;

/* ---- live connection ---- */
function connect(){
 if(es){es.onopen=es.onmessage=es.onerror=null;es.close()}
 const me=es=new EventSource('/events?cid='+cid+'&v='+(document.hidden?0:1));
 lastEv=Date.now();
 me.onopen=()=>{lastEv=Date.now();st.classList.add('on');reconnecting=false;if(opened)sync();opened=true};
 me.onmessage=e=>{
  lastEv=Date.now();st.classList.add('on');
  let ev;try{ev=JSON.parse(e.data)}catch(_){return}
  if(ev.t==='ka')return;
  if(ev.t==='msg'){
   const near=stick;
   if(add(ev.m)){if(near||ev.m.u===ME.uid)toBottom();else pill.hidden=false}
  }else if(ev.t==='del')remove(ev.id);
  else if(ev.t==='heart'){const r=rows.get(ev.id);if(r){r._h=ev.h;paintHearts(r)}}
  else if(ev.t==='wipe'){clearAll();lockInput(ev.lock||5)}
  else if(ev.t==='nick'){document.querySelectorAll('.who,.qwho').forEach(w=>{if(w.dataset.u===ev.u)w.textContent=ev.s});if(ev.u===ME.uid)ME.name=ev.s}
 };
 me.onerror=async()=>{
  st.classList.remove('on');
  try{const r=await fetch('/ping');if(r.status===401){me.close();return relogin()}}catch(_){}
  if(me.readyState===2&&!reconnecting){reconnecting=true;me.close();setTimeout(()=>{reconnecting=false;connect()},3000)}
 };
}
/* a stream that went quiet (sleeping phone, network change, proxy) is replaced and the chat re-synced */
const stale=()=>Date.now()-lastEv>40000;
setInterval(()=>{if(opened&&stale()){st.classList.remove('on');connect()}},10000);
const wake=()=>{if(opened){if(stale())connect();sync()}};
addEventListener('online',wake);addEventListener('pageshow',wake);
document.addEventListener('visibilitychange',()=>{
 fetch('/presence',{method:'POST',headers:JH,keepalive:true,body:JSON.stringify({cid,visible:!document.hidden})}).catch(()=>{});
 if(!document.hidden)wake();
});
/* size the app to what is really visible; also at load and a few times while mobile browsers settle their viewport */
function fit(){
 const h=vv();
 if(Math.abs(innerWidth-vvW)>50){vvW=innerWidth;vvMax=h}  // rotated: forget the old size
 if(h>vvMax)vvMax=h;
 const open=kbdOpen();
 if(wasOpen&&!open&&coarse()&&document.activeElement===ta)ta.blur(); // keyboard dismissed: don't leave the field focused
 wasOpen=open;
 document.body.style.height=h+'px';
 window.scrollTo(0,0);if(stick)toBottom();
}
fit();[60,250,700,1500].forEach(t=>setTimeout(fit,t));
addEventListener('resize',fit);addEventListener('orientationchange',fit);addEventListener('pageshow',fit);
if(window.visualViewport)visualViewport.addEventListener('resize',fit);
/* the fake error page belongs to "opening the app": a PWA that was only suspended wakes up
   without loading the page again, so load it ourselves once the app has been away for a while */
if(ME.gate){
 let away=0;
 document.addEventListener('visibilitychange',()=>{
  if(document.hidden){away=Date.now();return}
  if(away&&Date.now()-away>30000){away=0;location.reload()}
 },true);
 addEventListener('pageshow',e=>{if(e.persisted)location.reload()});
}
(async()=>{
 const j=await fetchPage();if(!j)return;
 j.msgs.forEach(add);older.hidden=!j.more;empty.hidden=rows.size>0;
 toBottom();upd();connect();pushRefresh();
 if(j.lock>0)lockInput(j.lock);
 takeShared();
})();
/* files / text shared to the app from the system share sheet: the service worker parks them in the cache, they land in the composer here */
async function takeShared(){
 try{
  if(!window.caches)return;
  const c=await caches.open('bunnychat-v2'),mr=await c.match('/__share/meta');
  if(!mr)return;
  const meta=await mr.json(),fs=[];
  for(let i=0;i<meta.n;i++){const r=await c.match('/__share/'+i);if(r){const b=await r.blob();fs.push(new File([b],decodeURIComponent(r.headers.get('x-name')||'file'),{type:b.type}))}}
  await c.delete('/__share/meta');for(let i=0;i<meta.n;i++)await c.delete('/__share/'+i);
  try{history.replaceState(null,'','/')}catch(_){}
  if(meta.text){ta.value=ta.value?ta.value+'\n'+meta.text:meta.text;ta.dispatchEvent(new Event('input'))}
  if(fs.length)addFiles(fs);
  upd();
 }catch(_){}
}
})();
"""

SW_JS = r"""const C = 'bunnychat-v2', OFF = '/offline';
self.addEventListener('install', e => e.waitUntil(caches.open(C).then(c => c.add(OFF)).then(() => self.skipWaiting())));
self.addEventListener('activate', e => e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== C).map(k => caches.delete(k)))).then(() => self.clients.claim())));
self.addEventListener('fetch', e => {
  const r = e.request;
  if (r.method === 'POST' && new URL(r.url).pathname === '/share-target') { // "Share to Bunny Tale" from the system share sheet
    e.respondWith((async () => {
      try {
        const f = await r.formData(), c = await caches.open(C);
        const fs = f.getAll('files').filter(x => typeof x !== 'string');
        await Promise.all((await c.keys()).filter(k => k.url.includes('/__share/')).map(k => c.delete(k)));
        await Promise.all(fs.map((x, i) => c.put('/__share/' + i, new Response(x, { headers: { 'x-name': encodeURIComponent(x.name || 'file'), 'content-type': x.type || 'application/octet-stream' } }))));
        const s = k => { const v = f.get(k); return typeof v === 'string' ? v.trim() : ''; };
        let text = [s('text'), s('url')].filter(Boolean).filter((v, i, a) => !a.some((o, j) => j !== i && o.includes(v) && o.length > v.length)).join('\n');
        if (!text && !fs.length) text = s('title');
        await c.put('/__share/meta', new Response(JSON.stringify({ n: fs.length, text })));
      } catch (_) {}
      return Response.redirect('/?share=1', 303);
    })());
    return;
  }
  if (r.mode === 'navigate') e.respondWith(fetch(r).catch(() => caches.match(OFF)));
});
self.addEventListener('push', e => {
  let d = {};
  try { d = e.data.json(); } catch (_) {}
  e.waitUntil(self.registration.showNotification(d.title || 'Bunny Tale', {
    body: d.body || 'New message', icon: '/icon-192.png', tag: 'bunnychat', renotify: true, data: { url: '/' }}));
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(clients.matchAll({ type: 'window', includeUncontrolled: true }).then(cs => {
    const c = cs.find(w => 'focus' in w);
    return c ? c.focus() : clients.openWindow('/');
  }));
});
"""


# ---- pwa / static ----
GATE_TTL = 120  # safety net only: the pass is spent by the first page load it unlocks
_gate_ser = URLSafeTimedSerializer(app.secret_key, salt="bunnychat-gate")

GATE_HTML = """<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1,viewport-fit=cover,interactive-widget=resizes-content">
<meta name=robots content="noindex,nofollow"><title>502 Bad Gateway</title>
<link rel=icon href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Ccircle cx='12' cy='12' r='11' fill='%23dc2626'/%3E%3Cpath d='M12 6v7M12 16.5v.5' stroke='white' stroke-width='2.4' stroke-linecap='round'/%3E%3C/svg%3E">
<style>
html,body{height:100%;margin:0}
body{display:flex;align-items:center;justify-content:center;background:#f5f6f8;color:#1f2937;font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;text-align:center;padding:24px;box-sizing:border-box}
.box{max-width:480px;width:100%}
#i{width:112px;height:112px;margin:0 auto 18px;display:block;cursor:default;user-select:none;-webkit-user-select:none;-webkit-tap-highlight-color:transparent;touch-action:manipulation}
.code{font-size:80px;font-weight:800;color:#dc2626;line-height:1;letter-spacing:-3px}
h1{font-size:28px;margin:10px 0 14px;font-weight:700}
p{color:#4b5563;margin:0 0 10px}
button{margin-top:14px;background:#1f2937;color:#fff;border:0;border-radius:8px;padding:11px 22px;font:inherit;font-weight:600;cursor:pointer}
button:hover{background:#111827}
.foot{margin-top:40px;padding-top:16px;border-top:1px solid #e5e7eb;color:#9ca3af;font-size:13px}
</style>
<body><div class=box>
<svg id="i" viewBox="0 0 112 112" aria-hidden="true">
<rect x="14" y="22" width="84" height="30" rx="7" fill="#e5e7eb" stroke="#9ca3af" stroke-width="2.5" />
<rect x="14" y="60" width="84" height="30" rx="7" fill="#e5e7eb" stroke="#9ca3af" stroke-width="2.5" />
<circle cx="30" cy="37" r="4" fill="#9ca3af"/><circle cx="30" cy="75" r="4" fill="#dc2626"/>
<rect x="44" y="34" width="34" height="6" rx="3" fill="#cbd5e1"/><rect x="44" y="72" width="34" height="6" rx="3" fill="#cbd5e1"/>
<circle cx="88" cy="88" r="20" fill="#dc2626" stroke="#f5f6f8" stroke-width="4" />
<path d="M80 80l16 16M96 80L80 96" stroke="#fff" stroke-width="4.5" stroke-linecap="round"/>
</svg>
<div class=code>502</div>
<h1>Bad Gateway</h1>
<p>The server received an invalid response from another server while trying to load this page.</p>
<p>This is usually temporary. Please wait a few minutes and try again.</p>
<button onclick="location.reload()">Try again</button>
<div class=foot>Error 502 &middot; nginx</div>
</div>
<script>
(function(){var n=0,t,i=document.getElementById('i');
i.addEventListener('click',function(){n++;clearTimeout(t);t=setTimeout(function(){n=0},1200);
if(n>=3){n=0;fetch('/gate/pass',{method:'POST'}).then(function(){location.replace('/')})}})})();
</script></html>"""


def gate_on():
    return request.cookies.get("bc_gw") == "1"


def gate_passed():
    try:
        _gate_ser.loads(request.cookies.get("bc_gp", ""), max_age=GATE_TTL)
        return True
    except Exception:
        return False


def give_pass(resp):
    resp.set_cookie("bc_gp", _gate_ser.dumps(1), max_age=GATE_TTL, httponly=True, samesite="Lax")
    return resp


@app.before_request
def gate():  # optional disguise: pages look like a broken proxy until the icon is tapped 3 times
    if request.method == "GET" and request.path in ("/", "/login") and gate_on():
        if gate_passed():
            g.gate_used = True  # single use: this page load spends the pass
        else:
            return Response(GATE_HTML, status=502, mimetype="text/html", headers={"Cache-Control": "no-store"})


@app.route("/gate/pass", methods=["POST"])
def gate_pass():
    return give_pass(Response("", 204))


@app.route("/gate/setting", methods=["POST"])
def gate_setting():
    if not auth():
        return "", 401
    on = bool((request.get_json(silent=True) or {}).get("on"))
    resp = Response("", 204)
    if on:
        resp.set_cookie("bc_gw", "1", max_age=365 * 86400, httponly=True, samesite="Lax")
    else:
        resp.delete_cookie("bc_gw")
        resp.delete_cookie("bc_gp")
    return resp


@app.after_request
def headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("Permissions-Policy", "microphone=(self)")  # voice messages
    if request.path in ("/", "/login"):
        resp.headers.setdefault("Cache-Control", "no-store")  # a reload must always reach the gate
    if getattr(g, "gate_used", False) and resp.status_code == 200:
        resp.delete_cookie("bc_gp")  # one pass = one page load
    return resp


@app.route("/manifest.webmanifest")
def manifest():
    return Response(json.dumps({
        "id": "/", "name": "Bunny Tale", "short_name": "Bunny Tale", "start_url": "/", "scope": "/", "display": "standalone",
        "share_target": {"action": "/share-target", "method": "POST", "enctype": "multipart/form-data",
                         "params": {"title": "title", "text": "text", "url": "url",
                                    "files": [{"name": "files", "accept": ["image/*", "video/*", "audio/*", "application/*", "text/*"]}]}},
        "background_color": "#09090b", "theme_color": "#09090b",
        "icons": [
            {"src": f"/icon-192.png?v={ICON_V}", "sizes": "192x192", "type": "image/png", "purpose": "any"},
            {"src": f"/icon-512.png?v={ICON_V}", "sizes": "512x512", "type": "image/png", "purpose": "any"},
            {"src": f"/icon-maskable.png?v={ICON_V}", "sizes": "512x512", "type": "image/png", "purpose": "maskable"}]}),
        mimetype="application/manifest+json", headers={"Cache-Control": "no-cache"})


@app.route("/sw.js")
def sw():
    return Response(SW_JS, mimetype="text/javascript", headers={"Cache-Control": "no-cache"})


@app.route("/app.js")
def appjs():
    return Response(CHAT_JS, mimetype="text/javascript", headers={"Cache-Control": "no-cache"})


@app.route("/icon-<name>.png")
def icon(name):
    data = {"192": ICON_192, "512": ICON_512, "maskable": ICON_MASK}.get(name)
    if not data:
        return "", 404
    return Response(data, mimetype="image/png", headers={"Cache-Control": "no-cache"})


@app.route("/favicon.ico")
def favicon():
    return Response(FAVICON, mimetype="image/x-icon", headers={"Cache-Control": "no-cache"})


@app.route("/share-target", methods=["POST"])
def share_target():  # normally answered by the service worker; this only catches a share that arrives without it
    return redirect("/", 303)


@app.route("/offline")
def offline():  # rendered without flash messages so the service worker's install fetch can't consume any
    return render_template_string(LAYOUT, cls="auth", msgs=[], iv=ICON_V, body=render_template_string(OFFLINE))


@app.route("/ping")
def ping():
    return ("", 204) if auth() else ("", 401)


# ---- auth ----
@app.route("/login", methods=["GET", "POST"])
def login():
    nxt = request.values.get("next", "")
    if not (nxt.startswith("/") and not nxt.startswith("//") and "\\" not in nxt and len(nxt) < 300):
        nxt = ""
    if request.method == "POST":
        f = request.form
        creds = {"license": f["license"].strip(), "email": f["email"].strip(), "password": f["password"]}
        try:
            r = bunny_login(creds)
            if r.ok:
                pool_set(creds, token_of(r))
                new_session(creds["email"], stay=bool(f.get("stay")))
                try:
                    master()  # load / create the chat key before letting the user in
                except Exception as e:
                    drop()
                    raise RuntimeError(f"Chat setup failed: {e}")
                touch_activity(True)
                resp = remember(redirect(nxt or "/"), creds)
                stay_forget(request.cookies.get("bc_rt"))
                if f.get("stay"):
                    tok = stay_save(creds)
                    AUTO[_h(tok)] = session["sid"]
                    resp.set_cookie("bc_rt", tok, max_age=STAY_DAYS * 86400, httponly=True, samesite="Lax")
                else:
                    resp.delete_cookie("bc_rt")
                return resp
            flash(reason(r))
        except Exception as e:
            flash(str(e))
    return page(LOGIN, "auth", lic=request.form.get("license") or request.cookies.get("bc_lic", ""),
                em=request.form.get("email") or request.cookies.get("bc_em", ""), nxt=nxt)


@app.route("/logout")
def logout():
    drop()
    stay_forget(request.cookies.get("bc_rt"))
    resp = redirect("/login")
    resp.delete_cookie("bc_rt")
    return resp


# ---- chat ----
def fail(e):  # error response for a failed Bunny call
    return ("", 401) if isinstance(e, AuthError) else (str(e), 502)


@app.route("/")
def index():
    s = auth()
    if not s:
        return redirect("/login")
    try:
        m = master()
        uid = uid_of(s["email"])
        me = {"uid": uid, "name": nick_map(m).get(uid) or s["name"], "vapid": vapid()[1], "gate": gate_on(),
              "gif": {"giphy": {"key": GIPHY_KEY, "rating": GIPHY_RATING} if GIPHY_KEY else None,
                      "klipy": {"key": KLIPY_KEY, "rating": GIPHY_RATING} if KLIPY_KEY else None}}
    except AuthError:
        return redirect("/login")
    except Exception as e:
        return page(ERR, "auth", err=str(e))
    touch_activity()
    ver = hashlib.sha1(CHAT_JS.encode()).hexdigest()[:8]
    return page(CHAT, "chatpg", me=me, ver=ver)


@app.route("/messages")
def messages():
    if not auth():
        return "", 401
    limit = 50
    before = request.args.get("before", type=int)
    try:
        m = master()
    except Exception as e:
        return fail(e)
    with conn() as c:
        if before:
            rows = c.execute(f"SELECT {COLS} FROM messages WHERE id<? ORDER BY id DESC LIMIT ?",
                             (before, limit + 1)).fetchall()
        else:
            rows = c.execute(f"SELECT {COLS} FROM messages ORDER BY id DESC LIMIT ?", (limit + 1,)).fetchall()
    more = len(rows) > limit
    out = decode_rows(m, rows[:limit], nick_map(m))
    out.reverse()
    return jsonify({"msgs": out, "more": more, "lock": max(0.0, round(WIPE_UNTIL - time.time(), 1))})


@app.route("/send", methods=["POST"])
def send():
    s = auth()
    if not s:
        return "", 401
    if time.time() < WIPE_UNTIL:
        return "The chat was just wiped, please wait a moment", 423
    j = request.get_json(silent=True) or {}
    text = str(j.get("text") or "").strip()
    if len(text) > MAX_TEXT:
        return f"Message too long (max {MAX_TEXT} characters)", 400
    atts, seen = [], set()
    for a in (j.get("media") or [])[:MAX_ATT]:
        ref = str(a.get("ref", "")) if isinstance(a, dict) else ""
        if not MEDIA_RE.match(ref) or ref in seen:
            return "Invalid attachment", 400
        seen.add(ref)
        name = re.sub(r"[\x00-\x1f]", "", str(a.get("name") or ref))[:120]
        size = a.get("size") if isinstance(a.get("size"), int) else 0
        atts.append({"r": ref, "n": name, "z": size, "k": kind_of(ref)})
    gif, g = None, j.get("gif")
    if g is not None:  # a GIF picked from GIPHY or Klipy: only a reference and the size are kept, the picture is loaded by the browsers
        if not isinstance(g, dict) or not isinstance(g.get("id"), str):
            return "Invalid GIF", 400
        prov = g.get("p") or "giphy"
        dim = lambda v: v if isinstance(v, int) and not isinstance(v, bool) and 1 <= v <= 2000 else 200
        gif = {"id": g["id"], "w": dim(g.get("w")), "h": dim(g.get("h")),
               "t": re.sub(r"[\x00-\x1f]", "", str(g.get("t") or ""))[:100]}
        if prov == "giphy" and GIPHY_KEY and re.fullmatch(r"[A-Za-z0-9]{5,32}", g["id"]):
            pass
        elif (prov == "klipy" and KLIPY_KEY and re.fullmatch(r"[A-Za-z0-9_\-]{3,160}", g["id"])
              and all(isinstance(g.get(k), str) and KLIPY_URL.fullmatch(g[k]) for k in ("u", "f"))):
            gif.update(p="klipy", u=g["u"], f=g["f"])
        else:
            return "Invalid GIF", 400
    if not text and not atts and not gif:
        return "Empty message", 400
    rid = j.get("reply")
    if rid is not None and (not isinstance(rid, int) or isinstance(rid, bool)):
        return "Bad request", 400
    try:
        m = master()
        uid = uid_of(s["email"])
    except Exception as e:
        return fail(e)
    nk = nick_map(m)
    name = nk.get(uid) or s["name"]
    payload = {"s": name, "t": text, "a": atts}
    if gif:
        payload["g"] = gif
    if rid:
        with conn() as c:
            if not c.execute("SELECT 1 FROM messages WHERE id=?", (rid,)).fetchone():
                return "The message you replied to was deleted", 409
        payload["r"] = rid
    mk = os.urandom(32)  # this message's own key; it lives only in this row
    ts = int(time.time() * 1000)
    with conn() as c:
        for a in atts:
            if c.execute("SELECT 1 FROM media WHERE ref=?", (a["r"],)).fetchone():
                return "Attachment already used", 400
        cur = c.execute("INSERT INTO messages(ts,uid,mkey,body) VALUES(?,?,?,?)",
                        (ts, uid, seal(m, mk), seal(m, seal(mk, json.dumps(payload).encode()))))
        mid = cur.lastrowid
        c.executemany("INSERT INTO media VALUES(?,?)", [(a["r"], mid) for a in atts])
    ev = {"id": mid, "ts": ts, "u": uid, "s": name, "t": text, "a": atts, "h": [], "g": gif}
    if rid:
        ev["q"] = quote_of(m, rid, nk)
    touch_activity()
    publish({"t": "msg", "m": ev})
    PUSHPOOL.submit(notify, uid, name, atts, text, bool(gif))
    return jsonify(ev)


@app.route("/heart", methods=["POST"])
def heart():
    s = auth()
    if not s:
        return "", 401
    mid = (request.get_json(silent=True) or {}).get("id")
    if not isinstance(mid, int):
        return "Bad request", 400
    try:
        master()
        uid = uid_of(s["email"])
    except Exception as e:
        return fail(e)
    with conn() as c:
        if not c.execute("SELECT 1 FROM messages WHERE id=?", (mid,)).fetchone():
            return "Message not found", 404
        if c.execute("SELECT 1 FROM hearts WHERE msg_id=? AND uid=?", (mid, uid)).fetchone():
            c.execute("DELETE FROM hearts WHERE msg_id=? AND uid=?", (mid, uid))
        else:
            c.execute("INSERT INTO hearts VALUES(?,?)", (mid, uid))
        h = [u for (u,) in c.execute("SELECT uid FROM hearts WHERE msg_id=? ORDER BY rowid", (mid,))]
    publish({"t": "heart", "id": mid, "h": h})
    return jsonify({"id": mid, "h": h})


@app.route("/delete", methods=["POST"])
def delete():
    s = auth()
    if not s:
        return "", 401
    mid = (request.get_json(silent=True) or {}).get("id")
    if not isinstance(mid, int):
        return "Bad request", 400
    try:
        master()
        uid = uid_of(s["email"])
    except Exception as e:
        return fail(e)
    with conn() as c:
        row = c.execute("SELECT uid FROM messages WHERE id=?", (mid,)).fetchone()
        if not row:
            return "Message not found", 404
        if row[0] != uid:
            return "You can only delete your own messages", 403
        refs = [r for (r,) in c.execute("SELECT ref FROM media WHERE msg_id=?", (mid,))]
        c.execute("DELETE FROM media WHERE msg_id=?", (mid,))
        c.execute("DELETE FROM hearts WHERE msg_id=?", (mid,))
        c.execute("DELETE FROM messages WHERE id=?", (mid,))  # the message and its key go together
    wipe_checkpoint()
    for ref in refs:
        try:
            api("GET", "/api/delete", headers={H_FILENAME: ref})
        except Exception:
            pass
    publish({"t": "del", "id": mid})
    return "", 200


@app.route("/nick", methods=["POST"])
def set_nick():
    s = auth()
    if not s:
        return "", 401
    nick = re.sub(r"\s+", " ", re.sub(r"[\x00-\x1f\x7f]", "", str((request.get_json(silent=True) or {}).get("nick") or ""))).strip()
    if len(nick) > 24:
        return "Nickname is too long (max 24 characters)", 400
    try:
        m = master()
        uid = uid_of(s["email"])
    except Exception as e:
        return fail(e)
    with conn() as c:
        if nick:
            taken = {v.casefold() for k, v in nick_map(m).items() if k != uid}
            if nick.casefold() in taken:
                return "That nickname is already taken", 409
            c.execute("INSERT OR REPLACE INTO nicks VALUES(?,?)", (uid, seal(m, nick.encode())))
        else:
            c.execute("DELETE FROM nicks WHERE uid=?", (uid,))
    name = nick or s["name"]
    publish({"t": "nick", "u": uid, "s": name})
    return jsonify({"name": name})


@app.route("/wipe", methods=["POST"])
def wipe():
    global WIPE_UNTIL
    if not auth():
        return "", 401
    try:
        master()
    except Exception as e:
        return fail(e)
    with _wipe_lock:
        WIPE_UNTIL = time.time() + WIPE_LOCK  # nobody can write for a few seconds
        with conn() as c:
            refs = [r for (r,) in c.execute("SELECT ref FROM media")]
            c.execute("DELETE FROM media")
            c.execute("DELETE FROM hearts")
            c.execute("DELETE FROM messages")  # every message key goes with its row
        wipe_db()
        pv_clear()
    publish({"t": "wipe", "lock": WIPE_LOCK})
    for ref in refs:
        try:
            api("GET", "/api/delete", headers={H_FILENAME: ref})
        except Exception:
            pass
    return "", 200


@app.route("/events")
def events():
    s = auth()
    if not s:
        return "", 401
    try:
        master()
        uid = uid_of(s["email"])
    except Exception as e:
        return fail(e)
    sid = session.get("sid")
    q = queue.Queue(256)
    cid = request.args.get("cid", "")[:64]
    with _slock:
        if cid:  # a page that reconnects replaces its own earlier (maybe half-dead) stream
            for q0, i0 in list(SUBS.items()):
                if i0["cid"] == cid:
                    SUBS.pop(q0, None)
                    try:
                        q0.put_nowait(None)
                    except queue.Full:
                        pass
        SUBS[q] = {"uid": uid, "cid": cid, "visible": request.args.get("v", "1") == "1"}

    def gen():
        born = time.time()
        try:
            yield "retry: 3000\n\n"
            while True:
                try:
                    ev = q.get(timeout=max(0.5, min(15, SSE_MAX_AGE - (time.time() - born))))
                    if ev is None:
                        return
                    yield f"data: {json.dumps(ev)}\n\n"
                except queue.Empty:
                    with _slock:
                        if q not in SUBS:
                            return
                    if time.time() - born >= SSE_MAX_AGE or not alive(sid):
                        return  # the browser reconnects and re-syncs by itself
                    yield 'data: {"t":"ka"}\n\n'  # a real event, so the page can tell the stream is alive
        finally:
            with _slock:
                SUBS.pop(q, None)

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/presence", methods=["POST"])
def presence():  # is this page in front of the user? (pushes only go to users who are not looking)
    s = auth()
    if not s:
        return "", 401
    j = request.get_json(silent=True) or {}
    cid = str(j.get("cid", ""))[:64]
    if cid:
        with _slock:
            for info in SUBS.values():
                if info["cid"] == cid:
                    info["visible"] = bool(j.get("visible"))
    return "", 204


# ---- push subscriptions ----
@app.route("/push/subscribe", methods=["POST"])
def push_subscribe():
    s = auth()
    if not s:
        return "", 401
    j = request.get_json(silent=True) or {}
    keys = j.get("keys") if isinstance(j.get("keys"), dict) else {}
    ep = str(j.get("endpoint", ""))
    if not push_ok_endpoint(ep) or not keys.get("p256dh") or not keys.get("auth"):
        return "Unsupported push service", 400
    try:
        m = master()
        uid = uid_of(s["email"])
    except Exception as e:
        return fail(e)
    sub = {"endpoint": ep, "keys": {"p256dh": str(keys["p256dh"]), "auth": str(keys["auth"])}}
    with conn() as c:
        c.execute("INSERT OR REPLACE INTO push VALUES(?,?,?)",
                  (hashlib.sha256(ep.encode()).hexdigest(), uid, seal(m, json.dumps(sub).encode())))
    return "", 204


@app.route("/push/unsubscribe", methods=["POST"])
def push_unsubscribe():
    s = auth()
    if not s:
        return "", 401
    ep = str((request.get_json(silent=True) or {}).get("endpoint", ""))
    try:
        master()
        uid = uid_of(s["email"])
    except Exception as e:
        return fail(e)
    with conn() as c:
        c.execute("DELETE FROM push WHERE eid=? AND uid=?", (hashlib.sha256(ep.encode()).hexdigest(), uid))
    return "", 204


# ---- media (stored on the Bunny server under random names, referenced from the database) ----
@app.route("/media/upload", methods=["POST"])
def media_upload():
    if not auth():
        return "", 401
    if time.time() < WIPE_UNTIL:
        return "The chat was just wiped, please wait a moment", 423
    orig = unquote(request.headers.get("X-File-Name", "")) or "file"
    ext = orig.rsplit(".", 1)[-1].lower() if "." in orig else ""
    ext = ext if re.fullmatch(r"[a-z0-9]{1,8}", ext) else "bin"
    ref = f"{MEDIA_PREFIX}bc-{secrets.token_hex(12)}.{ext}"
    boundary = secrets.token_hex(16)
    head = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{ref}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n").encode()
    tail = f"\r\n--{boundary}--\r\n".encode()

    def body():
        yield head
        while chunk := request.stream.read(65536):
            yield chunk
        yield tail

    try:
        r = api("POST", "/api/upload", data=body(), timeout=(30, None), headers={
            "File-Size": str(request.content_length or 0),
            "Content-Type": f"multipart/form-data; boundary={boundary}"})
    except (AuthError, BunnyError) as e:
        return fail(e)
    if not r.ok:
        return reason(r), 400
    return jsonify({"ref": ref, "k": kind_of(ref)})


@app.route("/media/discard", methods=["POST"])
def media_discard():  # removes an attachment that was uploaded but never sent
    if not auth():
        return "", 401
    ref = str((request.get_json(silent=True) or {}).get("ref", ""))
    if not MEDIA_RE.match(ref):
        return "Bad request", 400
    with conn() as c:
        if c.execute("SELECT 1 FROM media WHERE ref=?", (ref,)).fetchone():
            return "", 409
    try:
        api("GET", "/api/delete", headers={H_FILENAME: ref})
    except (AuthError, BunnyError) as e:
        return fail(e)
    return "", 200


@app.route("/media/<ref>")
def media_get(ref):
    if not MEDIA_RE.match(ref):
        return "", 404
    if not auth():
        return "", 401
    with conn() as c:
        if not c.execute("SELECT 1 FROM media WHERE ref=?", (ref,)).fetchone():
            return "", 404  # only files that belong to a message are served
    try:
        r = api("GET", "/api/download", headers={H_FILENAME: ref}, stream=True, timeout=(30, None))
    except (AuthError, BunnyError) as e:
        return fail(e)
    if not r.ok:
        return reason(r), 400
    total = int(r.headers.get("Content-Length") or 0)
    start, end, status = 0, total - 1, 200
    m = re.match(r"bytes=(\d*)-(\d*)$", request.headers.get("Range", "")) if total else None
    if m and (m[1] or m[2]):
        if m[1]:
            start = int(m[1])
            if m[2]:
                end = min(int(m[2]), end)
        else:
            start = max(total - int(m[2]), 0)
        if start > end:
            r.close()
            return "", 416, {"Content-Range": f"bytes */{total}"}
        status = 206

    def gen():  # upstream has no range support: skip bytes up to `start`, stop after `end`
        skip, left = start, (end - start + 1) if total else float("inf")
        try:
            for chunk in r.iter_content(262144):
                if skip:
                    if len(chunk) <= skip:
                        skip -= len(chunk)
                        continue
                    chunk, skip = chunk[skip:], 0
                if len(chunk) >= left:
                    yield chunk[:int(left)]
                    return
                left -= len(chunk)
                yield chunk
        finally:
            r.close()

    inline = kind_of(ref) != "file" and not request.args.get("dl")
    disp = "inline"
    if not inline:
        n = re.sub(r'[\x00-\x1f"\\/]', "_", request.args.get("n") or ref)[:120]
        disp = f"attachment; filename*=UTF-8''{quote(n)}"
    h = {"Accept-Ranges": "bytes", "Content-Disposition": disp, "Cache-Control": "private, max-age=86400",
         "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "sandbox"}
    if total:
        h["Content-Length"] = str(end - start + 1)
    if status == 206:
        h["Content-Range"] = f"bytes {start}-{end}/{total}"
    return Response(gen(), status=status, headers=h,
                    content_type=mimetypes.guess_type(ref)[0] or "application/octet-stream")


# idle auto-wipe watcher (one per process)
if AUTOWIPE_HOURS > 0 and os.environ.get("WERKZEUG_RUN_MAIN") != "false":
    threading.Thread(target=janitor, daemon=True).start()


# --- PWA icons: plain files in the "icons" folder next to this file ---
ICON_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons")


def _icon(name):
    try:
        with open(os.path.join(ICON_DIR, name), "rb") as f:
            return f.read()
    except OSError:
        raise RuntimeError(f"Icon file {name} not found in {ICON_DIR}. Copy the 'icons' folder next to app.py (Dockerfile: COPY icons ./icons).")


ICON_192, ICON_512, ICON_MASK, FAVICON = (_icon(n) for n in ("icon-192.png", "icon-512.png", "icon-maskable.png", "favicon.ico"))
ICON_V = hashlib.sha1(ICON_192 + ICON_512 + ICON_MASK + FAVICON).hexdigest()[:8]  # changes whenever the icons change

import os, re, time, secrets, sqlite3, json, base64, threading
from collections import defaultdict, deque
from datetime import datetime
from flask import jsonify, Flask, g, request, session, redirect, url_for, render_template, abort, flash
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("DB_PATH", os.path.join(BASE, "snezhok.db"))
app = Flask(__name__)
kf = os.path.join(BASE, ".secret")
if not os.path.exists(kf):
    open(kf, "w").write(secrets.token_hex(32))
app.secret_key = os.environ.get("SECRET_KEY") or open(kf).read()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=bool(os.environ.get("HTTPS")), PERMANENT_SESSION_LIFETIME=60*60*24*30, MAX_CONTENT_LENGTH=64 * 1024)
if os.environ.get("BEHIND_PROXY"):
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

SCHEMA = """
create table if not exists users(id integer primary key, name text unique collate nocase, pw text, bio text default '', created real);
create table if not exists posts(id integer primary key, uid integer, body text, ts real);
create table if not exists likes(uid integer, pid integer, primary key(uid,pid));
create table if not exists comments(id integer primary key, uid integer, pid integer, body text, ts real);
create table if not exists msgs(id integer primary key, frm integer, too integer, body text, ts real);
create table if not exists kv(k text primary key, v text);
create table if not exists push_subs(id integer primary key, uid integer, endpoint text unique, p256dh text, auth text);
"""
DBURL = os.environ.get("DATABASE_URL")  # если задан — Postgres (данные хранятся постоянно), иначе файл SQLite
SCHEMA_PG = ["create extension if not exists citext",
 "create table if not exists users(id serial primary key, name citext unique, pw text, bio text default '', created double precision)",
 "create table if not exists posts(id serial primary key, uid integer, body text, ts double precision)",
 "create table if not exists likes(uid integer, pid integer, primary key(uid,pid))",
 "create table if not exists comments(id serial primary key, uid integer, pid integer, body text, ts double precision)",
 "create table if not exists msgs(id serial primary key, frm integer, too integer, body text, ts double precision)",
 "create table if not exists kv(k text primary key, v text)",
 "create table if not exists push_subs(id serial primary key, uid integer, endpoint text unique, p256dh text, auth text)"]

def tr(q): return re.sub(r"\blike\b", "ilike", q.replace("?", "%s"))

class R:
    def __init__(s, cur, lid=None): s.cur, s.lastrowid, s.rowcount = cur, lid, cur.rowcount
    def fetchone(s): return s.cur.fetchone()
    def fetchall(s): return s.cur.fetchall()

class Conn:
    def __init__(s):
        if DBURL:
            import psycopg
            from psycopg.rows import dict_row
            s.c = psycopg.connect(DBURL, row_factory=dict_row)
        else:
            s.c = sqlite3.connect(DB); s.c.row_factory = sqlite3.Row
    def execute(s, q, a=()):
        if not DBURL: return s.c.execute(q, a)
        q = tr(q); ins = q.lstrip().startswith("insert into users")
        if ins: q += " returning id"
        cur = s.c.execute(q, a)
        return R(cur, cur.fetchone()["id"] if ins else None)
    def commit(s): s.c.commit()
    def close(s): s.c.close()

ALT = [("users", "last_seen", "real default 0"), ("users", "typing_to", "integer"),
       ("users", "typing_ts", "real default 0"), ("msgs", "seen", "integer default 0")]
def init():
    c = Conn()
    if DBURL:
        for st in SCHEMA_PG: c.execute(st)
        for t, col, typ in ALT: c.execute(f"alter table {t} add column if not exists {col} {typ.replace('real', 'double precision')}")
    else:
        c.c.executescript(SCHEMA)
        for t, col, typ in ALT:
            try: c.c.execute(f"alter table {t} add column {col} {typ}")
            except sqlite3.OperationalError: pass
    c.commit(); c.close()
init()

def db():
    if "db" not in g: g.db = Conn()
    return g.db
@app.teardown_appcontext
def close(_):
    d = g.pop("db", None)
    if d: d.close()

# ---- защита от спама: не более n действий за sec секунд ----
hits = defaultdict(deque)
def limited(key, n, sec):
    now = time.time(); q = hits[key]
    while q and q[0] < now - sec: q.popleft()
    if len(q) >= n: return True
    q.append(now); return False

def me():
    if "uid" not in session: return None
    if not hasattr(g, "me"):
        g.me = db().execute("select * from users where id=?", (session["uid"],)).fetchone()
        if g.me is None: session.clear(); return None
    return g.me
@app.context_processor
def ctx():
    return dict(me=me(), csrf=session.setdefault("csrf", secrets.token_hex(16)))
@app.template_filter("hue")
def hue(s): return sum(map(ord, s)) * 37 % 360
@app.template_filter("tm")
def tm(t): return datetime.fromtimestamp(t).strftime("%H:%M")
@app.template_filter("dt")
def dt(t): return datetime.fromtimestamp(t).strftime("%d.%m.%Y %H:%M")

@app.before_request
def guard():
    if request.method == "POST" and request.form.get("csrf", "") != session.get("csrf", None):
        abort(400)
    if request.endpoint not in ("login", "register", "static", "sw", "manifest") and not me():
        return redirect(url_for("login"))
def back(): return redirect(request.referrer or url_for("feed"))
def spam(kind, n=10, sec=60):
    if limited(f"{kind}:{session.get('uid')}", n, sec):
        flash("⛄ Слишком часто! Подожди минутку — защита от спама."); return True
    return False

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if limited("reg:" + request.remote_addr, 5, 3600):
            flash("Слишком много регистраций с вашего адреса. Попробуйте позже.")
        else:
            n, p = request.form.get("name", "").strip(), request.form.get("password", "")
            u0 = db().execute("select * from users where name=?", (n,)).fetchone()
            if not re.fullmatch(r"[A-Za-zА-Яа-яЁё0-9_]{3,20}", n): flash("Имя: 3–20 букв, цифр или _")
            elif len(p) < 6: flash("Пароль минимум 6 символов")
            elif u0 and check_password_hash(u0["pw"], p):
                session.clear(); session.permanent = True; session["uid"] = u0["id"]
                return redirect(url_for("feed"))
            elif u0: flash("Это имя уже занято. Если это ваш аккаунт, нажмите «Войти» и введите свой пароль.")
            else:
                c = db().execute("insert into users(name,pw,created) values(?,?,?)", (n, generate_password_hash(p), time.time()))
                db().commit(); session.clear(); session.permanent = True; session["uid"] = c.lastrowid
                return redirect(url_for("feed"))
    return render_template("auth.html", reg=True)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if limited("login:" + request.remote_addr, 8, 300):
            flash("Слишком много попыток входа. Подождите 5 минут.")
        else:
            u = db().execute("select * from users where name=?", (request.form.get("name", "").strip(),)).fetchone()
            if u and check_password_hash(u["pw"], request.form.get("password", "")):
                session.clear(); session.permanent = True; session["uid"] = u["id"]; return redirect(url_for("feed"))
            flash("Неверное имя или пароль")
    return render_template("auth.html", reg=False)

@app.route("/logout", methods=["POST"])
def logout():
    session.clear(); return redirect(url_for("login"))

def posts(where="", args=(), n=10):
    rows = db().execute("select p.*,u.name,(select count(*) from likes where pid=p.id) lk,"
        "(select count(*) from likes where pid=p.id and uid=?) liked from posts p join users u on u.id=p.uid "
        + where + " order by p.id desc limit ?", (me()["id"], *args, n + 1)).fetchall()
    out = []
    for r in rows[:n]:
        d = dict(r)
        d["comments"] = db().execute("select c.*,u.name from comments c join users u on u.id=c.uid where pid=? order by c.id", (r["id"],)).fetchall()
        out.append(d)
    return out, len(rows) > n
def nparam(): return min(max(request.args.get("n", 10, type=int), 10), 300)

@app.route("/")
def feed():
    n = nparam(); p, more = posts(n=n)
    return render_template("feed.html", posts=p, more=more, n=n + 10)

@app.route("/post", methods=["POST"])
def post():
    b = request.form.get("body", "").strip()[:1000]
    if b and not spam("post", 5):
        db().execute("insert into posts(uid,body,ts) values(?,?,?)", (me()["id"], b, time.time())); db().commit()
    return redirect(url_for("feed"))

@app.route("/like/<int:id>", methods=["POST"])
def like(id):
    if spam("like", 40): return back()
    d = db()
    if d.execute("select 1 from likes where uid=? and pid=?", (me()["id"], id)).fetchone():
        d.execute("delete from likes where uid=? and pid=?", (me()["id"], id))
    elif d.execute("select 1 from posts where id=?", (id,)).fetchone():
        d.execute("insert into likes values(?,?)", (me()["id"], id))
    d.commit(); return back()

@app.route("/comment/<int:id>", methods=["POST"])
def comment(id):
    b = request.form.get("body", "").strip()[:500]
    if b and not spam("comment", 10) and db().execute("select 1 from posts where id=?", (id,)).fetchone():
        db().execute("insert into comments(uid,pid,body,ts) values(?,?,?,?)", (me()["id"], id, b, time.time())); db().commit()
    return back()

@app.route("/delete/post/<int:id>", methods=["POST"])
def delpost(id):
    d = db()
    if d.execute("delete from posts where id=? and uid=?", (id, me()["id"])).rowcount:
        d.execute("delete from comments where pid=?", (id,)); d.execute("delete from likes where pid=?", (id,))
    d.commit(); return back()

@app.route("/delete/comment/<int:id>", methods=["POST"])
def delcomment(id):
    db().execute("delete from comments where id=? and uid=?", (id, me()["id"])); db().commit(); return back()

@app.route("/u/<name>")
def profile(name):
    u = db().execute("select * from users where name=?", (name,)).fetchone() or abort(404)
    n = nparam(); p, more = posts("where p.uid=?", (u["id"],), n)
    return render_template("profile.html", u=u, posts=p, more=more, n=n + 10)

@app.route("/search")
def search():
    q = request.args.get("q", "").strip()[:50]; users, p = [], []
    if q:
        like_ = "%" + q.replace("%", "").replace("_", "") + "%"
        users = db().execute("select name,bio from users where name like ? limit 30", (like_,)).fetchall()
        p, _ = posts("where p.body like ?", (like_,), 30)
    return render_template("search.html", q=q, users=users, posts=p)

@app.route("/chats")
def chats():
    i = me()["id"]
    users = db().execute("select u.name,m.body,m.ts,(select count(*) from msgs x where x.frm=u.id and x.too=? and x.seen=0) un from msgs m join users u on u.id=(case when m.frm=? then m.too else m.frm end) "
        "where m.id in (select max(id) from msgs where frm=? or too=? group by (case when frm=? then too else frm end)) order by m.id desc", (i, i, i, i, i)).fetchall()
    return render_template("chats.html", users=users)

@app.route("/chat/<name>", methods=["GET", "POST"])
def chat(name):
    o = db().execute("select * from users where name=?", (name,)).fetchone() or abort(404)
    i = me()["id"]
    if request.method == "POST":
        b = request.form.get("body", "").strip()[:1000]
        if b and not spam("msg", 20):
            db().execute("insert into msgs(frm,too,body,ts) values(?,?,?,?)", (i, o["id"], b, time.time())); db().execute("update users set typing_ts=0 where id=?", (i,)); db().commit(); notify(o, me()["name"], b)
        return redirect(url_for("chat", name=o["name"]))
    db().execute("update msgs set seen=1 where frm=? and too=? and seen=0", (o["id"], i)); db().commit()
    m = db().execute("select * from msgs where (frm=? and too=?) or (frm=? and too=?) order by id desc limit 100", (i, o["id"], o["id"], i)).fetchall()[::-1]
    return render_template("chat.html", o=o, msgs=m, ago=time.time() - (o["last_seen"] or 0))

@app.route("/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        f = request.form
        if f.get("do") == "bio":
            db().execute("update users set bio=? where id=?", (f.get("bio", "")[:300], me()["id"])); db().commit(); flash("Описание сохранено ✨")
        elif f.get("do") == "pw" and not spam("pw", 5, 300):
            if not check_password_hash(me()["pw"], f.get("old", "")): flash("Старый пароль неверный")
            elif len(f.get("new", "")) < 6: flash("Новый пароль минимум 6 символов")
            else:
                db().execute("update users set pw=? where id=?", (generate_password_hash(f["new"]), me()["id"])); db().commit(); flash("Пароль изменён 🔐")
        return redirect(url_for("settings"))
    return render_template("settings.html")

def find(q):
    l = "%" + q.replace("%", "").replace("_", "") + "%"
    return db().execute("select name,bio from users where name like ? and id!=? order by (name like ?) desc, name limit 50",
                        (l, me()["id"], q + "%")).fetchall()

@app.route("/people")
def people():
    q = request.args.get("q", "").strip()[:30]
    return render_template("people.html", users=find(q), q=q)

@app.route("/api/people")
def api_people():
    return render_template("_ppl.html", users=find(request.args.get("q", "").strip()[:30]))

@app.route("/api/poll")
def poll():
    i = me()["id"]; now = time.time(); d = db()
    if now - (me()["last_seen"] or 0) > 10:
        d.execute("update users set last_seen=? where id=?", (now, i))
    since = request.args.get("since", -1, type=int)
    last = d.execute("select coalesce(max(id),0) m from msgs where too=?", (i,)).fetchone()["m"]
    new = []
    if since >= 0:
        new = [dict(r) for r in d.execute("select m.id,m.body,u.name from msgs m join users u on u.id=m.frm where m.too=? and m.id>? order by m.id limit 5", (i, since)).fetchall()]
    out = {"new": new, "last": int(last)}
    o = d.execute("select * from users where name=?", (request.args.get("chat", ""),)).fetchone()
    if o:
        if request.args.get("vis") == "1":
            d.execute("update msgs set seen=1 where frm=? and too=? and seen=0", (o["id"], i))
        r = d.execute("select coalesce(max(id),0) a, coalesce(sum(case when frm=? and seen=1 then 1 else 0 end),0) b from msgs "
                      "where (frm=? and too=?) or (frm=? and too=?)", (i, i, o["id"], o["id"], i)).fetchone()
        out["sig"] = "%d:%d" % (r["a"], r["b"])
        out["peer"] = {"ago": now - (o["last_seen"] or 0), "typing": bool(o["typing_to"] == i and now - (o["typing_ts"] or 0) < 4)}
    out["unread"] = d.execute("select count(*) c from msgs where too=? and seen=0", (i,)).fetchone()["c"]
    d.commit()
    return jsonify(out)

@app.route("/api/typing", methods=["POST"])
def typing():
    o = db().execute("select id from users where name=?", (request.form.get("to", ""),)).fetchone()
    if o:
        db().execute("update users set typing_to=?,typing_ts=? where id=?", (o["id"], time.time(), me()["id"])); db().commit()
    return "", 204

# ---- push-уведомления (работают, даже когда сайт закрыт) ----
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def vapid():
    if os.environ.get("VAPID_PUBLIC") and os.environ.get("VAPID_PRIVATE"):
        return os.environ["VAPID_PUBLIC"], os.environ["VAPID_PRIVATE"]
    d = db()
    kv = {r["k"]: r["v"] for r in d.execute("select k,v from kv").fetchall()}
    if "vpub" not in kv:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization as S
        k = ec.generate_private_key(ec.SECP256R1())
        kv = {"vpriv": b64(k.private_numbers().private_value.to_bytes(32, "big")),
              "vpub": b64(k.public_key().public_bytes(S.Encoding.X962, S.PublicFormat.UncompressedPoint))}
        try:
            for a, v in kv.items(): d.execute("insert into kv(k,v) values(?,?)", (a, v))
            d.commit()
        except Exception:
            d.c.rollback(); kv = {r["k"]: r["v"] for r in d.execute("select k,v from kv").fetchall()}
    return kv["vpub"], kv["vpriv"]

def vkey(pr):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization as S
    raw = base64.urlsafe_b64decode(pr + "=" * (-len(pr) % 4))
    if len(raw) != 32: return pr
    k = ec.derive_private_key(int.from_bytes(raw, "big"), ec.SECP256R1())
    return b64(k.private_bytes(S.Encoding.DER, S.PrivateFormat.PKCS8, S.NoEncryption()))

def _send(subs, payload, pr, sub):
    try:
        from pywebpush import webpush, WebPushException
        key = vkey(pr)
    except Exception:
        return
    for s_ in subs:
        try:
            webpush(subscription_info={"endpoint": s_["endpoint"], "keys": {"p256dh": s_["p256dh"], "auth": s_["auth"]}},
                    data=payload, vapid_private_key=key, vapid_claims={"sub": sub}, ttl=3600)
        except WebPushException as e:
            if e.response is not None and e.response.status_code in (404, 410):
                try:
                    c = Conn(); c.execute("delete from push_subs where endpoint=?", (s_["endpoint"],)); c.commit(); c.close()
                except Exception: pass
        except Exception:
            pass

def push(uid, title, body, url, tag):
    subs = [dict(r) for r in db().execute("select * from push_subs where uid=?", (uid,)).fetchall()]
    if not subs: return
    _, pr = vapid()
    threading.Thread(target=_send, daemon=True, args=(subs, json.dumps({"title": title, "body": body[:120], "url": url, "tag": tag}),
                     pr, request.host_url.rstrip("/"))).start()

def notify(o, frm, text):
    if time.time() - (o["last_seen"] or 0) < 15: return  # человек сейчас в приложении — ему хватит всплывашки на сайте
    try: push(o["id"], frm, text, "/chat/" + frm, "chat-" + frm)
    except Exception: pass

@app.route("/sw.js")
def sw():
    return app.send_static_file("sw.js"), 200, {"Content-Type": "text/javascript", "Service-Worker-Allowed": "/", "Cache-Control": "no-cache"}

@app.route("/manifest.json")
def manifest():
    return app.send_static_file("manifest.json"), 200, {"Content-Type": "application/manifest+json"}

@app.route("/api/push/key")
def push_key(): return jsonify(key=vapid()[0])

@app.route("/api/push/subscribe", methods=["POST"])
def push_sub():
    try:
        j = json.loads(request.form.get("sub", "")); e, k = j["endpoint"], j["keys"]
        db().execute("delete from push_subs where endpoint=?", (e,))
        db().execute("insert into push_subs(uid,endpoint,p256dh,auth) values(?,?,?,?)", (me()["id"], e, k["p256dh"], k["auth"])); db().commit()
    except Exception: abort(400)
    return "", 204

@app.route("/api/push/unsubscribe", methods=["POST"])
def push_unsub():
    db().execute("delete from push_subs where endpoint=? and uid=?", (request.form.get("endpoint", ""), me()["id"])); db().commit(); return "", 204

@app.route("/api/push/test", methods=["POST"])
def push_test():
    if not spam("pushtest", 3): push(me()["id"], "Снежок ❄", "Уведомления работают! 🎄", "/chats", "test")
    return "", 204

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)

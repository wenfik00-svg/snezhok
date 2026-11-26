import os, io, re, time, secrets, sqlite3, json, base64, threading
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
                  SESSION_COOKIE_SECURE=bool(os.environ.get("HTTPS")), PERMANENT_SESSION_LIFETIME=60*60*24*30, MAX_CONTENT_LENGTH=8 * 1024 * 1024)
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
create table if not exists files(id integer primary key, mime text, data blob);
create table if not exists follows(a integer, b integer, primary key(a,b));
create table if not exists reacts(uid integer, pid integer, e text, primary key(uid,pid));
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
 "create table if not exists files(id serial primary key, mime text, data bytea)",
 "create table if not exists follows(a integer, b integer, primary key(a,b))",
 "create table if not exists reacts(uid integer, pid integer, e text, primary key(uid,pid))",
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
        q = tr(q); ins = q.lstrip().startswith(("insert into users", "insert into files"))
        if ins: q += " returning id"
        cur = s.c.execute(q, a)
        return R(cur, cur.fetchone()["id"] if ins else None)
    def commit(s): s.c.commit()
    def close(s): s.c.close()

# ---- шифрование сообщений в базе (AES, Fernet). Ключ берётся из ENC_KEY или SECRET_KEY и в базе не хранится ----
import hashlib
from cryptography.fernet import Fernet, InvalidToken
F = Fernet(base64.urlsafe_b64encode(hashlib.sha256(("msg:" + (os.environ.get("ENC_KEY") or app.secret_key)).encode()).digest()))
def enc(t): return "enc:" + F.encrypt(t.encode()).decode()
def dec(t):
    if t and t.startswith("enc:"):
        try: return F.decrypt(t[4:].encode()).decode()
        except InvalidToken: return "🔒 не удалось расшифровать"
    return t

ALT = [("users", "last_seen", "real default 0"), ("users", "typing_to", "integer"),
       ("users", "typing_ts", "real default 0"), ("msgs", "seen", "integer default 0"),
       ("users", "avatar", "integer"), ("users", "admin", "integer default 0"), ("users", "banned", "integer default 0"), ("users", "badge", "text"), ("users", "color", "integer default 0"), ("posts", "img", "integer")]
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
    try:
        c.execute("insert into reacts(uid,pid,e) select uid,pid,'❤️' from likes where (uid,pid) not in (select uid,pid from reacts)")
    except Exception:
        try: c.c.rollback()
        except Exception: pass
    try:  # зашифровать старые сообщения, которые лежат открытым текстом
        for r in c.execute("select id,body from msgs where body not like ?", ("enc:%",)).fetchall():
            c.execute("update msgs set body=? where id=?", (enc(r["body"]), r["id"]))
    except Exception:
        try: c.c.rollback()
        except Exception: pass
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

ADMINS = {x.strip().lower() for x in os.environ.get("ADMIN_USERS", "").split(",") if x.strip()}

def me():
    if "uid" not in session: return None
    if not hasattr(g, "me"):
        g.me = db().execute("select * from users where id=?", (session["uid"],)).fetchone()
        if g.me is not None and g.me["name"].lower() in ADMINS and not g.me["admin"]:
            db().execute("update users set admin=1 where id=?", (g.me["id"],)); db().commit()
            g.me = db().execute("select * from users where id=?", (session["uid"],)).fetchone()
        if g.me is None or g.me["banned"]: session.clear(); g.me = None; return None
    return g.me
@app.context_processor
def ctx():
    return dict(me=me(), csrf=session.setdefault("csrf", secrets.token_hex(16)))
@app.template_filter("hue")
def hue(s): return sum(map(ord, s)) * 37 % 360
BADGES = ["", "🎅", "🦌", "☃️", "🎁", "⭐", "🧝", "❄️", "🎄", "🔔"]
STYLES = [(0, "Обычный"), (1, "Дед Мороз"), (2, "Ёлочка"), (3, "Золото"), (4, "Лёд"), (5, "Гирлянда")]
@app.template_filter("nm")
def nm(name):
    from markupsafe import Markup
    c = g.setdefault("fl", {})
    if name not in c:
        r = db().execute("select badge,color from users where name=?", (name,)).fetchone()
        c[name] = ((r["badge"] or ""), (r["color"] or 0)) if r else ("", 0)
    b, k = c[name]
    return Markup('<span class="nmw">{}<span class="nm c{}">{}</span></span>').format((Markup('<i class="bd">👑</i>') if name.lower() in admin_names() else Markup("")) + (Markup('<i class="bd">%s</i>' % b) if b else Markup("")), k, name)
def admin_names():
    if not hasattr(g, "adm"):
        g.adm = {r["name"].lower() for r in db().execute("select name from users where admin=1").fetchall()}
    return g.adm
@app.template_filter("crown")
def crown(n): return "👑 " if n.lower() in admin_names() else ""

def check_name(n, uid):
    if not re.fullmatch(r"[A-Za-zА-Яа-яЁё0-9_]{3,20}", n): return "3–20 символов: буквы, цифры или _"
    if db().execute("select 1 from users where name=? and id!=?", (n, uid)).fetchone(): return "Это имя уже занято"
    return None

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
def back(a=""):
    return redirect((request.referrer or url_for("feed")).split("#")[0] + ("#" + a if a else ""))
REACT = ["❤️", "👍", "😂", "🔥", "🎄"]
def save_img(fs, size, square=False):
    from PIL import Image, ImageOps
    Image.MAX_IMAGE_PIXELS = 40_000_000
    im = ImageOps.exif_transpose(Image.open(fs.stream)).convert("RGB")
    if square: im = ImageOps.fit(im, (size, size))
    else: im.thumbnail((size, size))
    buf = io.BytesIO(); im.save(buf, "JPEG", quality=82, optimize=True)
    c = db().execute("insert into files(mime,data) values(?,?)", ("image/jpeg", buf.getvalue()))
    db().commit(); return c.lastrowid
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
            elif u0 and not u0["banned"] and check_password_hash(u0["pw"], p):
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
                if u["banned"]: flash("🚫 Аккаунт заблокирован администратором")
                else:
                    session.clear(); session.permanent = True; session["uid"] = u["id"]; return redirect(url_for("feed"))
            else: flash("Неверное имя или пароль")
    return render_template("auth.html", reg=False)

@app.route("/logout", methods=["POST"])
def logout():
    session.clear(); return redirect(url_for("login"))

def posts(where="", args=(), n=10):
    rows = db().execute("select p.*,u.name from posts p join users u on u.id=p.uid " + where + " order by p.id desc limit ?", (*args, n + 1)).fetchall()
    out = []
    for r in rows[:n]:
        d = dict(r)
        d["comments"] = db().execute("select c.*,u.name from comments c join users u on u.id=c.uid where pid=? order by c.id", (r["id"],)).fetchall()
        d["rx"] = db().execute("select e, count(*) c from reacts where pid=? group by e order by c desc", (r["id"],)).fetchall()
        m = db().execute("select e from reacts where pid=? and uid=?", (r["id"], me()["id"])).fetchone()
        d["mine"] = m["e"] if m else None
        out.append(d)
    return out, len(rows) > n
def nparam(): return min(max(request.args.get("n", 10, type=int), 10), 300)

@app.route("/")
def feed():
    n = nparam(); f = request.args.get("f") == "1"
    p, more = posts("where p.uid in (select b from follows where a=?)", (me()["id"],), n) if f else posts(n=n)
    return render_template("feed.html", posts=p, more=more, n=n + 10, f=f)

@app.route("/post", methods=["POST"])
def post():
    b = request.form.get("body", "").strip()[:1000]; fs = request.files.get("img"); img = None
    if (b or (fs and fs.filename)) and not spam("post", 5):
        if fs and fs.filename:
            try: img = save_img(fs, 1280)
            except Exception: flash("Не удалось загрузить фото. Нужен файл JPG или PNG."); return redirect(url_for("feed"))
        db().execute("insert into posts(uid,body,ts,img) values(?,?,?,?)", (me()["id"], b, time.time(), img)); db().commit()
    return redirect(url_for("feed"))

@app.route("/react/<int:id>", methods=["POST"])
def react(id):
    e = request.form.get("e", ""); d = db()
    if e in REACT and not spam("like", 40) and d.execute("select 1 from posts where id=?", (id,)).fetchone():
        cur = d.execute("select e from reacts where uid=? and pid=?", (me()["id"], id)).fetchone()
        d.execute("delete from reacts where uid=? and pid=?", (me()["id"], id))
        if not cur or cur["e"] != e: d.execute("insert into reacts(uid,pid,e) values(?,?,?)", (me()["id"], id, e))
        d.commit()
    return back("p%d" % id)

@app.route("/follow/<name>", methods=["POST"])
def follow(name):
    u = db().execute("select id from users where name=?", (name,)).fetchone() or abort(404)
    i = me()["id"]
    if u["id"] != i:
        if db().execute("select 1 from follows where a=? and b=?", (i, u["id"])).fetchone():
            db().execute("delete from follows where a=? and b=?", (i, u["id"]))
        else:
            db().execute("insert into follows(a,b) values(?,?)", (i, u["id"]))
        db().commit()
    return back()

@app.route("/avatar/<name>")
def avatar(name):
    r = db().execute("select f.mime,f.data from users u join files f on f.id=u.avatar where u.name=?", (name,)).fetchone()
    if not r: return "", 404, {"Cache-Control": "max-age=300"}
    return bytes(r["data"]), 200, {"Content-Type": r["mime"], "Cache-Control": "public, max-age=300"}

@app.route("/img/<int:id>")
def img(id):
    r = db().execute("select mime,data from files where id=?", (id,)).fetchone() or abort(404)
    return bytes(r["data"]), 200, {"Content-Type": r["mime"], "Cache-Control": "public, max-age=31536000, immutable"}

@app.route("/comment/<int:id>", methods=["POST"])
def comment(id):
    b = request.form.get("body", "").strip()[:500]
    if b and not spam("comment", 10) and db().execute("select 1 from posts where id=?", (id,)).fetchone():
        db().execute("insert into comments(uid,pid,body,ts) values(?,?,?,?)", (me()["id"], id, b, time.time())); db().commit()
    return back("p%d" % id)

@app.route("/delete/post/<int:id>", methods=["POST"])
def delpost(id):
    d = db(); r = d.execute("select img,uid from posts where id=?", (id,)).fetchone()
    if r and r["uid"] != me()["id"] and not me()["admin"]: r = None
    if r:
        d.execute("delete from posts where id=?", (id,)); d.execute("delete from comments where pid=?", (id,)); d.execute("delete from reacts where pid=?", (id,))
        if r["img"]: d.execute("delete from files where id=?", (r["img"],))
        d.commit()
    return back()

@app.route("/delete/comment/<int:id>", methods=["POST"])
def delcomment(id):
    db().execute("delete from comments where id=?" + ("" if me()["admin"] else " and uid=?"), (id,) if me()["admin"] else (id, me()["id"])); db().commit(); return back()

@app.route("/u/<name>")
def profile(name):
    u = db().execute("select * from users where name=?", (name,)).fetchone() or abort(404)
    n = nparam(); p, more = posts("where p.uid=?", (u["id"],), n)
    d = db(); i = me()["id"]
    fo = d.execute("select count(*) c from follows where b=?", (u["id"],)).fetchone()["c"]
    fg = d.execute("select count(*) c from follows where a=?", (u["id"],)).fetchone()["c"]
    isf = bool(d.execute("select 1 from follows where a=? and b=?", (i, u["id"])).fetchone())
    return render_template("profile.html", u=u, posts=p, more=more, n=n + 10, fo=fo, fg=fg, isf=isf)

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
    users = [dict(r, body=dec(r["body"])) for r in users]
    return render_template("chats.html", users=users)

@app.route("/chat/<name>", methods=["GET", "POST"])
def chat(name):
    o = db().execute("select * from users where name=?", (name,)).fetchone() or abort(404)
    i = me()["id"]
    if request.method == "POST":
        b = request.form.get("body", "").strip()[:1000]
        if b and not spam("msg", 20):
            db().execute("insert into msgs(frm,too,body,ts) values(?,?,?,?)", (i, o["id"], enc(b), time.time())); db().execute("update users set typing_ts=0 where id=?", (i,)); db().commit(); notify(o, me()["name"], b)
        return redirect(url_for("chat", name=o["name"]))
    db().execute("update msgs set seen=1 where frm=? and too=? and seen=0", (o["id"], i)); db().commit()
    m = db().execute("select * from msgs where (frm=? and too=?) or (frm=? and too=?) order by id desc limit 100", (i, o["id"], o["id"], i)).fetchall()[::-1]
    m = [dict(r, body=dec(r["body"])) for r in m]
    return render_template("chat.html", o=o, msgs=m, ago=time.time() - (o["last_seen"] or 0))

@app.route("/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        f = request.form
        if f.get("do") == "bio":
            db().execute("update users set bio=? where id=?", (f.get("bio", "")[:300], me()["id"])); db().commit(); flash("Описание сохранено ✨")
        elif f.get("do") == "style":
            b, k = f.get("badge", ""), f.get("color", 0, type=int)
            if b in BADGES and 0 <= k < len(STYLES):
                db().execute("update users set badge=?,color=? where id=?", (b, k, me()["id"])); db().commit(); flash("Стиль сохранён 🎨")
        elif f.get("do") == "name":
            n = f.get("name", "").strip()
            if n == me()["name"]: pass
            elif not me()["admin"] and spam("rename", 3, 3600): pass
            else:
                err = check_name(n, me()["id"])
                if err: flash(err)
                else:
                    db().execute("update users set name=? where id=?", (n, me()["id"])); db().commit(); flash("🎉 Готово! Теперь вас зовут «%s»" % n)
        elif f.get("do") == "avatar" and request.files.get("img") and not spam("img", 5):
            try:
                fid = save_img(request.files["img"], 256, True); old = me()["avatar"]
                db().execute("update users set avatar=? where id=?", (fid, me()["id"]))
                if old: db().execute("delete from files where id=?", (old,))
                db().commit(); flash("Фото профиля обновлено 📸")
            except Exception: flash("Не удалось загрузить фото. Нужен файл JPG или PNG.")
        elif f.get("do") == "noavatar":
            if me()["avatar"]: db().execute("delete from files where id=?", (me()["avatar"],))
            db().execute("update users set avatar=NULL where id=?", (me()["id"],)); db().commit(); flash("Фото удалено")
        elif f.get("do") == "pw" and not spam("pw", 5, 300):
            if not check_password_hash(me()["pw"], f.get("old", "")): flash("Старый пароль неверный")
            elif len(f.get("new", "")) < 6: flash("Новый пароль минимум 6 символов")
            else:
                db().execute("update users set pw=? where id=?", (generate_password_hash(f["new"]), me()["id"])); db().commit(); flash("Пароль изменён 🔐")
        return redirect(url_for("settings"))
    return render_template("settings.html", badges=BADGES, styles=STYLES)

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
        new = [dict(r, body=dec(r["body"])) for r in d.execute("select m.id,m.body,u.name from msgs m join users u on u.id=m.frm where m.too=? and m.id>? order by m.id limit 5", (i, since)).fetchall()]
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

@app.route("/api/name")
def api_name():
    n = request.args.get("n", "").strip()
    if n == me()["name"]: return jsonify(ok=True, msg="Это ваше текущее имя")
    e = check_name(n, me()["id"]); return jsonify(ok=e is None, msg=e or "Имя свободно!")

# ---- админ-панель ----
def need_admin():
    if not me()["admin"]: abort(403)

@app.route("/admin")
def admin():
    need_admin(); q = request.args.get("q", "").strip()[:30]
    users = db().execute("select u.id,u.name,u.admin,u.banned,(select count(*) from posts p where p.uid=u.id) np from users u "
                         "where u.name like ? order by u.id desc limit 100", ("%" + q.replace("%", "").replace("_", "") + "%",)).fetchall()
    return render_template("admin.html", users=users, q=q)

@app.route("/admin/ban/<int:id>", methods=["POST"])
def admin_ban(id):
    need_admin(); u = db().execute("select * from users where id=?", (id,)).fetchone()
    if u and not u["admin"]:
        db().execute("update users set banned=? where id=?", (0 if u["banned"] else 1, id)); db().commit()
        flash(("Разблокирован: " if u["banned"] else "🚫 Заблокирован: ") + u["name"])
    elif u: flash("Админа заблокировать нельзя")
    return back()

@app.route("/admin/rename/<int:id>", methods=["POST"])
def admin_rename(id):
    need_admin(); n = request.form.get("name", "").strip(); err = check_name(n, id)
    if err: flash(err)
    else: db().execute("update users set name=? where id=?", (n, id)); db().commit(); flash("Ник изменён на «%s»" % n)
    return back()

@app.route("/admin/wipe/<int:id>", methods=["POST"])
def admin_wipe(id):
    need_admin(); d = db()
    for r in d.execute("select id,img from posts where uid=?", (id,)).fetchall():
        d.execute("delete from comments where pid=?", (r["id"],)); d.execute("delete from reacts where pid=?", (r["id"],))
        if r["img"]: d.execute("delete from files where id=?", (r["img"],))
        d.execute("delete from posts where id=?", (r["id"],))
    d.commit(); flash("Все посты пользователя удалены"); return back()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)

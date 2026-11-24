import os, re, time, secrets, sqlite3
from collections import defaultdict, deque
from datetime import datetime
from flask import Flask, g, request, session, redirect, url_for, render_template, abort, flash
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("DB_PATH", os.path.join(BASE, "snezhok.db"))
app = Flask(__name__)
kf = os.path.join(BASE, ".secret")
if not os.path.exists(kf):
    open(kf, "w").write(secrets.token_hex(32))
app.secret_key = os.environ.get("SECRET_KEY") or open(kf).read()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=bool(os.environ.get("HTTPS")), MAX_CONTENT_LENGTH=64 * 1024)
if os.environ.get("BEHIND_PROXY"):
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

SCHEMA = """
create table if not exists users(id integer primary key, name text unique collate nocase, pw text, bio text default '', created real);
create table if not exists posts(id integer primary key, uid integer, body text, ts real);
create table if not exists likes(uid integer, pid integer, primary key(uid,pid));
create table if not exists comments(id integer primary key, uid integer, pid integer, body text, ts real);
create table if not exists msgs(id integer primary key, frm integer, too integer, body text, ts real);
"""
def init():
    c = sqlite3.connect(DB); c.executescript(SCHEMA); c.commit(); c.close()
init()

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB); g.db.row_factory = sqlite3.Row
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
    return g.me
@app.context_processor
def ctx():
    return dict(me=me(), csrf=session.setdefault("csrf", secrets.token_hex(16)))
@app.template_filter("hue")
def hue(s): return sum(map(ord, s)) * 37 % 360
@app.template_filter("dt")
def dt(t): return datetime.fromtimestamp(t).strftime("%d.%m.%Y %H:%M")

@app.before_request
def guard():
    if request.method == "POST" and request.form.get("csrf", "") != session.get("csrf", None):
        abort(400)
    if request.endpoint not in ("login", "register", "static") and not me():
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
            if not re.fullmatch(r"[A-Za-zА-Яа-яЁё0-9_]{3,20}", n): flash("Имя: 3–20 букв, цифр или _")
            elif len(p) < 6: flash("Пароль минимум 6 символов")
            elif db().execute("select 1 from users where name=?", (n,)).fetchone(): flash("Это имя уже занято")
            else:
                c = db().execute("insert into users(name,pw,created) values(?,?,?)", (n, generate_password_hash(p), time.time()))
                db().commit(); session.clear(); session["uid"] = c.lastrowid
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
                session.clear(); session["uid"] = u["id"]; return redirect(url_for("feed"))
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
    users = db().execute("select u.name,m.body,m.ts from msgs m join users u on u.id=(case when m.frm=? then m.too else m.frm end) "
        "where m.id in (select max(id) from msgs where frm=? or too=? group by (case when frm=? then too else frm end)) order by m.id desc", (i, i, i, i)).fetchall()
    return render_template("chats.html", users=users)

@app.route("/chat/<name>", methods=["GET", "POST"])
def chat(name):
    o = db().execute("select * from users where name=?", (name,)).fetchone() or abort(404)
    i = me()["id"]
    if request.method == "POST":
        b = request.form.get("body", "").strip()[:1000]
        if b and not spam("msg", 20):
            db().execute("insert into msgs(frm,too,body,ts) values(?,?,?,?)", (i, o["id"], b, time.time())); db().commit()
        return redirect(url_for("chat", name=o["name"]))
    m = db().execute("select * from msgs where (frm=? and too=?) or (frm=? and too=?) order by id desc limit 100", (i, o["id"], o["id"], i)).fetchall()[::-1]
    return render_template("chat.html", o=o, msgs=m)

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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)

#!/usr/bin/env python3

import sqlite3
import subprocess
import os
import pickle
import base64
import urllib.request
from flask import Flask, request, render_template_string, session, redirect, url_for, g

app = Flask(__name__)
app.secret_key = "supersecretkey123"  # intentionally weak, on purpose

DB_PATH = "dvfa.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        is_admin INTEGER DEFAULT 0
    )""")
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                   ("admin", "password", 1))
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                   ("alice", "alice123", 0))
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                   ("bob", "letmein", 0))
    c.execute("""CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY,
        author TEXT,
        body TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY,
        name TEXT,
        price TEXT
    )""")
    c.execute("SELECT COUNT(*) FROM products")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO products (name, price) VALUES (?, ?)", ("Widget", "$9.99"))
        c.execute("INSERT INTO products (name, price) VALUES (?, ?)", ("Gadget", "$19.99"))
        c.execute("INSERT INTO products (name, price) VALUES (?, ?)", ("Gizmo", "$29.99"))
    conn.commit()
    conn.close()

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def get_level():
    return session.get("security", "low")

def hints_on():
    return session.get("hints", False)

@app.route("/toggle_hints")
def toggle_hints():
    session["hints"] = not session.get("hints", False)
    return redirect(request.referrer or url_for("index"))

def hint(text):
    """Only renders if hints are enabled."""
    if hints_on():
        return f'<p class="hint">💡 Hint: {text}</p>'
    return ""

LAYOUT = """
<!doctype html>
<html>
<head>
<title>DamnVulnerableFlaskApplication</title>
<style>
body { font-family: sans-serif; margin: 0; display: flex; }
nav { width: 220px; background: #222; color: #fff; min-height: 100vh; padding: 20px; }
nav a { color: #fff; display: block; margin: 8px 0; text-decoration: none; }
nav a:hover { text-decoration: underline; }
main { padding: 30px; flex: 1; }
h1 { margin-top: 0; }
.topbar { display: flex; justify-content: space-between; align-items: center;
          background: #c0392b; color: white; padding: 10px 20px; }
.hintbtn { background: #f39c12; color: #222; border: none; padding: 8px 14px;
           font-weight: bold; cursor: pointer; border-radius: 4px; }
.hintbtn.on { background: #27ae60; color: white; }
.hint { background: #fff3cd; border-left: 4px solid #f39c12; padding: 8px 12px; margin-top: 10px; }
input, textarea, select { padding: 6px; margin: 4px 0; }
pre { background: #eee; padding: 10px; overflow-x: auto; }
code { background: #ddd; padding: 2px 4px; }
</style>
</head>
<body>
<nav>
<h2>DVFA</h2>
<a href="{{ url_for('index') }}">Home</a>
<a href="{{ url_for('sqli') }}?id=1">SQL Injection</a>
<a href="{{ url_for('search') }}?q=widget">Search (SQLi)</a>
<a href="{{ url_for('cart') }}?cartid=1">Cart Viewer (IDOR)</a>
<a href="{{ url_for('xss') }}">Stored XSS</a>
<a href="{{ url_for('cmd_exec') }}?cmd=127.0.0.1">Command Injection</a>
<a href="{{ url_for('traversal') }}?file=welcome.txt">Path Traversal</a>
<a href="{{ url_for('deserialize') }}">Insecure Deserialization</a>
<a href="{{ url_for('fetch_url') }}?url=http://127.0.0.1:5000/">SSRF</a>
<a href="{{ url_for('login') }}">Login</a>
<a href="{{ url_for('security') }}">Security Level</a>
</nav>
<main>
<div class="topbar">
  <span>LOOPBACK ONLY — INTENTIONALLY VULNERABLE — DO NOT EXPOSE</span>
  <a href="{{ url_for('toggle_hints') }}">
    <button class="hintbtn {{ 'on' if hints else '' }}">
      {{ 'Hints: ON' if hints else 'Hints: OFF' }}
    </button>
  </a>
</div>
<p>Security level: <b>{{ level }}</b></p>
{{ content|safe }}
</main>
</body>
</html>
"""

def render(content):
    return render_template_string(LAYOUT, content=content, level=get_level(), hints=hints_on())

@app.route("/")
def index():
    user = session.get("username", "guest")
    body = f"<h1>Welcome, {user}</h1><p>Pick a module from the menu. Each one takes a URL parameter.</p>"
    body += hint("Click 'Hints: ON' in the top bar to get guidance on each page. It's off by default, like a real engagement.")
    return render(body)

@app.route("/security", methods=["GET", "POST"])
def security():
    if request.method == "POST":
        session["security"] = request.form.get("level", "low")
        return redirect(url_for("security"))
    content = f"""
    <h1>Security Level</h1>
    <form method="post">
      <select name="level">
        <option value="low" {"selected" if get_level()=="low" else ""}>Low</option>
        <option value="medium" {"selected" if get_level()=="medium" else ""}>Medium</option>
        <option value="high" {"selected" if get_level()=="high" else ""}>High</option>
      </select>
      <button type="submit">Set</button>
    </form>
    """
    content += hint("Low = no protection. Medium = naive blacklist filtering (often bypassable). High = proper fix, for comparison.")
    return render(content)

@app.route("/sqli")
def sqli():
    uid = request.args.get("id", "1")
    db = get_db()
    level = get_level()
    result = ""
    try:
        if level == "low":
            query = f"SELECT id, username, is_admin FROM users WHERE id = '{uid}'"
            rows = db.execute(query).fetchall()
        elif level == "medium":
            cleaned = uid
            for b in ["--", ";", "DROP", "UNION"]:
                cleaned = cleaned.replace(b, "")
            query = f"SELECT id, username, is_admin FROM users WHERE id = '{cleaned}'"
            rows = db.execute(query).fetchall()
        else:
            query = "SELECT id, username, is_admin FROM users WHERE id = ?"
            rows = db.execute(query, (uid,)).fetchall()
        result = f"<pre>Query ran.\nResults: {rows}</pre>"
    except Exception as e:
        result = f"<pre>Error: {e}</pre>"
    content = f"""
    <h1>SQL Injection</h1>
    <p>Param: <code>?id=</code></p>
    <form method="get">
      User ID: <input name="id" value="{uid}">
      <button type="submit">Lookup</button>
    </form>
    {result}
    """
    content += hint("Try <code>?id=1' OR '1'='1</code> on low/medium.")
    return render(content)

@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    level = get_level()
    result = ""
    try:
        if level == "low":
            query = f"SELECT id, name, price FROM products WHERE name LIKE '%{q}%'"
            rows = db.execute(query).fetchall()
        elif level == "medium":
            cleaned = q.replace("'", "").replace("UNION", "").replace("--", "")
            query = f"SELECT id, name, price FROM products WHERE name LIKE '%{cleaned}%'"
            rows = db.execute(query).fetchall()
        else:
            query = "SELECT id, name, price FROM products WHERE name LIKE ?"
            rows = db.execute(query, (f"%{q}%",)).fetchall()
        result = f"<pre>{rows}</pre>"
    except Exception as e:
        result = f"<pre>Error: {e}</pre>"
    content = f"""
    <h1>Product Search</h1>
    <p>Param: <code>?q=</code></p>
    <form method="get">
      Search: <input name="q" value="{q}">
      <button type="submit">Search</button>
    </form>
    {result}
    """
    content += hint("Try <code>?q=' UNION SELECT id, username, password FROM users --</code> on low.")
    return render(content)

@app.route("/cart")
def cart():
    cartid = request.args.get("cartid", "1")
    level = get_level()
    fake_carts = {
        "1": {"owner": "alice", "items": ["Widget x2"]},
        "2": {"owner": "bob", "items": ["Gadget x1", "Gizmo x3"]},
        "3": {"owner": "admin", "items": ["Secret Prototype x1"]},
    }
    if level == "high":
        current_user = session.get("username")
        owned = [cid for cid, c in fake_carts.items() if c["owner"] == current_user]
        if cartid not in owned:
            result = "<p>403 — that cart does not belong to you.</p>"
        else:
            c = fake_carts[cartid]
            result = f"<pre>Owner: {c['owner']}\nItems: {c['items']}</pre>"
    else:
        c = fake_carts.get(cartid)
        result = f"<pre>Owner: {c['owner']}\nItems: {c['items']}</pre>" if c else "<p>No such cart.</p>"
    content = f"""
    <h1>Cart Viewer</h1>
    <p>Param: <code>?cartid=</code></p>
    <form method="get">
      Cart ID: <input name="cartid" value="{cartid}">
      <button type="submit">View</button>
    </form>
    {result}
    """
    content += hint("Log in as alice, then just change <code>?cartid=</code> to 2 or 3. No ownership check on low/medium.")
    return render(content)

@app.route("/xss", methods=["GET", "POST"])
def xss():
    db = get_db()
    level = get_level()
    if request.method == "POST":
        author = request.form.get("author", "anon")
        body = request.form.get("body", "")
        db.execute("INSERT INTO comments (author, body) VALUES (?, ?)", (author, body))
        db.commit()
    rows = db.execute("SELECT author, body FROM comments ORDER BY id DESC LIMIT 20").fetchall()
    comments_html = ""
    for author, body in rows:
        if level == "high":
            from markupsafe import escape
            comments_html += f"<p><b>{escape(author)}:</b> {escape(body)}</p>"
        else:
            comments_html += f"<p><b>{author}:</b> {body}</p>"
    content = f"""
    <h1>Stored XSS - Comments</h1>
    <form method="post">
      Name: <input name="author"><br>
      Comment: <textarea name="body"></textarea><br>
      <button type="submit">Post</button>
    </form>
    <hr>
    {comments_html}
    """
    content += hint("Try posting <code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code> as a comment on low/medium.")
    return render(content)

@app.route("/cmdexec")
def cmd_exec():
    target = request.args.get("cmd", "127.0.0.1")
    level = get_level()
    output = ""
    try:
        if level == "low":
            cmd = f"ping -c 1 {target}"
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            output = out.stdout + out.stderr
        elif level == "medium":
            cleaned = target
            for b in [";", "&&", "|", "`"]:
                cleaned = cleaned.replace(b, "")
            cmd = f"ping -c 1 {cleaned}"
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            output = out.stdout + out.stderr
        else:
            out = subprocess.run(["ping", "-c", "1", target], capture_output=True, text=True, timeout=5)
            output = out.stdout + out.stderr
    except Exception as e:
        output = str(e)
    content = f"""
    <h1>Command Injection</h1>
    <p>Param: <code>?cmd=</code></p>
    <form method="get">
      Host: <input name="cmd" value="{target}">
      <button type="submit">Ping</button>
    </form>
    <pre>{output}</pre>
    """
    content += hint("Try <code>?cmd=127.0.0.1; id</code> on low.")
    return render(content)

SANDBOX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")
os.makedirs(SANDBOX, exist_ok=True)
with open(os.path.join(SANDBOX, "welcome.txt"), "w") as f:
    f.write("Welcome to DVFA file viewer.\n")

@app.route("/traversal")
def traversal():
    fname = request.args.get("file", "welcome.txt")
    level = get_level()
    content_out = ""
    try:
        if level == "low":
            path = os.path.join(SANDBOX, fname)
        elif level == "medium":
            cleaned = fname.replace("../", "")
            path = os.path.join(SANDBOX, cleaned)
        else:
            path = os.path.normpath(os.path.join(SANDBOX, fname))
            if not path.startswith(os.path.abspath(SANDBOX)):
                path = os.path.join(SANDBOX, "welcome.txt")
        with open(path, "r", errors="replace") as fh:
            content_out = fh.read()
    except Exception as e:
        content_out = str(e)
    content = f"""
    <h1>Path Traversal - File Viewer</h1>
    <p>Param: <code>?file=</code></p>
    <form method="get">
      File: <input name="file" value="{fname}">
      <button type="submit">View</button>
    </form>
    <pre>{content_out}</pre>
    """
    content += hint("Try <code>?file=../../../../etc/passwd</code> on low.")
    return render(content)

@app.route("/deserialize")
def deserialize():
    level = get_level()
    sample = base64.b64encode(pickle.dumps({"hello": "world"})).decode()
    blob = request.args.get("data", sample)
    output = ""
    if request.args.get("data") is not None:
        try:
            raw = base64.b64decode(blob)
            if level == "high":
                import json
                output = f"json.loads result: {json.loads(raw)}"
            else:
                obj = pickle.loads(raw)
                output = f"Deserialized object: {obj!r}"
        except Exception as e:
            output = str(e)
    content = f"""
    <h1>Insecure Deserialization</h1>
    <p>Param: <code>?data=</code> (base64-encoded)</p>
    <form method="get">
      Data: <input name="data" style="width:400px" value="{blob}">
      <button type="submit">Load</button>
    </form>
    <pre>{output}</pre>
    """
    content += hint("On low/medium this is <code>pickle.loads()</code> on raw user input — craft a payload with a <code>__reduce__</code> method for RCE.")
    return render(content)

@app.route("/ssrf")
def fetch_url():
    target = request.args.get("url", "http://127.0.0.1:5000/")
    level = get_level()
    output = ""
    if request.args.get("url") is not None:
        try:
            if level == "high":
                if not target.startswith("https://api.example.com/"):
                    raise ValueError("URL not allowed by allowlist")
            if level == "medium" and "localhost" in target:
                raise ValueError("localhost blocked")
            with urllib.request.urlopen(target, timeout=3) as resp:
                output = resp.read(500).decode(errors="replace")
        except Exception as e:
            output = str(e)
    content = f"""
    <h1>SSRF - URL Fetcher</h1>
    <p>Param: <code>?url=</code></p>
    <form method="get">
      URL: <input name="url" style="width:400px" value="{target}">
      <button type="submit">Fetch</button>
    </form>
    <pre>{output}</pre>
    """
    content += hint("Medium only blocks the literal string 'localhost' — try <code>127.0.0.1</code> or <code>0.0.0.0</code> instead.")
    return render(content)

@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        level = get_level()
        if level == "low":
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            row = db.execute(query).fetchone()
        else:
            row = db.execute(
                "SELECT * FROM users WHERE username = ? AND password = ?",
                (username, password)
            ).fetchone()
        if row:
            session["username"] = row[1]
            session["is_admin"] = bool(row[3])
            return redirect(url_for("index"))
        else:
            error = "Invalid credentials."
    content = f"""
    <h1>Login</h1>
    <form method="post">
      Username: <input name="username"><br>
      Password: <input name="password" type="password"><br>
      <button type="submit">Login</button>
    </form>
    <p style="color:red">{error}</p>
    """
    content += hint("Default creds: admin / password. On low, try username <code>admin' --</code> with any password.")
    return render(content)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
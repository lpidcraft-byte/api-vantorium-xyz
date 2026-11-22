import os
import re
import json
import random
import sqlite3
import requests
import urllib.parse
import time
import secrets
import hashlib
import html
import ast
import operator as op

from datetime import datetime
from functools import wraps
from flask import (
    Flask, request, jsonify, Response,
    render_template_string, redirect,
    make_response
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# =========================================================
# 1. DATABASE
# =========================================================

DB_FILE = "vantorium.db"


def db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            api_key TEXT UNIQUE NOT NULL,
            created_at TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS memory (
            word TEXT PRIMARY KEY,
            answer TEXT,
            confidence REAL,
            source TEXT,
            created_at TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER,
            created_at TEXT
        )
    """)

    conn.commit()
    conn.close()


init_db()


# =========================================================
# 2. HELPERS
# =========================================================

def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def normalize(text):
    text = str(text).lower().strip()
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"[?!.,;:]+$", "", text)
    return text.strip()


def memory_get(word):
    conn = db()

    row = conn.execute(
        "SELECT answer FROM memory WHERE word = ?",
        (word,)
    ).fetchone()

    conn.close()

    return row["answer"] if row else None


def memory_save(word, answer, confidence, source):
    conn = db()

    conn.execute("""
        INSERT OR REPLACE INTO memory
        (word, answer, confidence, source, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (
        word,
        answer,
        confidence,
        source,
        datetime.now().isoformat()
    ))

    conn.commit()
    conn.close()


# =========================================================
# 3. DATASET
# =========================================================

def load_dataset():

    files = [
        "ultra_soru_cevap_30_cevapli.txt",
        "ultra_soru_cevap_30_cevapli.txt.txt",
        "storage/ultra_soru_cevap_30_cevapli.txt",
        "storage/ultra_soru_cevap_30_cevapli.txt.txt"
    ]

    data = {}

    for filename in files:

        if not os.path.exists(filename):
            continue

        with open(
            filename,
            "r",
            encoding="utf-8"
        ) as file:

            current_q = None

            for line in file:

                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                if line.startswith("Input:"):

                    current_q = normalize(
                        line.replace("Input:", "").strip()
                    )

                    if current_q not in data:
                        data[current_q] = []

                elif line.startswith("Reply:") and current_q:

                    data[current_q].append(
                        line.replace("Reply:", "").strip()
                    )

        break

    return data


DATASET = load_dataset()


# =========================================================
# 4. QUERY ANALYSIS
# =========================================================

def analyze_query(query):

    q = query.lower()

    return {
        "is_greeting": bool(
            re.search(
                r"\b(merhaba|selam|hello|hi|hey|günaydın|nasılsın|naber|nbr)\b",
                q
            )
        ),

        "is_math": bool(
            re.match(
                r"^[\d\s\+\-\*\/\(\)\.\,\^%]+$",
                query
            )
            and
            re.search(r"[\+\-\*\/\^%]", query)
        ),

        "is_code": bool(
            re.search(
                r"\b(kod|function|class|php|javascript|python|api|hata|error|debug|yazılım|programlama)\b",
                q
            )
        )
    }


# =========================================================
# 5. SAFE MATH
# =========================================================

_ALLOWED_OPERATORS = {
    ast.Add: op.add,
    ast.Sub: op.sub,
    ast.Mult: op.mul,
    ast.Div: op.truediv,
    ast.Mod: op.mod,
    ast.Pow: op.pow,
    ast.USub: op.neg,
    ast.UAdd: op.pos
}


def safe_math(expression):

    expression = expression.replace("^", "**")
    expression = expression.replace(",", ".")

    def evaluate(node):

        if isinstance(node, ast.Expression):
            return evaluate(node.body)

        if isinstance(node, ast.Constant):
            if isinstance(node.value, (int, float)):
                return node.value

        if isinstance(node, ast.BinOp):
            operator = _ALLOWED_OPERATORS.get(type(node.op))

            if not operator:
                raise ValueError()

            left = evaluate(node.left)
            right = evaluate(node.right)

            if isinstance(node.op, ast.Pow) and abs(right) > 100:
                raise ValueError()

            return operator(left, right)

        if isinstance(node, ast.UnaryOp):
            operator = _ALLOWED_OPERATORS.get(type(node.op))

            if not operator:
                raise ValueError()

            return operator(evaluate(node.operand))

        raise ValueError()

    tree = ast.parse(expression, mode="eval")

    return evaluate(tree)


# =========================================================
# 6. WEB SEARCH
# =========================================================

def web_search(query, parts):

    results = []

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
    ]

    headers = {
        "User-Agent": random.choice(user_agents),
        "Accept": "application/json, text/html, application/xhtml+xml, */*",
        "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7"
    }

    session = requests.Session()
    session.headers.update(headers)

    # Google CSE
    try:

        cse_url = (
            "https://cse.google.com/cse/element/v1"
            "?rsz=filtered_cse"
            "&num=5"
            "&hl=tr"
            "&source=gcsc"
            "&cselibv=8a5d5b6de8c9f12f"
            "&cx=f79f63e39ec7f4c78"
            f"&q={urllib.parse.quote(query)}"
            "&safe=off"
            "&cse_tok="
            "&exp=csqr,cc"
            "&callback=cb"
        )

        response = session.get(
            cse_url,
            timeout=8
        )

        match = re.search(
            r"cb\((.*)\)",
            response.text,
            re.DOTALL
        )

        if match:

            google_data = json.loads(
                match.group(1)
            )

            for item in google_data.get("results", [])[:5]:

                results.append({
                    "title": item.get(
                        "titleNoFormatting",
                        ""
                    ),
                    "url": item.get(
                        "unescapedUrl",
                        ""
                    ),
                    "snippet": item.get(
                        "contentNoFormatting",
                        ""
                    ),
                    "source": "google"
                })

    except Exception:
        pass

    # Wikipedia
    try:

        wiki_url = (
            "https://tr.wikipedia.org/w/api.php"
            "?action=query"
            "&list=search"
            f"&srsearch={urllib.parse.quote(query)}"
            "&utf8="
            "&format=json"
            "&srlimit=3"
        )

        response = session.get(
            wiki_url,
            timeout=8
        )

        wiki_data = response.json()

        for item in wiki_data.get(
            "query",
            {}
        ).get("search", []):

            snippet = re.sub(
                r"<[^>]+>",
                "",
                item.get("snippet", "")
            )

            title = item.get("title", "")

            results.append({
                "title": title,
                "url":
                    "https://tr.wikipedia.org/wiki/"
                    + urllib.parse.quote(
                        title.replace(" ", "_")
                    ),
                "snippet": snippet,
                "source": "wikipedia"
            })

    except Exception:
        pass

    # GitHub
    if parts["is_code"]:

        try:

            github_url = (
                "https://api.github.com/search/repositories"
                f"?q={urllib.parse.quote(query)}"
                "&sort=stars"
                "&per_page=3"
            )

            response = session.get(
                github_url,
                timeout=8
            )

            if response.status_code == 200:

                for item in response.json().get(
                    "items",
                    []
                ):

                    results.append({
                        "title": item.get(
                            "full_name",
                            ""
                        ),
                        "url": item.get(
                            "html_url",
                            ""
                        ),
                        "snippet": item.get(
                            "description",
                            ""
                        ) or "Açıklama yok.",
                        "source": "github"
                    })

        except Exception:
            pass

    return results


def synthesize_results(query, results):

    if not results:
        return None

    lines = []
    seen = set()

    for result in results:

        url = result.get("url", "")

        if not url or url in seen:
            continue

        seen.add(url)

        snippet = result.get(
            "snippet",
            ""
        )

        if len(snippet) > 220:
            snippet = snippet[:217] + "..."

        line = (
            f"• [{result.get('source', '').upper()}] "
            f"{result.get('title', '')}"
        )

        if snippet:
            line += f"\n{snippet}"

        line += f"\n{url}"

        lines.append(line)

        if len(lines) >= 5:
            break

    return (
        f'"{query}" hakkında bulduklarım:\n\n'
        + "\n\n".join(lines)
    )


# =========================================================
# 7. AI ENGINE
# =========================================================

def get_answer(kelime):

    normalized = normalize(kelime)

    parts = analyze_query(kelime)

    if parts["is_greeting"]:

        return random.choice([
            "Merhaba! Ben Vantorium. Sana nasıl yardımcı olabilirim?",
            "Selam! Vantorium hazır. Ne hakkında konuşalım?",
            "Selam kral! Ne yapmak istiyorsun?"
        ]), "selamlama"

    if parts["is_math"]:

        try:

            result = safe_math(kelime)

            return f"Sonuç: {result}", "matematik"

        except Exception:

            return (
                "Matematik ifadesini çözemedim.",
                "hata"
            )

    if normalized in DATASET:

        if DATASET[normalized]:

            return (
                random.choice(
                    DATASET[normalized]
                ),
                "veri_seti"
            )

    cached = memory_get(normalized)

    if cached:

        return cached, "hafiza"

    results = web_search(
        kelime,
        parts
    )

    if results:

        answer = synthesize_results(
            kelime,
            results
        )

        memory_save(
            normalized,
            answer,
            0.8,
            "web"
        )

        return answer, "web"

    return (
        "Bunu bilmiyorum, internette de bulamadım.",
        "bulunamadi"
    )


# =========================================================
# 8. AUTH
# =========================================================

def get_current_user():

    token = request.cookies.get(
        "session_token"
    )

    if not token:
        return None

    conn = db()

    row = conn.execute("""
        SELECT u.*
        FROM users u
        JOIN sessions s
        ON u.id = s.user_id
        WHERE s.token = ?
    """, (token,)).fetchone()

    conn.close()

    return row


def login_required(func):

    @wraps(func)
    def decorated(*args, **kwargs):

        if not get_current_user():
            return redirect("/login")

        return func(*args, **kwargs)

    return decorated


# =========================================================
# 9. PREMIUM INTER UI
# =========================================================

BASE_STYLE = r"""
<style>

:root {
    --bg: #07090c;
    --panel: #0d1117;
    --panel-2: #111720;
    --border: rgba(255,255,255,.08);
    --text: #f5f7fa;
    --muted: #8d98a7;
    --green: #18c88f;
    --green-2: #0e9f72;
    --danger: #ff5d6c;
    --shadow: 0 25px 80px rgba(0,0,0,.45);
}

* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

html {
    scroll-behavior: smooth;
}

body {
    font-family:
        Inter,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;

    background:
        radial-gradient(
            circle at 15% 10%,
            rgba(24,200,143,.09),
            transparent 28%
        ),
        radial-gradient(
            circle at 85% 20%,
            rgba(70,100,255,.07),
            transparent 30%
        ),
        var(--bg);

    color: var(--text);
    min-height: 100vh;

    -webkit-font-smoothing: antialiased;
}

a {
    color: inherit;
    text-decoration: none;
}

button,
input {
    font-family: inherit;
}

/* NAVBAR */

.navbar {
    height: 68px;
    padding: 0 26px;

    display: flex;
    align-items: center;
    justify-content: space-between;

    position: sticky;
    top: 0;
    z-index: 1000;

    background: rgba(7,9,12,.72);
    backdrop-filter: blur(22px);
    -webkit-backdrop-filter: blur(22px);

    border-bottom: 1px solid var(--border);
}

.logo {
    display: flex;
    align-items: center;
    gap: 11px;

    font-weight: 800;
    letter-spacing: -.5px;
}

.logo-icon {
    width: 34px;
    height: 34px;

    display: flex;
    align-items: center;
    justify-content: center;

    border-radius: 11px;

    background:
        linear-gradient(
            135deg,
            #21dca0,
            #07885f
        );

    box-shadow:
        0 8px 25px rgba(24,200,143,.25);

    font-weight: 900;
}

.nav-actions {
    display: flex;
    align-items: center;
    gap: 5px;
}

.btn-nav {
    padding: 9px 13px;

    border-radius: 9px;

    color: #9aa4b2;

    font-size: 13px;
    font-weight: 600;

    transition:
        .2s ease;

    border: 1px solid transparent;
}

.btn-nav:hover {
    color: white;
    background: rgba(255,255,255,.055);
}

.btn-nav.primary {
    color: white;

    background:
        linear-gradient(
            135deg,
            var(--green),
            var(--green-2)
        );

    box-shadow:
        0 7px 25px rgba(24,200,143,.18);
}

.btn-nav.primary:hover {
    transform: translateY(-1px);
}

/* GENERAL */

.auth-wrapper {
    min-height: calc(100vh - 68px);

    display: flex;
    align-items: center;
    justify-content: center;

    padding: 35px 20px;
}

.container {
    width: 100%;
    max-width: 430px;

    padding: 34px;

    background:
        linear-gradient(
            145deg,
            rgba(17,23,32,.96),
            rgba(10,14,20,.96)
        );

    border:
        1px solid var(--border);

    border-radius: 22px;

    box-shadow: var(--shadow);

    position: relative;
    overflow: hidden;
}

.container::before {
    content: "";

    position: absolute;

    width: 180px;
    height: 180px;

    top: -90px;
    right: -80px;

    background: rgba(24,200,143,.13);

    filter: blur(50px);

    pointer-events: none;
}

.container.wide {
    max-width: 1000px;
    margin: 38px auto;
}

/* AUTH */

.auth-brand {
    display: flex;
    justify-content: center;
    margin-bottom: 22px;
}

.auth-brand .logo-icon {
    width: 50px;
    height: 50px;

    border-radius: 15px;

    font-size: 20px;
}

.auth-title {
    text-align: center;

    font-size: 25px;
    font-weight: 800;

    letter-spacing: -.8px;

    margin-bottom: 8px;
}

.auth-subtitle {
    text-align: center;

    color: var(--muted);

    font-size: 13px;

    line-height: 1.6;

    margin-bottom: 25px;
}

label {
    display: block;

    margin-bottom: 7px;

    color: #cbd2db;

    font-size: 12px;
    font-weight: 700;
}

input[type=text],
input[type=password] {

    width: 100%;

    padding: 13px 14px;

    margin-bottom: 17px;

    color: white;

    background: #080c11;

    border: 1px solid rgba(255,255,255,.09);

    border-radius: 11px;

    outline: none;

    font-size: 14px;

    transition: .2s ease;
}

input:focus {

    border-color:
        rgba(24,200,143,.65);

    box-shadow:
        0 0 0 4px
        rgba(24,200,143,.08);
}

.btn {

    width: 100%;

    border: 0;

    padding: 13px 16px;

    border-radius: 11px;

    color: white;

    background:
        linear-gradient(
            135deg,
            var(--green),
            var(--green-2)
        );

    font-size: 14px;
    font-weight: 700;

    cursor: pointer;

    transition:
        transform .18s ease,
        box-shadow .18s ease,
        opacity .18s ease;
}

.btn:hover {

    transform: translateY(-1px);

    box-shadow:
        0 10px 30px
        rgba(24,200,143,.2);
}

.btn:active {
    transform: translateY(0);
}

.btn.secondary {
    background: #171d25;
}

.btn.danger {
    background:
        linear-gradient(
            135deg,
            #ff6472,
            #d93648
        );
}

.btn-small {
    width: auto;
    padding: 10px 14px;
}

.auth-links {

    display: flex;
    align-items: center;
    justify-content: center;

    gap: 5px;

    margin-top: 19px;

    color: var(--muted);

    font-size: 13px;
}

.auth-links a {
    color: #48e4b2;
    font-weight: 700;
}

.policy-box {

    margin-top: 22px;

    padding: 13px;

    border:
        1px solid rgba(255,255,255,.07);

    background:
        rgba(255,255,255,.025);

    border-radius: 12px;

    text-align: center;
}

.policy-box-title {

    color: #dce2e8;

    font-size: 12px;
    font-weight: 700;

    margin-bottom: 5px;
}

.policy-box-text {

    color: #727d8c;

    font-size: 11px;

    line-height: 1.5;

    margin-bottom: 9px;
}

.policy-link {

    display: inline-flex;

    align-items: center;
    justify-content: center;

    padding: 7px 11px;

    border-radius: 8px;

    background: rgba(24,200,143,.08);

    color: #4de5b5;

    font-size: 11px;
    font-weight: 700;

    border:
        1px solid rgba(24,200,143,.14);

    transition: .2s ease;
}

.policy-link:hover {
    background: rgba(24,200,143,.15);
}

.error {

    margin-bottom: 17px;

    padding: 12px 13px;

    border-radius: 10px;

    color: #ff8993;

    background: rgba(255,77,94,.07);

    border:
        1px solid rgba(255,77,94,.14);

    font-size: 12px;
}

/* DASHBOARD */

.page-header {
    margin-bottom: 24px;
}

.page-title {
    font-size: 30px;
    font-weight: 800;
    letter-spacing: -1px;
}

.page-subtitle {
    margin-top: 7px;
    color: var(--muted);
    font-size: 14px;
}

.grid {

    display: grid;

    grid-template-columns:
        repeat(2, minmax(0, 1fr));

    gap: 17px;
}

.card {

    padding: 23px;

    border-radius: 17px;

    background:
        rgba(13,17,23,.88);

    border:
        1px solid var(--border);

    box-shadow:
        0 15px 50px rgba(0,0,0,.17);

    margin-bottom: 17px;
}

.card h3 {

    display: flex;
    align-items: center;
    gap: 9px;

    margin-bottom: 13px;

    font-size: 15px;
}

.card p {

    color: #9ba5b2;

    font-size: 13px;

    line-height: 1.7;
}

.api-key-box {

    padding: 14px;

    margin-bottom: 11px;

    color: #5ce6b9;

    background: #070a0e;

    border:
        1px solid rgba(24,200,143,.12);

    border-radius: 10px;

    font-family:
        "SFMono-Regular",
        Consolas,
        monospace;

    font-size: 12px;

    word-break: break-all;
}

.code-block {

    padding: 14px;

    margin: 12px 0;

    background: #070a0e;

    border:
        1px solid rgba(255,255,255,.07);

    border-radius: 10px;

    font-family:
        "SFMono-Regular",
        Consolas,
        monospace;

    font-size: 12px;

    color: #b9c3cf;

    overflow-x: auto;

    line-height: 1.6;
}

.section-title {

    margin:
        35px 0 14px;

    font-size: 18px;

    font-weight: 800;
}

.card ul {
    list-style: none;
}

.card li {

    padding: 11px 0;

    color: #9da7b4;

    border-bottom:
        1px solid rgba(255,255,255,.055);

    font-size: 13px;

    line-height: 1.6;
}

.card li:last-child {
    border-bottom: 0;
}

.card li::before {

    content: "✓";

    color: #35dba7;

    font-weight: 800;

    margin-right: 9px;
}

.footer {

    padding: 30px 0;

    text-align: center;

    color: #596372;

    font-size: 11px;
}

/* CHAT */

.chat-page {

    height:
        calc(100vh - 68px);

    display: flex;
    flex-direction: column;
}

.chat-layout {

    width: 100%;
    max-width: 930px;

    margin: auto;

    flex: 1;

    display: flex;
    flex-direction: column;

    padding:
        0 20px;
}

.chat-history {

    flex: 1;

    overflow-y: auto;

    padding:
        30px 0;

    scrollbar-width: thin;

    scrollbar-color:
        #252d38 transparent;
}

.chat-msg {

    display: flex;

    gap: 12px;

    width: 100%;

    margin-bottom: 24px;

    animation:
        messageIn .2s ease;
}

@keyframes messageIn {

    from {
        opacity: 0;
        transform:
            translateY(5px);
    }

    to {
        opacity: 1;
        transform:
            translateY(0);
    }
}

.chat-msg.user {
    flex-direction: row-reverse;
}

.avatar {

    width: 34px;
    height: 34px;

    min-width: 34px;

    display: flex;
    align-items: center;
    justify-content: center;

    border-radius: 11px;

    font-size: 12px;
    font-weight: 800;
}

.chat-msg.ai .avatar {

    background:
        linear-gradient(
            135deg,
            var(--green),
            var(--green-2)
        );

    box-shadow:
        0 6px 20px
        rgba(24,200,143,.15);
}

.chat-msg.user .avatar {
    background: #1c232d;
}

.msg-content {

    max-width: 76%;

    color: #dfe5ec;

    font-size: 14px;

    line-height: 1.75;

    white-space: pre-wrap;

    overflow-wrap: anywhere;

    padding-top: 5px;
}

.chat-msg.user .msg-content {

    padding:
        11px 15px;

    border-radius: 16px;

    border-top-right-radius: 5px;

    background:
        #171d25;

    color: #f1f4f7;
}

.chat-input-area {

    padding:
        12px 0 24px;

    background:
        linear-gradient(
            transparent,
            var(--bg) 30%
        );
}

.chat-input-box {

    position: relative;

    max-width: 800px;

    margin: auto;
}

.chat-input-box input {

    width: 100%;

    margin: 0;

    padding:
        16px 58px 16px 18px;

    border-radius: 15px;

    background:
        rgba(13,17,23,.96);

    border:
        1px solid rgba(255,255,255,.1);

    box-shadow:
        0 12px 40px rgba(0,0,0,.3);

    color: white;

    outline: none;

    font-size: 14px;
}

.chat-input-box button {

    position: absolute;

    right: 8px;
    top: 50%;

    transform:
        translateY(-50%);

    width: 38px;
    height: 38px;

    border: 0;

    border-radius: 11px;

    background:
        linear-gradient(
            135deg,
            var(--green),
            var(--green-2)
        );

    color: white;

    display: flex;
    align-items: center;
    justify-content: center;

    cursor: pointer;

    transition: .18s ease;
}

.chat-input-box button:hover {
    transform:
        translateY(-50%)
        scale(1.04);
}

/* MOBILE */

@media (max-width: 700px) {

    .navbar {
        padding: 0 13px;
        height: 62px;
    }

    .logo {
        font-size: 14px;
    }

    .logo-icon {
        width: 30px;
        height: 30px;
    }

    .btn-nav {
        padding: 7px 8px;
        font-size: 11px;
    }

    .container {
        padding: 25px 20px;
        border-radius: 18px;
    }

    .container.wide {
        margin: 20px 12px;
    }

    .grid {
        grid-template-columns: 1fr;
    }

    .page-title {
        font-size: 25px;
    }

    .chat-layout {
        padding: 0 12px;
    }

    .msg-content {
        max-width: 82%;
        font-size: 13px;
    }

    .auth-wrapper {
        padding: 20px 14px;
    }
}

</style>

<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link
    href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap"
    rel="stylesheet"
>
"""


# =========================================================
# 10. PAGE RENDER
# =========================================================

def render_page(
    title,
    content,
    user=None,
    show_nav=True
):

    nav = ""

    if show_nav:

        if user:

            actions = """
                <a href="/chat" class="btn-nav">Sohbet</a>
                <a href="/dashboard" class="btn-nav">Dashboard</a>
                <a href="/info" class="btn-nav">Bilgi</a>
                <a href="/logout" class="btn-nav">Çıkış</a>
            """

        else:

            actions = """
                <a href="/info" class="btn-nav">Bilgi</a>
                <a href="/login" class="btn-nav">Giriş</a>
                <a href="/register" class="btn-nav primary">
                    Kayıt Ol
                </a>
            """

        nav = f"""
        <nav class="navbar">

            <a href="/" class="logo">
                <div class="logo-icon">V</div>
                <span>Vantorium</span>
            </a>

            <div class="nav-actions">
                {actions}
            </div>

        </nav>
        """

    return f"""
    <!DOCTYPE html>

    <html lang="tr">

    <head>

        <meta charset="UTF-8">

        <meta
            name="viewport"
            content="width=device-width, initial-scale=1.0"
        >

        <meta
            name="theme-color"
            content="#07090c"
        >

        <title>
            {html.escape(title)} | Vantorium
        </title>

        {BASE_STYLE}

    </head>

    <body>

        {nav}

        {content}

    </body>

    </html>
    """


# =========================================================
# 11. HOME
# =========================================================

@app.route("/")
def index():

    if get_current_user():
        return redirect("/dashboard")

    return redirect("/login")


# =========================================================
# 12. REGISTER
# =========================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if get_current_user():
        return redirect("/dashboard")

    error = None

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if len(username) < 3:

            error = (
                "Kullanıcı adı en az "
                "3 karakter olmalı."
            )

        elif len(password) < 6:

            error = (
                "Şifre en az "
                "6 karakter olmalı."
            )

        else:

            conn = db()

            exists = conn.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,)
            ).fetchone()

            if exists:

                error = (
                    "Bu kullanıcı adı "
                    "zaten kullanılıyor."
                )

            else:

                api_key = (
                    "vnt_"
                    + secrets.token_hex(24)
                )

                conn.execute("""
                    INSERT INTO users
                    (
                        username,
                        password_hash,
                        api_key,
                        created_at
                    )
                    VALUES (?, ?, ?, ?)
                """, (
                    username,
                    hash_password(password),
                    api_key,
                    datetime.now().isoformat()
                ))

                conn.commit()
                conn.close()

                return redirect("/login")

            conn.close()

    error_html = ""

    if error:

        error_html = f"""
        <div class="error">
            {html.escape(error)}
        </div>
        """

    content = f"""

    <main class="auth-wrapper">

        <section class="container">

            <div class="auth-brand">
                <div class="logo-icon">V</div>
            </div>

            <h1 class="auth-title">
                Vantorium'a Katıl
            </h1>

            <p class="auth-subtitle">
                Hesabını oluştur ve kendi Vantorium
                API anahtarını hemen al.
            </p>

            {error_html}

            <form method="POST">

                <label>
                    Kullanıcı Adı
                </label>

                <input
                    type="text"
                    name="username"
                    required
                    autocomplete="username"
                    placeholder="kullanici_adi"
                >

                <label>
                    Şifre
                </label>

                <input
                    type="password"
                    name="password"
                    required
                    autocomplete="new-password"
                    placeholder="En az 6 karakter"
                >

                <button
                    type="submit"
                    class="btn"
                >
                    Hesap Oluştur
                </button>

            </form>

            <div class="auth-links">
                Zaten hesabın var mı?
                <a href="/login">
                    Giriş Yap
                </a>
            </div>

            <div class="policy-box">

                <div class="policy-box-title">
                    Kurallar ve Politikalar
                </div>

                <div class="policy-box-text">
                    Vantorium'u kullanmadan önce
                    kullanım koşullarını ve politikaları
                    inceleyebilirsin.
                </div>

                <a
                    class="policy-link"
                    href="https://api-vantorium-xyz-production.up.railway.app/info"
                >
                    Kurallar & Politikaları Gör
                </a>

            </div>

        </section>

    </main>

    """

    return render_page(
        "Kayıt Ol",
        content
    )


# =========================================================
# 13. LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if get_current_user():
        return redirect("/dashboard")

    error = None

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        conn = db()

        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if user and user["password_hash"] == hash_password(password):

            token = secrets.token_hex(32)

            conn.execute("""
                INSERT INTO sessions
                (token, user_id, created_at)
                VALUES (?, ?, ?)
            """, (
                token,
                user["id"],
                datetime.now().isoformat()
            ))

            conn.commit()
            conn.close()

            response = make_response(
                redirect("/dashboard")
            )

            response.set_cookie(
                "session_token",
                token,
                httponly=True,
                max_age=30 * 24 * 3600,
                samesite="Lax",
                secure=request.is_secure
            )

            return response

        error = (
            "Kullanıcı adı veya şifre hatalı."
        )

        conn.close()

    error_html = ""

    if error:

        error_html = f"""
        <div class="error">
            {html.escape(error)}
        </div>
        """

    content = f"""

    <main class="auth-wrapper">

        <section class="container">

            <div class="auth-brand">
                <div class="logo-icon">V</div>
            </div>

            <h1 class="auth-title">
                Tekrar Hoş Geldin
            </h1>

            <p class="auth-subtitle">
                Vantorium hesabına giriş yap ve
                sistemlerine devam et.
            </p>

            {error_html}

            <form method="POST">

                <label>
                    Kullanıcı Adı
                </label>

                <input
                    type="text"
                    name="username"
                    required
                    autocomplete="username"
                    placeholder="kullanici_adi"
                >

                <label>
                    Şifre
                </label>

                <input
                    type="password"
                    name="password"
                    required
                    autocomplete="current-password"
                    placeholder="••••••••"
                >

                <button
                    type="submit"
                    class="btn"
                >
                    Giriş Yap
                </button>

            </form>

            <div class="auth-links">
                Hesabın yok mu?
                <a href="/register">
                    Kayıt Ol
                </a>
            </div>

            <div class="policy-box">

                <div class="policy-box-title">
                    Kurallar ve Politikalar
                </div>

                <div class="policy-box-text">
                    Hizmeti kullanmadan önce
                    kurallarımızı ve politikalarımızı
                    inceleyebilirsin.
                </div>

                <a
                    class="policy-link"
                    href="https://api-vantorium-xyz-production.up.railway.app/info"
                >
                    Kurallar & Politikaları Gör
                </a>

            </div>

        </section>

    </main>

    """

    return render_page(
        "Giriş Yap",
        content
    )


# =========================================================
# 14. LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    token = request.cookies.get(
        "session_token"
    )

    if token:

        conn = db()

        conn.execute(
            "DELETE FROM sessions WHERE token = ?",
            (token,)
        )

        conn.commit()
        conn.close()

    response = make_response(
        redirect("/login")
    )

    response.delete_cookie(
        "session_token"
    )

    return response


# =========================================================
# 15. DASHBOARD
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():

    user = get_current_user()

    base_url = request.host_url.rstrip("/")

    example_url = (
        f"{base_url}/api-key="
        f"{user['api_key']}?word=merhaba"
    )

    content = f"""

    <main class="container wide">

        <div class="page-header">

            <h1 class="page-title">
                Dashboard
            </h1>

            <p class="page-subtitle">
                Hoş geldin,
                <strong style="color:white;">
                    {html.escape(user['username'])}
                </strong>.
                Vantorium hesabını buradan yönet.
            </p>

        </div>

        <div class="grid">

            <section class="card">

                <h3>
                    🔑 API Anahtarın
                </h3>

                <div class="api-key-box">
                    {html.escape(user['api_key'])}
                </div>

                <p>
                    API anahtarını gizli tut.
                    Sızdırılması durumunda yenileyebilirsin.
                </p>

                <form
                    method="POST"
                    action="/regenerate-key"
                    style="margin-top:15px;"
                >

                    <button
                        type="submit"
                        class="btn danger btn-small"
                    >
                        Anahtarı Yenile
                    </button>

                </form>

            </section>

            <section class="card">

                <h3>
                    ⚡ API Durumu
                </h3>

                <p style="color:#54e3b5;">
                    ● Sistem aktif
                </p>

                <p style="margin-top:8px;">
                    Vantorium API motoru
                    istekleri işlemeye hazır.
                </p>

            </section>

        </div>

        <section class="card">

            <h3>
                🚀 API Kullanımı
            </h3>

            <p>
                HTTP GET isteği göndererek
                Vantorium motorunu kullanabilirsin.
            </p>

            <div class="code-block">
                {html.escape(example_url)}
            </div>

            <p>
                JSON yanıtında
                <code style="color:#51dfb1;">
                    answer
                </code>
                alanı asistanın cevabını içerir.
            </p>

        </section>

        <section class="card">

            <h3>
                🧠 Vantorium Motoru
            </h3>

            <ul>

                <li>
                    Kendi soru-cevap veri setini kullanır.
                </li>

                <li>
                    Daha önce öğrenilen cevapları hafızasında tutabilir.
                </li>

                <li>
                    Google ve Wikipedia üzerinden araştırma yapabilir.
                </li>

                <li>
                    Kod sorularında GitHub sonuçlarını kullanabilir.
                </li>

            </ul>

        </section>

    </main>

    """

    return render_page(
        "Dashboard",
        content,
        user
    )


# =========================================================
# 16. CHAT
# =========================================================

@app.route("/chat")
@login_required
def chat():

    user = get_current_user()

    content = """

    <main class="chat-page">

        <div class="chat-layout">

            <div
                class="chat-history"
                id="chatHistory"
            >

                <div class="chat-msg ai">

                    <div class="avatar">
                        V
                    </div>

                    <div class="msg-content">
                        Merhaba! Ben Vantorium.
                        Sorunu yaz, birlikte bakalım.
                    </div>

                </div>

            </div>

            <div class="chat-input-area">

                <div class="chat-input-box">

                    <input
                        type="text"
                        id="chatInput"
                        placeholder="Vantorium'a bir şey sor..."
                        autocomplete="off"
                    >

                    <button
                        id="sendBtn"
                        onclick="sendChat()"
                        aria-label="Gönder"
                    >

                        <svg
                            width="17"
                            height="17"
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="2.4"
                            stroke-linecap="round"
                            stroke-linejoin="round"
                        >

                            <line
                                x1="12"
                                y1="19"
                                x2="12"
                                y2="5"
                            ></line>

                            <polyline
                                points="5 12 12 5 19 12"
                            ></polyline>

                        </svg>

                    </button>

                </div>

            </div>

        </div>

    </main>

    <script>

    const chatHistory =
        document.getElementById("chatHistory");

    const chatInput =
        document.getElementById("chatInput");

    const sendBtn =
        document.getElementById("sendBtn");


    chatInput.focus();


    chatInput.addEventListener(
        "keydown",
        function(event) {

            if (
                event.key === "Enter"
                && !event.shiftKey
            ) {

                event.preventDefault();

                sendChat();

            }

        }
    );


    function addMsg(text, sender) {

        const wrapper =
            document.createElement("div");

        wrapper.className =
            "chat-msg " + sender;


        const avatar =
            document.createElement("div");

        avatar.className =
            "avatar";

        avatar.textContent =
            sender === "user"
                ? "K"
                : "V";


        const message =
            document.createElement("div");

        message.className =
            "msg-content";

        message.textContent =
            text;


        wrapper.appendChild(avatar);

        wrapper.appendChild(message);

        chatHistory.appendChild(wrapper);

        chatHistory.scrollTop =
            chatHistory.scrollHeight;


        return message;

    }


    async function sendChat() {

        const text =
            chatInput.value.trim();

        if (!text)
            return;


        chatInput.value = "";

        sendBtn.disabled = true;


        addMsg(
            text,
            "user"
        );


        const aiMessage =
            addMsg(
                "Düşünüyor...",
                "ai"
            );


        try {

            const response =
                await fetch(
                    "/api/chat",
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        body: JSON.stringify({
                            message: text
                        })
                    }
                );


            if (!response.ok) {
                throw new Error();
            }


            const reader =
                response.body.getReader();

            const decoder =
                new TextDecoder();

            aiMessage.textContent = "";


            while (true) {

                const {
                    done,
                    value
                } = await reader.read();


                if (done)
                    break;


                aiMessage.textContent +=
                    decoder.decode(
                        value,
                        {stream:true}
                    );


                chatHistory.scrollTop =
                    chatHistory.scrollHeight;

            }

        } catch(error) {

            aiMessage.textContent =
                "Bağlantı hatası oluştu.";

        }


        sendBtn.disabled = false;

        chatInput.focus();

    }

    </script>

    """

    return render_page(
        "Sohbet",
        content,
        user
    )


# =========================================================
# 17. CHAT API
# =========================================================

@app.route(
    "/api/chat",
    methods=["POST"]
)
@login_required
def api_chat():

    data = request.get_json(
        silent=True
    ) or {}

    kelime = str(
        data.get("message", "")
    ).strip()

    if not kelime:

        return Response(
            "Mesaj boş olamaz.",
            mimetype="text/plain"
        )

    if len(kelime) > 4000:

        return Response(
            "Mesaj çok uzun.",
            mimetype="text/plain"
        ), 400

    answer, source = get_answer(
        kelime
    )

    def generate():

        for char in answer:

            yield char

            time.sleep(0.008)

    return Response(
        generate(),
        mimetype="text/plain; charset=utf-8"
    )


# =========================================================
# 18. REGENERATE API KEY
# =========================================================

@app.route(
    "/regenerate-key",
    methods=["POST"]
)
@login_required
def regenerate_key():

    user = get_current_user()

    new_key = (
        "vnt_"
        + secrets.token_hex(24)
    )

    conn = db()

    conn.execute(
        "UPDATE users SET api_key = ? WHERE id = ?",
        (new_key, user["id"])
    )

    conn.commit()
    conn.close()

    return redirect("/dashboard")


# =========================================================
# 19. INFO / RULES
# =========================================================

@app.route("/info")
def info():

    user = get_current_user()

    base_url = request.host_url.rstrip("/")

    content = f"""

    <main class="container wide">

        <div class="page-header">

            <h1 class="page-title">
                Bilgi Merkezi
            </h1>

            <p class="page-subtitle">
                Vantorium API ve kullanım politikaları.
            </p>

        </div>


        <section class="card">

            <h3>
                🤖 Vantorium Nedir?
            </h3>

            <p>
                Vantorium; soru-cevap veri tabanı,
                hafıza sistemi ve web araştırma
                özelliklerini bir araya getiren
                yapay zekâ asistanıdır.
            </p>

        </section>


        <h2 class="section-title">
            API Kullanımı
        </h2>

        <section class="card">

            <p>
                API anahtarın hesabına özel olarak
                oluşturulur.
            </p>

            <div class="code-block">
                {html.escape(base_url)}
                /api-key=SENIN_ANAHTARIN?word=merhaba
            </div>

            <p>
                Örnek:
            </p>

            <div class="code-block">
                {html.escape(base_url)}
                /api-key=vnt_ornekanahtar123?word=merhaba
            </div>

        </section>


        <h2 class="section-title">
            Kurallar ve Koşullar
        </h2>

        <section class="card">

            <ul>

                <li>
                    API anahtarını üçüncü kişilerle paylaşma.
                </li>

                <li>
                    Sisteme zarar verecek saldırılar
                    gerçekleştirme.
                </li>

                <li>
                    DDoS, SQL Injection ve XSS gibi
                    kötüye kullanım yasaktır.
                </li>

                <li>
                    Yasa dışı faaliyetlerde kullanma.
                </li>

                <li>
                    Aşırı otomatik isteklerle sistemi
                    yorma.
                </li>

                <li>
                    Vantorium tarafından verilen
                    bilgileri kritik kararlar öncesinde
                    doğrula.
                </li>

            </ul>

        </section>


        <h2 class="section-title">
            Gizlilik
        </h2>

        <section class="card">

            <p>
                Hesap işlemleri için kullanıcı adı,
                parola özeti ve API anahtarı tutulur.
                Sistem performansını geliştirmek amacıyla
                bazı teknik veriler saklanabilir.
            </p>

        </section>


        <h2 class="section-title">
            Hizmet Kullanımı
        </h2>

        <section class="card">

            <p>
                Vantorium hizmeti geliştirilebilir,
                güncellenebilir veya bakım nedeniyle
                geçici olarak kullanılamayabilir.
            </p>

        </section>


        <h2 class="section-title">
            Yasal Uyarı
        </h2>

        <section class="card">

            <p>
                Vantorium tarafından oluşturulan
                cevaplar bilgilendirme amaçlıdır.
                Tıbbi, hukuki veya finansal profesyonel
                tavsiye yerine geçmez.
            </p>

        </section>


        <div class="footer">
            © 2026 Vantorium AI · Tüm hakları saklıdır.
        </div>

    </main>

    """

    return render_page(
        "Bilgi Merkezi",
        content,
        user
    )


# =========================================================
# 20. EXTERNAL API
# =========================================================

@app.route(
    "/api-key=<apikey>",
    methods=["GET"]
)
def api_word(apikey):

    word = request.args.get(
        "word",
        ""
    ).strip()

    if not word:

        return jsonify({
            "error":
                "word parametresi gerekli",

            "usage":
                "/api-key=...?word=kelime"
        }), 400


    conn = db()

    user = conn.execute(
        "SELECT * FROM users WHERE api_key = ?",
        (apikey,)
    ).fetchone()

    conn.close()


    if not user:

        return jsonify({
            "error":
                "Geçersiz API anahtarı"
        }), 401


    start = time.time()

    answer, source = get_answer(
        word
    )


    return jsonify({

        "input": word,

        "answer": answer,

        "meta": {

            "source": source,

            "time_ms":
                round(
                    (time.time() - start)
                    * 1000,
                    2
                ),

            "engine":
                "Vantorium v4.1",

            "timestamp":
                datetime.now()
                .astimezone()
                .isoformat()
        }

    })


# =========================================================
# 21. RUN
# =========================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    app.run(
        host="0.0.0.0",
        port=port
    )

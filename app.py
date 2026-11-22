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
import ast
import operator
from datetime import datetime
from functools import wraps
from flask import (
    Flask,
    request,
    jsonify,
    Response,
    redirect,
    make_response
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

DB_FILE = "vantorium.db"

# =========================================================
# 1. DATABASE
# =========================================================

def init_db():
    conn = sqlite3.connect(DB_FILE)
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


def db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


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
# 2. DATASET
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

        try:
            with open(filename, "r", encoding="utf-8") as file:
                current_question = None

                for line in file:
                    line = line.strip()

                    if not line or line.startswith("#"):
                        continue

                    if line.startswith("Input:"):
                        current_question = normalize(
                            line.replace("Input:", "", 1).strip()
                        )

                        if current_question not in data:
                            data[current_question] = []

                    elif line.startswith("Reply:") and current_question:
                        answer = line.replace("Reply:", "", 1).strip()

                        if answer:
                            data[current_question].append(answer)

            break

        except Exception:
            continue

    return data


DATASET = load_dataset()


# =========================================================
# 3. QUERY ANALYSIS
# =========================================================

def analyze_query(query):
    q = normalize(query)

    code_words = [
        "kod",
        "python",
        "javascript",
        "js",
        "node",
        "php",
        "flask",
        "html",
        "css",
        "api",
        "github",
        "programlama",
        "yazılım",
        "function",
        "class",
        "bug",
        "hata",
        "error",
        "debug",
        "sql",
        "database",
        "veritabanı",
        "react",
        "discord bot",
        "telegram bot"
    ]

    greeting_words = [
        "merhaba",
        "selam",
        "hello",
        "hi",
        "hey",
        "günaydın",
        "iyi akşamlar",
        "iyi geceler",
        "nasılsın",
        "naber",
        "nbr"
    ]

    is_math = bool(
        re.fullmatch(
            r"[0-9\s\+\-\*\/\(\)\.\,\^%]+",
            query
        )
        and re.search(r"[\+\-\*\/\^%]", query)
    )

    return {
        "is_greeting": any(
            re.search(r"\b" + re.escape(word) + r"\b", q)
            for word in greeting_words
        ),
        "is_math": is_math,
        "is_code": any(word in q for word in code_words),
        "query": q
    }


# =========================================================
# 4. SAFE MATH
# =========================================================

ALLOWED_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos
}


def safe_math(expression):
    expression = expression.replace(",", ".")
    expression = expression.replace("^", "**")

    if len(expression) > 100:
        raise ValueError("Expression too long")

    tree = ast.parse(expression, mode="eval")

    def calculate(node):
        if isinstance(node, ast.Expression):
            return calculate(node.body)

        if isinstance(node, ast.Constant):
            if isinstance(node.value, (int, float)):
                if abs(node.value) > 10**12:
                    raise ValueError("Number too large")
                return node.value

        if isinstance(node, ast.BinOp):
            left = calculate(node.left)
            right = calculate(node.right)

            operation = ALLOWED_OPERATORS.get(type(node.op))

            if operation is None:
                raise ValueError("Operator not allowed")

            if isinstance(node.op, ast.Pow) and abs(right) > 20:
                raise ValueError("Exponent too large")

            result = operation(left, right)

            if abs(result) > 10**15:
                raise ValueError("Result too large")

            return result

        if isinstance(node, ast.UnaryOp):
            operation = ALLOWED_OPERATORS.get(type(node.op))

            if operation is None:
                raise ValueError("Operator not allowed")

            return operation(calculate(node.operand))

        raise ValueError("Invalid expression")

    return calculate(tree)


# =========================================================
# 5. WEB SEARCH
# =========================================================

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/131.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/131.0 Safari/537.36"
]


def create_session():
    session = requests.Session()

    session.headers.update({
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7"
    })

    return session


def github_search(query):
    """
    Public GitHub repository search.
    Token zorunlu değildir.

    Kod/yazılım sorularında GitHub kullanılır.
    """

    results = []

    try:
        session = create_session()

        params = {
            "q": query,
            "sort": "stars",
            "order": "desc",
            "per_page": 5
        }

        response = session.get(
            "https://api.github.com/search/repositories",
            params=params,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2026-03-10"
            },
            timeout=8
        )

        if response.status_code != 200:
            return results

        data = response.json()

        for item in data.get("items", [])[:5]:
            description = item.get("description") or ""

            results.append({
                "title": item.get("full_name", ""),
                "description": description,
                "url": item.get("html_url", ""),
                "stars": item.get("stargazers_count", 0),
                "language": item.get("language") or "",
                "source": "github"
            })

    except Exception:
        pass

    return results


def wikipedia_search(query):
    results = []

    try:
        session = create_session()

        params = {
            "action": "query",
            "list": "search",
            "srsearch": query,
            "utf8": 1,
            "format": "json",
            "srlimit": 5
        }

        response = session.get(
            "https://tr.wikipedia.org/w/api.php",
            params=params,
            timeout=8
        )

        if response.status_code != 200:
            return results

        data = response.json()

        for item in data.get("query", {}).get("search", [])[:5]:
            title = item.get("title", "")
            snippet = item.get("snippet", "")

            snippet = re.sub(r"<[^>]+>", "", snippet)
            snippet = re.sub(r"\s+", " ", snippet).strip()

            url = (
                "https://tr.wikipedia.org/wiki/"
                + urllib.parse.quote(title.replace(" ", "_"))
            )

            results.append({
                "title": title,
                "description": snippet,
                "url": url,
                "source": "wikipedia"
            })

    except Exception:
        pass

    return results


def search_web(query, parts):
    """
    Kod sorularında:
        GitHub

    Diğer sorularda:
        Wikipedia

    Böylece GitHub sonuçları normal sorulara gereksiz şekilde
    karışmaz.
    """

    if parts["is_code"]:
        return github_search(query)

    return wikipedia_search(query)


# =========================================================
# 6. ANSWER BUILDER
# =========================================================

def clean_text(text):
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def choose_best_result(results):
    if not results:
        return None

    cleaned = []

    for result in results:
        title = clean_text(result.get("title", ""))
        description = clean_text(
            result.get("description", "")
        )

        if not title and not description:
            continue

        cleaned.append({
            **result,
            "title": title,
            "description": description
        })

    if not cleaned:
        return None

    # GitHub için yıldız sayısını da hesaba kat.
    if cleaned[0].get("source") == "github":
        cleaned.sort(
            key=lambda x: x.get("stars", 0),
            reverse=True
        )

    return cleaned[0]


def build_normal_answer(query, results):
    """
    Arama sonuçlarını kullanıcıya ham şekilde göstermiyoruz.
    En uygun sonucu seçip doğal bir cevap haline getiriyoruz.
    """

    if not results:
        return (
            "Bu konuda güvenilir bir bilgi bulamadım. "
            "İstersen soruyu biraz daha ayrıntılı yazabilirsin."
        )

    best = choose_best_result(results)

    if not best:
        return (
            "Arama yaptım fakat kullanılabilir bir sonuç "
            "bulamadım."
        )

    title = best.get("title", "")
    description = best.get("description", "")
    source = best.get("source", "")

    if source == "github":
        language = best.get("language", "")
        stars = best.get("stars", 0)

        answer_parts = []

        answer_parts.append(
            f"{query} konusunda GitHub'daki en uygun "
            f"kaynaklardan biri **{title}**."
        )

        if description:
            answer_parts.append(description)

        extra = []

        if language:
            extra.append(f"Dil: {language}")

        if stars:
            extra.append(f"⭐ {stars:,} yıldız".replace(",", "."))

        if extra:
            answer_parts.append(" • ".join(extra))

        answer_parts.append(
            f"Kaynak: {best.get('url', '')}"
        )

        return "\n\n".join(answer_parts)

    # Wikipedia
    answer_parts = []

    if title:
        answer_parts.append(
            f"**{query}** hakkında bulduğum en uygun bilgi:"
        )

    if description:
        answer_parts.append(description)

    if title:
        answer_parts.append(
            f"Kaynak: {best.get('url', '')}"
        )

    return "\n\n".join(answer_parts)


# =========================================================
# 7. MAIN AI ENGINE
# =========================================================

def get_answer(kelime):
    normalized = normalize(kelime)
    parts = analyze_query(kelime)

    # Greeting
    if parts["is_greeting"]:
        return (
            random.choice([
                "Selam! Ben Vantorium. Hazırım, ne hakkında konuşalım?",
                "Merhaba! Vantorium hazır. Sana nasıl yardımcı olabilirim?",
                "Selam kral! Ne araştırmamı veya çözmemi istersin?"
            ]),
            "selamlama"
        )

    # Math
    if parts["is_math"]:
        try:
            result = safe_math(kelime)

            if isinstance(result, float) and result.is_integer():
                result = int(result)

            return f"Sonuç: {result}", "matematik"

        except Exception:
            return (
                "Bu matematik ifadesini güvenli şekilde çözemedim.",
                "hata"
            )

    # Dataset
    if normalized in DATASET and DATASET[normalized]:
        return (
            random.choice(DATASET[normalized]),
            "veri_seti"
        )

    # Memory
    cached = memory_get(normalized)

    if cached:
        return cached, "hafiza"

    # Search
    results = search_web(kelime, parts)

    if results:
        answer = build_normal_answer(
            kelime,
            results
        )

        memory_save(
            normalized,
            answer,
            0.85,
            results[0].get("source", "web")
        )

        return answer, results[0].get(
            "source",
            "web"
        )

    return (
        "Bunu şu anda bilmiyorum ve kullanılabilir "
        "bir kaynak da bulamadım.",
        "bulunamadi"
    )


# =========================================================
# 8. AUTH
# =========================================================

def get_current_user():
    token = request.cookies.get("session_token")

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
# 9. UI
# =========================================================

BASE_STYLE = """
<style>

:root {
    --bg: #07090d;
    --panel: #0e1117;
    --panel2: #12161d;
    --border: rgba(255,255,255,.08);
    --muted: #8b93a1;
    --text: #f4f7fb;
    --green: #18d49b;
    --green2: #0ea878;
    --danger: #ef4444;
}

* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

html,
body {
    min-height: 100%;
}

body {
    font-family:
        Inter,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        Roboto,
        sans-serif;

    background:
        radial-gradient(
            circle at 50% -20%,
            rgba(24,212,155,.12),
            transparent 40%
        ),
        var(--bg);

    color: var(--text);

    -webkit-font-smoothing: antialiased;
    text-rendering: optimizeLegibility;
}

a {
    color: inherit;
    text-decoration: none;
}

button,
input {
    font: inherit;
}


/* =====================================================
   NAVBAR
===================================================== */

.navbar {
    position: sticky;
    top: 0;
    z-index: 100;

    height: 68px;

    display: flex;
    align-items: center;
    justify-content: space-between;

    padding: 0 22px;

    background: rgba(7,9,13,.78);
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
            #1ee6a9,
            #0d9b74
        );

    box-shadow:
        0 8px 30px rgba(24,212,155,.2);

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

    color: #9ba3b0;

    font-size: 13px;
    font-weight: 600;

    transition:
        .2s ease;
}

.btn-nav:hover {
    color: white;
    background: rgba(255,255,255,.06);
}

.btn-nav.primary {
    color: #04140f;

    background: var(--green);

    box-shadow:
        0 8px 25px rgba(24,212,155,.16);
}

.btn-nav.primary:hover {
    background: #2be8ae;
}


/* =====================================================
   AUTH
===================================================== */

.auth-page {
    min-height:
        calc(100vh - 68px);

    display: flex;
    align-items: center;
    justify-content: center;

    padding: 35px 18px;
}

.auth-panel {
    width: 100%;
    max-width: 430px;

    padding: 30px;

    background:
        linear-gradient(
            180deg,
            rgba(18,22,29,.97),
            rgba(11,14,19,.97)
        );

    border: 1px solid var(--border);

    border-radius: 22px;

    box-shadow:
        0 30px 100px rgba(0,0,0,.45);

    animation:
        panelIn .35s ease;
}

@keyframes panelIn {
    from {
        opacity: 0;
        transform: translateY(12px) scale(.98);
    }

    to {
        opacity: 1;
        transform: none;
    }
}

.auth-brand {
    text-align: center;
    margin-bottom: 25px;
}

.auth-brand .mini-logo {
    width: 50px;
    height: 50px;

    margin: 0 auto 15px;

    display: flex;
    align-items: center;
    justify-content: center;

    border-radius: 15px;

    background:
        linear-gradient(
            135deg,
            #1ee6a9,
            #0b956e
        );

    font-size: 21px;
    font-weight: 900;

    box-shadow:
        0 15px 45px rgba(24,212,155,.18);
}

.auth-brand h1 {
    font-size: 23px;
    letter-spacing: -.7px;
}

.auth-brand p {
    margin-top: 7px;

    color: var(--muted);

    font-size: 13px;
    line-height: 1.5;
}

.form-group {
    margin-bottom: 16px;
}

label {
    display: block;

    margin-bottom: 7px;

    color: #cbd1da;

    font-size: 12px;
    font-weight: 700;
}

input[type=text],
input[type=password] {
    width: 100%;

    padding: 13px 14px;

    color: white;

    background: #080b10;

    border: 1px solid rgba(255,255,255,.09);

    border-radius: 11px;

    outline: none;

    transition: .2s ease;
}

input:focus {
    border-color: rgba(24,212,155,.65);

    box-shadow:
        0 0 0 4px rgba(24,212,155,.09);
}

.main-btn {
    width: 100%;

    padding: 13px;

    border: 0;
    border-radius: 11px;

    cursor: pointer;

    color: #03140f;

    background: var(--green);

    font-weight: 800;

    transition: .2s ease;
}

.main-btn:hover {
    background: #2be8ae;

    transform: translateY(-1px);
}

.error {
    margin-bottom: 17px;

    padding: 12px 13px;

    border-radius: 11px;

    background: rgba(239,68,68,.08);

    border: 1px solid rgba(239,68,68,.16);

    color: #ff8b8b;

    font-size: 13px;
}


/* POLICY BOX */

.policy-box {
    margin-top: 22px;

    padding: 15px;

    border-radius: 14px;

    background:
        rgba(255,255,255,.025);

    border:
        1px solid rgba(255,255,255,.07);
}

.policy-title {
    display: flex;
    align-items: center;
    gap: 9px;

    margin-bottom: 7px;

    font-size: 13px;
    font-weight: 800;
}

.policy-icon {
    width: 28px;
    height: 28px;

    display: flex;
    align-items: center;
    justify-content: center;

    border-radius: 8px;

    background: rgba(24,212,155,.1);

    color: var(--green);
}

.policy-box p {
    color: #7f8794;

    font-size: 12px;
    line-height: 1.55;

    margin-bottom: 10px;
}

.policy-link {
    display: inline-flex;
    align-items: center;
    gap: 5px;

    color: var(--green);

    font-size: 12px;
    font-weight: 700;
}

.auth-switch {
    text-align: center;

    margin-top: 18px;

    color: #747d8b;

    font-size: 13px;
}

.auth-switch a {
    color: var(--green);
    font-weight: 700;
}


/* =====================================================
   DASHBOARD
===================================================== */

.container {
    width: 100%;
    max-width: 980px;

    margin: 0 auto;

    padding: 42px 20px;
}

.page-title {
    font-size: 30px;
    letter-spacing: -1px;
}

.subtitle {
    margin-top: 7px;

    color: var(--muted);

    font-size: 14px;
    line-height: 1.6;
}

.card {
    margin-top: 20px;

    padding: 24px;

    background:
        rgba(14,17,23,.9);

    border: 1px solid var(--border);

    border-radius: 17px;
}

.card h3 {
    margin-bottom: 14px;

    font-size: 15px;
}

.card p {
    color: #929aa7;

    font-size: 13px;
    line-height: 1.7;
}

.api-key-box {
    margin-top: 12px;

    padding: 14px;

    background: #080b10;

    border: 1px solid rgba(255,255,255,.07);

    border-radius: 10px;

    color: var(--green);

    font-family: monospace;

    word-break: break-all;
}

.code-block {
    margin-top: 12px;

    padding: 15px;

    background: #070a0e;

    border: 1px solid rgba(255,255,255,.07);

    border-radius: 10px;

    overflow-x: auto;

    color: #cfd6df;

    font-family: monospace;

    font-size: 12px;

    line-height: 1.6;
}

.small-danger {
    margin-top: 14px;

    padding: 10px 14px;

    border: 0;
    border-radius: 9px;

    color: white;

    background: var(--danger);

    cursor: pointer;

    font-size: 12px;
    font-weight: 700;
}


/* =====================================================
   CHAT
===================================================== */

.chat-shell {
    height:
        calc(100vh - 68px);

    display: flex;
    flex-direction: column;

    max-width: 980px;

    margin: 0 auto;

    width: 100%;
}

.chat-history {
    flex: 1;

    overflow-y: auto;

    padding:
        28px
        20px
        160px;

    scrollbar-width: thin;
}

.chat-history::-webkit-scrollbar {
    width: 5px;
}

.chat-history::-webkit-scrollbar-thumb {
    background: #252b34;

    border-radius: 20px;
}

.chat-msg {
    width: 100%;
    max-width: 850px;

    margin: 0 auto 25px;

    display: flex;

    gap: 12px;

    animation:
        msgIn .25s ease;
}

@keyframes msgIn {
    from {
        opacity: 0;
        transform: translateY(5px);
    }

    to {
        opacity: 1;
        transform: none;
    }
}

.chat-msg.user {
    justify-content: flex-end;
}

.avatar {
    width: 35px;
    height: 35px;

    flex: 0 0 35px;

    display: flex;
    align-items: center;
    justify-content: center;

    border-radius: 11px;

    font-size: 12px;
    font-weight: 900;
}

.chat-msg.ai .avatar {
    background:
        linear-gradient(
            135deg,
            #19d9a0,
            #0b986f
        );

    color: #03140f;

    box-shadow:
        0 8px 25px rgba(24,212,155,.12);
}

.chat-msg.user .avatar {
    order: 2;

    background: #1c222c;

    color: white;
}

.msg-content {
    max-width: min(720px, 78%);

    color: #e7ebf0;

    font-size: 15px;
    line-height: 1.75;

    white-space: pre-wrap;

    word-break: break-word;
}

.chat-msg.user .msg-content {
    order: 1;

    padding:
        11px
        15px;

    border-radius: 16px;

    border-top-right-radius: 5px;

    background:
        #171d26;
}


/* thinking */

.thinking-box {
    display: flex;
    flex-direction: column;
    gap: 8px;

    padding-top: 1px;
}

.thinking-main {
    color: #dfe6ed;

    font-weight: 600;
}

.thinking-status {
    display: flex;
    align-items: center;
    gap: 8px;

    color: #788291;

    font-size: 12px;
}

.loader {
    width: 8px;
    height: 8px;

    border-radius: 50%;

    background: var(--green);

    box-shadow:
        0 0 15px rgba(24,212,155,.65);

    animation:
        pulse 1s infinite;
}

@keyframes pulse {
    0%,100% {
        opacity: .3;
        transform: scale(.75);
    }

    50% {
        opacity: 1;
        transform: scale(1);
    }
}


/* INPUT */

.chat-composer {
    position: fixed;

    left: 50%;

    bottom: 0;

    transform: translateX(-50%);

    width: min(900px, calc(100% - 28px));

    padding:
        15px
        0
        22px;

    background:
        linear-gradient(
            to bottom,
            transparent,
            var(--bg) 25%
        );

    z-index: 20;
}

.composer-box {
    position: relative;

    background: #11161e;

    border:
        1px solid rgba(255,255,255,.09);

    border-radius: 17px;

    box-shadow:
        0 20px 60px rgba(0,0,0,.4);
}

.composer-box input {
    width: 100%;

    padding:
        17px
        58px
        17px
        17px;

    color: white;

    background: transparent;

    border: 0;

    outline: none;

    font-size: 14px;
}

.send-btn {
    position: absolute;

    right: 8px;
    top: 50%;

    transform:
        translateY(-50%);

    width: 38px;
    height: 38px;

    border: 0;

    border-radius: 11px;

    display: flex;
    align-items: center;
    justify-content: center;

    color: #03140f;

    background: var(--green);

    cursor: pointer;

    transition: .2s ease;
}

.send-btn:hover {
    transform:
        translateY(-50%)
        scale(1.04);
}

.send-btn:disabled {
    opacity: .45;
    cursor: not-allowed;
}


/* =====================================================
   INFO
===================================================== */

.info-card {
    margin-top: 18px;

    padding: 22px;

    background: rgba(14,17,23,.9);

    border: 1px solid var(--border);

    border-radius: 16px;
}

.info-card h2 {
    margin-bottom: 11px;

    font-size: 16px;
}

.info-card p,
.info-card li {
    color: #929aa7;

    font-size: 13px;
    line-height: 1.8;
}

.info-card ul {
    padding-left: 19px;
}

.footer {
    padding: 35px 20px;

    text-align: center;

    color: #555d69;

    font-size: 12px;
}


/* =====================================================
   MOBILE
===================================================== */

@media(max-width: 650px) {

    .navbar {
        height: 60px;

        padding:
            0 13px;
    }

    .nav-actions {
        gap: 2px;
    }

    .btn-nav {
        padding:
            8px 7px;

        font-size: 11px;
    }

    .logo {
        font-size: 15px;
    }

    .logo-icon {
        width: 30px;
        height: 30px;
    }

    .auth-page {
        min-height:
            calc(100vh - 60px);

        padding:
            18px 13px;
    }

    .auth-panel {
        padding: 22px 18px;

        border-radius: 19px;
    }

    .container {
        padding:
            27px 14px;
    }

    .page-title {
        font-size: 25px;
    }

    .chat-shell {
        height:
            calc(100vh - 60px);
    }

    .chat-history {
        padding:
            20px
            12px
            145px;
    }

    .chat-msg {
        gap: 9px;
        margin-bottom: 21px;
    }

    .avatar {
        width: 31px;
        height: 31px;
        flex-basis: 31px;
    }

    .msg-content {
        max-width: 82%;

        font-size: 14px;
        line-height: 1.65;
    }

    .chat-composer {
        width:
            calc(100% - 18px);

        padding-bottom: 13px;
    }

}

</style>

<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>

<link
    href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap"
    rel="stylesheet"
>
"""


# =========================================================
# 10. PAGE RENDER
# =========================================================

def render_page(title, content, user=None, show_nav=True):

    nav = ""

    if show_nav:

        if user:

            actions = """
                <a href="/dashboard" class="btn-nav">
                    Dashboard
                </a>

                <a href="/chat" class="btn-nav">
                    Sohbet
                </a>

                <a href="/info" class="btn-nav">
                    Bilgi
                </a>

                <a href="/logout" class="btn-nav">
                    Çıkış
                </a>
            """

        else:

            actions = """
                <a href="/info" class="btn-nav">
                    Bilgi
                </a>

                <a href="/login" class="btn-nav">
                    Giriş
                </a>

                <a href="/register" class="btn-nav primary">
                    Kayıt Ol
                </a>
            """

        nav = f"""
        <nav class="navbar">

            <a href="/" class="logo">
                <span class="logo-icon">V</span>
                Vantorium
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
    content="width=device-width, initial-scale=1.0, viewport-fit=cover"
>

<meta
    name="theme-color"
    content="#07090d"
>

<title>{title} | Vantorium</title>

{BASE_STYLE}

</head>

<body>

{nav}

{content}

</body>

</html>
"""


# =========================================================
# 11. AUTH PAGE
# =========================================================

def auth_page(
    title,
    heading,
    description,
    action,
    action_text,
    switch_text,
    switch_link,
    switch_label,
    error=None
):

    error_html = ""

    if error:
        error_html = f"""
        <div class="error">
            {error}
        </div>
        """

    content = f"""
    <main class="auth-page">

        <section class="auth-panel">

            <div class="auth-brand">

                <div class="mini-logo">
                    V
                </div>

                <h1>
                    {heading}
                </h1>

                <p>
                    {description}
                </p>

            </div>

            {error_html}

            <form
                method="POST"
                action="{action}"
            >

                <div class="form-group">

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

                </div>

                <div class="form-group">

                    <label>
                        Şifre
                    </label>

                    <input
                        type="password"
                        name="password"
                        required
                        autocomplete="{
                            'new-password'
                            if action == '/register'
                            else 'current-password'
                        }"
                        placeholder="••••••••"
                    >

                </div>

                <button
                    type="submit"
                    class="main-btn"
                >
                    {action_text}
                </button>

            </form>


            <!-- KURALLAR / POLİTİKALAR -->

            <div class="policy-box">

                <div class="policy-title">

                    <span class="policy-icon">
                        ✓
                    </span>

                    Kurallar ve Politikalar

                </div>

                <p>
                    Vantorium'u kullanarak hizmet şartlarını,
                    kullanım kurallarını ve gizlilik politikasını
                    kabul etmiş olursun.
                </p>

                <a
                    href="https://api-vantorium-xyz-production.up.railway.app/info"
                    class="policy-link"
                >
                    Kuralları ve politikaları incele →
                </a>

            </div>


            <div class="auth-switch">

                {switch_text}

                <a href="{switch_link}">
                    {switch_label}
                </a>

            </div>

        </section>

    </main>
    """

    return render_page(
        title,
        content,
        show_nav=True
    )


# =========================================================
# 12. ROUTES
# =========================================================

@app.route("/")
def index():

    if get_current_user():
        return redirect("/dashboard")

    return redirect("/login")


@app.route("/register", methods=["GET", "POST"])
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
                "Kullanıcı adı en az 3 karakter "
                "olmalı."
            )

        elif len(username) > 30:

            error = (
                "Kullanıcı adı en fazla 30 karakter "
                "olabilir."
            )

        elif len(password) < 6:

            error = (
                "Şifre en az 6 karakter olmalı."
            )

        else:

            conn = db()

            exists = conn.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,)
            ).fetchone()

            if exists:

                error = (
                    "Bu kullanıcı adı zaten alınmış."
                )

                conn.close()

            else:

                api_key = (
                    "vnt_"
                    + secrets.token_hex(24)
                )

                conn.execute("""
                    INSERT INTO users
                    (username, password_hash, api_key, created_at)
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

    return auth_page(
        "Kayıt Ol",
        "Vantorium'a Katıl",
        "Kendi hesabını oluştur ve Vantorium API'ni kullanmaya başla.",
        "/register",
        "Hesap Oluştur",
        "Zaten hesabın var mı?",
        "/login",
        "Giriş Yap",
        error
    )


@app.route("/login", methods=["GET", "POST"])
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
                secure=request.is_secure,
                samesite="Lax",
                max_age=30 * 24 * 3600
            )

            return response

        error = "Kullanıcı adı veya şifre hatalı."

        conn.close()

    return auth_page(
        "Giriş",
        "Tekrar Hoş Geldin",
        "Vantorium hesabına giriş yap ve yapay zekâ asistanını kullan.",
        "/login",
        "Giriş Yap",
        "Hesabın yok mu?",
        "/register",
        "Kayıt Ol",
        error
    )


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
# 13. DASHBOARD
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():

    user = get_current_user()

    base_url = request.host_url.rstrip("/")

    example_url = (
        f"{base_url}/api-key="
        f"{user['api_key']}"
        f"?word=merhaba"
    )

    content = f"""

    <main class="container">

        <h1 class="page-title">
            Dashboard
        </h1>

        <p class="subtitle">
            Hoş geldin,
            <strong style="color:white">
                {user['username']}
            </strong>.
            Vantorium hesabını buradan yönetebilirsin.
        </p>


        <section class="card">

            <h3>
                API Anahtarın
            </h3>

            <div class="api-key-box">
                {user['api_key']}
            </div>

            <p>
                API anahtarını kimseyle paylaşma.
                Gerekirse aşağıdaki butondan yenileyebilirsin.
            </p>

            <form
                method="POST"
                action="/regenerate-key"
            >

                <button
                    class="small-danger"
                    type="submit"
                >
                    Anahtarı Yenile
                </button>

            </form>

        </section>


        <section class="card">

            <h3>
                API Kullanımı
            </h3>

            <p>
                HTTP GET isteği göndererek Vantorium'u
                uygulamalarında kullanabilirsin.
            </p>

            <div class="code-block">
                {example_url}
            </div>

            <p style="margin-top:12px">
                Yanıt JSON olarak döner.
            </p>

        </section>


        <section class="card">

            <h3>
                Hızlı Başlangıç
            </h3>

            <p>
                Sohbet ekranından Vantorium'a soru sorabilir,
                sistemin gerektiğinde bilgi kaynağını
                araştırmasını sağlayabilirsin.
            </p>

            <a
                href="/chat"
                class="main-btn"
                style="
                    display:flex;
                    justify-content:center;
                    margin-top:15px;
                "
            >
                Sohbete Başla
            </a>

        </section>

    </main>

    """

    return render_page(
        "Dashboard",
        content,
        user
    )


# =========================================================
# 14. CHAT
# =========================================================

@app.route("/chat")
@login_required
def chat():

    user = get_current_user()

    content = """

    <main class="chat-shell">

        <div
            class="chat-history"
            id="chatHistory"
        >

            <div class="chat-msg ai">

                <div class="avatar">
                    V
                </div>

                <div class="msg-content">
                    Selam! Ben Vantorium. Hazırım.
                    Bir şey sor, gerektiğinde araştırıp
                    en uygun cevabı hazırlayayım.
                </div>

            </div>

        </div>


        <div class="chat-composer">

            <div class="composer-box">

                <input
                    id="chatInput"
                    type="text"
                    placeholder="Vantorium'a bir şey sor..."
                    autocomplete="off"
                    maxlength="2000"
                >

                <button
                    id="sendBtn"
                    class="send-btn"
                    type="button"
                    onclick="sendChat()"
                    aria-label="Gönder"
                >

                    <svg
                        width="17"
                        height="17"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="2.5"
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

    </main>


    <script>

    const historyBox =
        document.getElementById("chatHistory");

    const input =
        document.getElementById("chatInput");

    const sendButton =
        document.getElementById("sendBtn");

    let busy = false;


    function scrollBottom() {

        historyBox.scrollTo({
            top: historyBox.scrollHeight,
            behavior: "smooth"
        });

    }


    function addMessage(text, type) {

        const wrapper =
            document.createElement("div");

        wrapper.className =
            "chat-msg " + type;


        const avatar =
            document.createElement("div");

        avatar.className =
            "avatar";

        avatar.textContent =
            type === "user" ? "K" : "V";


        const message =
            document.createElement("div");

        message.className =
            "msg-content";

        // Güvenli:
        // innerHTML yerine textContent.
        message.textContent =
            text;


        wrapper.appendChild(avatar);
        wrapper.appendChild(message);

        historyBox.appendChild(wrapper);

        scrollBottom();

        return message;
    }


    function createThinkingMessage() {

        const wrapper =
            document.createElement("div");

        wrapper.className =
            "chat-msg ai";


        const avatar =
            document.createElement("div");

        avatar.className =
            "avatar";

        avatar.textContent =
            "V";


        const content =
            document.createElement("div");

        content.className =
            "msg-content";


        content.innerHTML = `
            <div class="thinking-box">

                <div class="thinking-main">
                    Düşünüyor...
                </div>

                <div class="thinking-status">

                    <span class="loader"></span>

                    <span id="thinkingStatus">
                        Sorunu analiz ediyor...
                    </span>

                </div>

            </div>
        `;


        wrapper.appendChild(avatar);
        wrapper.appendChild(content);

        historyBox.appendChild(wrapper);

        scrollBottom();

        return {
            wrapper,
            content
        };

    }


    async function sendChat() {

        if (busy)
            return;


        const text =
            input.value.trim();


        if (!text)
            return;


        busy = true;

        sendButton.disabled = true;

        input.value = "";


        addMessage(
            text,
            "user"
        );


        const thinking =
            createThinkingMessage();


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

                throw new Error(
                    "Server error"
                );

            }


            const reader =
                response.body.getReader();

            const decoder =
                new TextDecoder();


            let buffer = "";

            let answerStarted = false;

            let answerElement = null;


            while (true) {

                const result =
                    await reader.read();


                if (result.done)
                    break;


                buffer +=
                    decoder.decode(
                        result.value,
                        {
                            stream: true
                        }
                    );


                const lines =
                    buffer.split("\\n");

                buffer =
                    lines.pop();


                for (const line of lines) {

                    if (!line.trim())
                        continue;


                    try {

                        const event =
                            JSON.parse(line);


                        if (event.type === "status") {

                            const status =
                                thinking.content
                                    .querySelector(
                                        "#thinkingStatus"
                                    );

                            const main =
                                thinking.content
                                    .querySelector(
                                        ".thinking-main"
                                    );


                            if (status)
                                status.textContent =
                                    event.message;


                            if (main)
                                main.textContent =
                                    event.title || "Düşünüyor...";


                            scrollBottom();

                        }


                        else if (
                            event.type === "answer"
                        ) {

                            if (!answerStarted) {

                                thinking.wrapper.remove();

                                answerElement =
                                    addMessage(
                                        "",
                                        "ai"
                                    );

                                answerStarted = true;

                            }


                            answerElement.textContent +=
                                event.text;


                            scrollBottom();

                        }


                        else if (
                            event.type === "done"
                        ) {

                            scrollBottom();

                        }


                        else if (
                            event.type === "error"
                        ) {

                            if (!answerStarted) {

                                thinking.wrapper.remove();

                                addMessage(
                                    event.message ||
                                    "Bir hata oluştu.",
                                    "ai"
                                );

                            }

                        }

                    } catch (e) {
                        // Bozuk stream parçasını atla.
                    }

                }

            }


        } catch (error) {

            thinking.wrapper.remove();

            addMessage(
                "Bağlantı sırasında bir hata oluştu. Lütfen tekrar dene.",
                "ai"
            );

        }


        busy = false;

        sendButton.disabled = false;

        input.focus();

    }


    input.addEventListener(
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


    input.focus();

    </script>

    """

    return render_page(
        "Sohbet",
        content,
        user
    )


# =========================================================
# 15. STREAMING CHAT API
# =========================================================

@app.route("/api/chat", methods=["POST"])
@login_required
def api_chat():

    data = request.get_json(
        silent=True
    ) or {}

    message = str(
        data.get("message", "")
    ).strip()


    if not message:

        return jsonify({
            "error": "Mesaj boş olamaz."
        }), 400


    if len(message) > 2000:

        return jsonify({
            "error": "Mesaj çok uzun."
        }), 400


    def generate():

        try:

            # 1
            yield json.dumps({
                "type": "status",
                "title": "Düşünüyor...",
                "message": "Sorunu analiz ediyor..."
            }, ensure_ascii=False) + "\n"

            time.sleep(.25)


            parts = analyze_query(
                message
            )


            # Greeting / dataset / math
            local_answer = None
            local_source = None


            if parts["is_greeting"]:

                local_answer = random.choice([
                    "Selam! Ben Vantorium. Hazırım, ne hakkında konuşalım?",
                    "Merhaba! Vantorium hazır. Ne öğrenmek istersin?",
                    "Selam kral! Sorunu gönder, birlikte bakalım."
                ])

                local_source = "selamlama"


            elif parts["is_math"]:

                try:

                    result = safe_math(message)

                    if (
                        isinstance(result, float)
                        and result.is_integer()
                    ):
                        result = int(result)

                    local_answer = (
                        f"Sonuç: {result}"
                    )

                    local_source = "matematik"

                except Exception:

                    local_answer = (
                        "Bu matematik ifadesini "
                        "çözemedim."
                    )

                    local_source = "hata"


            elif (
                normalize(message) in DATASET
                and DATASET[
                    normalize(message)
                ]
            ):

                local_answer = random.choice(
                    DATASET[
                        normalize(message)
                    ]
                )

                local_source = "veri_seti"


            else:

                cached = memory_get(
                    normalize(message)
                )

                if cached:

                    local_answer = cached
                    local_source = "hafiza"


            if local_answer is not None:

                yield json.dumps({
                    "type": "status",
                    "title": "Cevap hazırlanıyor...",
                    "message": "Bildiklerimi kontrol ediyorum..."
                }, ensure_ascii=False) + "\n"

                time.sleep(.3)


            else:

                # 2
                yield json.dumps({
                    "type": "status",
                    "title": "Web'de arıyor...",
                    "message": (
                        "Uygun bilgi kaynaklarını "
                        "araştırıyorum..."
                    )
                }, ensure_ascii=False) + "\n"

                time.sleep(.35)


                results = search_web(
                    message,
                    parts
                )


                # 3
                yield json.dumps({
                    "type": "status",
                    "title": "Bulduğu bilgileri inceliyor...",
                    "message": (
                        f"{len(results)} kaynak "
                        "değerlendiriliyor..."
                    )
                }, ensure_ascii=False) + "\n"

                time.sleep(.35)


                local_answer = build_normal_answer(
                    message,
                    results
                )


                local_source = (
                    results[0].get(
                        "source",
                        "web"
                    )
                    if results
                    else "bulunamadi"
                )


                if results:

                    memory_save(
                        normalize(message),
                        local_answer,
                        .85,
                        local_source
                    )


            # 4
            yield json.dumps({
                "type": "status",
                "title": "En uygun cevabı hazırlıyor...",
                "message": "Bilgileri sade ve anlaşılır hale getiriyorum..."
            }, ensure_ascii=False) + "\n"

            time.sleep(.3)


            # Answer stream
            for char in local_answer:

                yield json.dumps({
                    "type": "answer",
                    "text": char
                }, ensure_ascii=False) + "\n"

                # hızlı ama akıcı
                time.sleep(.006)


            yield json.dumps({
                "type": "done",
                "source": local_source
            }, ensure_ascii=False) + "\n"


        except Exception as error:

            yield json.dumps({
                "type": "error",
                "message": (
                    "Cevap oluşturulurken "
                    "bir hata oluştu."
                )
            }, ensure_ascii=False) + "\n"


    return Response(
        generate(),
        mimetype="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no"
        }
    )


# =========================================================
# 16. API KEY REGENERATE
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
# 17. INFO
# =========================================================

@app.route("/info")
def info():

    user = get_current_user()

    base_url = request.host_url.rstrip("/")

    content = f"""

    <main class="container">

        <h1 class="page-title">
            Bilgi Merkezi
        </h1>

        <p class="subtitle">
            Vantorium'u kullanmadan önce bilmen gerekenler.
        </p>


        <section class="info-card">

            <h2>
                Vantorium Nedir?
            </h2>

            <p>
                Vantorium, soruları analiz eden,
                gerektiğinde bilgi kaynaklarını araştıran
                ve bulunan bilgileri kullanıcıya daha
                anlaşılır şekilde sunmayı amaçlayan
                yapay zekâ asistanıdır.
            </p>

        </section>


        <section class="info-card">

            <h2>
                API Kullanımı
            </h2>

            <p>
                API anahtarını kullanarak şu şekilde
                istek gönderebilirsin:
            </p>

            <div class="code-block">
                {base_url}/api-key=SENIN_API_KEY?word=merhaba
            </div>

        </section>


        <section class="info-card">

            <h2>
                Kurallar
            </h2>

            <ul>

                <li>
                    API anahtarını başkalarıyla paylaşma.
                </li>

                <li>
                    Sistemi aşırı isteklerle yavaşlatmaya
                    veya hizmet dışı bırakmaya çalışma.
                </li>

                <li>
                    Yasa dışı amaçlarla kullanma.
                </li>

                <li>
                    Vantorium'un verdiği bilgileri kritik
                    konularda ayrıca doğrula.
                </li>

                <li>
                    Sistemin açıklarını kötüye kullanma.
                </li>

            </ul>

        </section>


        <section class="info-card">

            <h2>
                Gizlilik
            </h2>

            <p>
                Hesap sistemi kullanıcı adı, parola özeti
                ve API anahtarı gibi hesap verilerini
                yönetmek için SQLite kullanır.
                Sohbet cevapları gerektiğinde sistemin
                hafıza mekanizmasında saklanabilir.
            </p>

        </section>


        <section class="info-card">

            <h2>
                Sorumluluk Reddi
            </h2>

            <p>
                Vantorium tarafından verilen cevaplar
                bilgilendirme amaçlıdır. Özellikle tıbbi,
                hukuki ve finansal konularda profesyonel
                doğrulama yapılmalıdır.
            </p>

        </section>


        <div class="footer">
            © 2026 Vantorium AI
        </div>

    </main>

    """

    return render_page(
        "Bilgi",
        content,
        user
    )


# =========================================================
# 18. EXTERNAL API
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
            "error": "word parametresi gerekli",
            "usage": "/api-key=...?word=kelime"
        }), 400


    conn = db()

    user = conn.execute(
        "SELECT * FROM users WHERE api_key = ?",
        (apikey,)
    ).fetchone()

    conn.close()


    if not user:

        return jsonify({
            "error": "Geçersiz API anahtarı"
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

            "time_ms": round(
                (time.time() - start) * 1000,
                2
            ),

            "engine": "Vantorium v5",

            "timestamp":
                datetime.now()
                .astimezone()
                .isoformat()

        }

    })


# =========================================================
# 19. RUN
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
        port=port,
        threaded=True
    )

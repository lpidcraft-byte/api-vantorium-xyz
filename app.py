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
import operator
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, Response, redirect, make_response, render_template_string

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

DB_FILE = "vantorium.db"
GOOGLE_CX = os.environ.get("GOOGLE_CX", "f79f63e39ec7f4c78")

# =========================================================
# DATABASE
# =========================================================

def db():
    conn = sqlite3.connect(DB_FILE, timeout=20)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            api_key TEXT UNIQUE NOT NULL,
            created_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS memory (
            word TEXT PRIMARY KEY,
            answer TEXT,
            confidence REAL,
            source TEXT,
            created_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def normalize(text):
    text = (text or "").lower().strip()
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"[?!.,;:]+$", "", text)
    return text

def memory_get(word):
    conn = db()
    row = conn.execute(
        "SELECT answer FROM memory WHERE word = ?", (word,)
    ).fetchone()
    conn.close()
    return row["answer"] if row else None

def memory_save(word, answer, confidence, source):
    conn = db()
    conn.execute("""
        INSERT OR REPLACE INTO memory
        (word, answer, confidence, source, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (word, answer, confidence, source, datetime.now().isoformat()))
    conn.commit()
    conn.close()

# =========================================================
# DATASET
# =========================================================

def load_dataset():
    files = [
        "ultra_soru_cevap_30_cevapli.txt",
        "ultra_soru_cevap_30_cevapli.txt.txt",
        "storage/ultra_soru_cevap_30_cevapli.txt",
        "storage/ultra_soru_cevap_30_cevapli.txt.txt",
    ]

    data = {}

    for filename in files:
        if not os.path.exists(filename):
            continue

        with open(filename, "r", encoding="utf-8") as f:
            current_q = None

            for raw in f:
                line = raw.strip()

                if not line or line.startswith("#"):
                    continue

                if line.startswith("Input:"):
                    current_q = normalize(
                        line.replace("Input:", "", 1).strip()
                    )
                    data.setdefault(current_q, [])

                elif line.startswith("Reply:") and current_q:
                    data[current_q].append(
                        line.replace("Reply:", "", 1).strip()
                    )

        break

    return data

DATASET = load_dataset()

# =========================================================
# QUERY INTELLIGENCE
# =========================================================

GREETING_RE = re.compile(
    r"^\s*(selam|selamün aleyküm|selamun aleykum|merhaba|"
    r"hello|hi|hey|günaydın|iyi akşamlar|iyi geceler|"
    r"naber|nbr|nasılsın|sa|s.a)\s*[!.?]*\s*$",
    re.I
)

DEFINITION_RE = re.compile(
    r"^\s*[\"“”']?(.+?)[\"“”']?\s+"
    r"(ne demek|ne anlama geliyor|anlamı ne|nedir|ne anlama gelir)"
    r"\s*[?.!]*\s*$",
    re.I
)

RESPONSE_RE = re.compile(
    r"(bana|biri bana|birisi bana|biri|birisi).{0,80}"
    r"(derse|dedi|söylerse|söyledi).{0,80}"
    r"(ne demeliyim|ne diyeyim|nasıl cevap vereyim|ne cevap vereyim)",
    re.I
)

def analyze_query(query):
    q = normalize(query)

    return {
        "is_greeting": bool(GREETING_RE.match(query or "")),
        "is_math": bool(
            re.fullmatch(r"[\d\s+\-*/().,%^]+", query or "")
            and re.search(r"[+\-*/%^]", query or "")
        ),
        "is_code": bool(re.search(
            r"\b(kod|python|php|javascript|js|html|css|api|"
            r"flask|discord|telegram|github|programlama|hata|error|debug)\b",
            q
        )),
        "is_definition": bool(DEFINITION_RE.match(query or "")),
        "is_response_advice": bool(RESPONSE_RE.search(query or "")),
    }

# =========================================================
# SAFE MATH
# =========================================================

OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
    ast.Mod: operator.mod,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}

def safe_math(expression):
    expression = expression.replace("^", "**").replace(",", ".")
    tree = ast.parse(expression, mode="eval")

    def calc(node):
        if isinstance(node, ast.Expression):
            return calc(node.body)

        if isinstance(node, ast.Constant) and isinstance(
            node.value, (int, float)
        ):
            if abs(node.value) > 10**12:
                raise ValueError
            return node.value

        if isinstance(node, ast.UnaryOp) and type(node.op) in OPS:
            return OPS[type(node.op)](calc(node.operand))

        if isinstance(node, ast.BinOp) and type(node.op) in OPS:
            left = calc(node.left)
            right = calc(node.right)

            if isinstance(node.op, ast.Pow) and abs(right) > 20:
                raise ValueError

            return OPS[type(node.op)](left, right)

        raise ValueError

    return calc(tree)

# =========================================================
# GOOGLE CSE SEARCH
# =========================================================

def cse_search(query, search_type="web", num=6):
    """
    Uses the Google Programmable Search Element endpoint.
    This does not use the Google Custom Search JSON API.
    Therefore no Google API key is needed here.
    """

    url = "https://cse.google.com/cse/element/v1"

    params = {
        "rsz": "filtered_cse",
        "num": min(max(num, 1), 10),
        "hl": "tr",
        "source": "gcsc",
        "cselibv": "8a5d5b6de8c9f12f",
        "cx": GOOGLE_CX,
        "q": query,
        "safe": "active",
        "exp": "csqr,cc",
        "callback": "vantoriumCallback",
    }

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Linux; Android 15) "
            "AppleWebKit/537.36 Chrome/131 Mobile Safari/537.36"
        ),
        "Accept": "application/javascript,text/javascript,*/*;q=0.8",
        "Accept-Language": "tr-TR,tr;q=0.9,en;q=0.6",
    }

    try:
        r = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=12
        )

        if r.status_code != 200:
            return []

        match = re.search(
            r"vantoriumCallback\((.*)\)\s*;?\s*$",
            r.text,
            re.S
        )

        if not match:
            return []

        data = json.loads(match.group(1))
        raw_results = data.get("results", [])

        results = []

        for item in raw_results:
            link = item.get("unescapedUrl") or item.get("url") or ""
            title = (
                item.get("titleNoFormatting")
                or item.get("title")
                or ""
            )
            snippet = (
                item.get("contentNoFormatting")
                or item.get("content")
                or ""
            )

            if not link:
                continue

            results.append({
                "title": html.unescape(title).strip(),
                "url": link,
                "snippet": re.sub(r"\s+", " ", html.unescape(snippet)).strip(),
                "source": "Google"
            })

        return results

    except Exception:
        return []

# =========================================================
# GOOGLE IMAGE SEARCH
# =========================================================

def cse_image_search(query, num=8):
    url = "https://cse.google.com/cse/element/v1"

    params = {
        "rsz": "filtered_cse",
        "num": min(max(num, 1), 10),
        "hl": "tr",
        "source": "gcsc",
        "cx": GOOGLE_CX,
        "q": query,
        "safe": "active",
        "searchType": "image",
        "callback": "vantoriumCallback",
    }

    headers = {
        "User-Agent": "Mozilla/5.0 Chrome/131 Safari/537.36"
    }

    try:
        r = requests.get(url, params=params, headers=headers, timeout=12)

        if r.status_code != 200:
            return []

        match = re.search(
            r"vantoriumCallback\((.*)\)\s*;?\s*$",
            r.text,
            re.S
        )

        if not match:
            return []

        data = json.loads(match.group(1))
        images = []

        for item in data.get("results", []):
            image = item.get("image", {})

            thumbnail = (
                image.get("thumbnailLink")
                or image.get("source")
                or ""
            )

            context = (
                image.get("contextLink")
                or item.get("unescapedUrl")
                or item.get("url")
                or ""
            )

            if thumbnail:
                images.append({
                    "title": html.unescape(
                        item.get("titleNoFormatting")
                        or item.get("title")
                        or query
                    ),
                    "thumbnail": thumbnail,
                    "url": context
                })

        return images

    except Exception:
        return []

# =========================================================
# WIKIPEDIA
# =========================================================

def wikipedia_search(query, num=4):
    try:
        url = "https://tr.wikipedia.org/w/api.php"

        params = {
            "action": "query",
            "list": "search",
            "srsearch": query,
            "utf8": 1,
            "format": "json",
            "srlimit": num,
        }

        r = requests.get(
            url,
            params=params,
            headers={"User-Agent": "VantoriumAI/5.0"},
            timeout=10
        )

        data = r.json()
        results = []

        for item in data.get("query", {}).get("search", []):
            title = item.get("title", "")
            snippet = re.sub(
                r"<[^>]+>",
                "",
                item.get("snippet", "")
            )

            results.append({
                "title": title,
                "url": (
                    "https://tr.wikipedia.org/wiki/"
                    + urllib.parse.quote(title.replace(" ", "_"))
                ),
                "snippet": snippet,
                "source": "Wikipedia",
            })

        return results

    except Exception:
        return []

# =========================================================
# GITHUB SEARCH
# =========================================================

def github_search(query, num=5):
    """
    GitHub repository search.
    For technical/code questions GitHub is prioritized.
    """

    try:
        url = "https://api.github.com/search/repositories"

        params = {
            "q": query,
            "sort": "stars",
            "order": "desc",
            "per_page": num,
        }

        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "VantoriumAI",
        }

        r = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=10
        )

        if r.status_code != 200:
            return []

        results = []

        for item in r.json().get("items", []):
            results.append({
                "title": item.get("full_name", ""),
                "url": item.get("html_url", ""),
                "snippet": (
                    item.get("description")
                    or "GitHub deposu."
                ),
                "source": "GitHub",
                "stars": item.get("stargazers_count", 0),
                "language": item.get("language") or "",
            })

        return results

    except Exception:
        return []

# =========================================================
# SEARCH RANKING
# =========================================================

def score_result(result, query):
    q = normalize(query)
    text = normalize(
        result.get("title", "") + " " + result.get("snippet", "")
    )

    score = 0

    if q and q in text:
        score += 10

    for word in q.split():
        if len(word) >= 3 and word in text:
            score += 2

    source = result.get("source", "").lower()

    if source == "wikipedia":
        score += 3

    if source == "github":
        score += 4

    if source == "google":
        score += 5

    score += min(len(result.get("snippet", "")) / 100, 2)

    return score

def unique_results(results):
    seen = set()
    clean = []

    for result in results:
        url = result.get("url", "").strip()

        if not url or url in seen:
            continue

        seen.add(url)
        clean.append(result)

    return clean

def best_results(results, query, limit=6):
    results = unique_results(results)

    for result in results:
        result["_score"] = score_result(result, query)

    results.sort(
        key=lambda x: x.get("_score", 0),
        reverse=True
    )

    return results[:limit]

# =========================================================
# SMART ANSWER
# =========================================================

def extract_target(query, parts):
    if parts["is_definition"]:
        match = DEFINITION_RE.match(query)
        if match:
            return match.group(1).strip(" \"“”'")

    if parts["is_response_advice"]:
        # Remove common Turkish instruction words.
        cleaned = re.sub(
            r"\b(bana|birisi|biri|dediğim|dediğim kelime|"
            r"derse|dedi|söylerse|söyledi|ne demeliyim|"
            r"ne diyeyim|nasıl cevap vereyim|ne cevap vereyim)\b",
            " ",
            query,
            flags=re.I
        )
        cleaned = re.sub(r"\s+", " ", cleaned).strip(" ?!.,")
        return cleaned

    return query

def make_search_query(query, parts):
    target = extract_target(query, parts)

    if parts["is_definition"]:
        return f'"{target}" ne demek anlamı'

    if parts["is_response_advice"]:
        return f'"{target}" ne demek nasıl cevap verilir'

    return target

def clean_snippet(text, max_len=420):
    text = re.sub(r"<[^>]+>", "", text or "")
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()

    if len(text) > max_len:
        return text[:max_len - 3].rstrip() + "..."

    return text

def synthesize_answer(query, results, parts):
    if not results:
        return None

    results = best_results(results, query, 6)

    target = extract_target(query, parts)

    # Definition: concise, direct answer.
    if parts["is_definition"]:
        for result in results:
            snippet = clean_snippet(result.get("snippet", ""), 500)
            if snippet:
                return (
                    f"{target} şu anlama gelir: {snippet}\n\n"
                    f"Kaynak: {result.get('url', '')}"
                )

    # "Biri bana X derse ne demeliyim?"
    if parts["is_response_advice"]:
        for result in results:
            snippet = clean_snippet(result.get("snippet", ""), 350)

            if snippet:
                return (
                    f"{target} ifadesine vereceğin cevap, "
                    f"bağlama göre değişir. İnternetteki en uygun "
                    f"bilgiye göre: {snippet}\n\n"
                    f"Kaynak: {result.get('url', '')}"
                )

    # Normal search: one good result, not a dump.
    first = results[0]
    snippet = clean_snippet(first.get("snippet", ""), 550)

    if snippet:
        return (
            f"{snippet}\n\n"
            f"Kaynak: {first.get('url', '')}"
        )

    return f"İlgili sonuç: {first.get('url', '')}"

def search_everywhere(query, parts=None):
    if parts is None:
        parts = analyze_query(query)

    search_query = make_search_query(query, parts)

    google_results = cse_search(search_query, "web", 6)

    github_results = []
    if parts["is_code"]:
        github_results = github_search(search_query, 5)

    wiki_results = wikipedia_search(search_query, 3)

    all_results = (
        google_results
        + github_results
        + wiki_results
    )

    return best_results(all_results, search_query, 8)

def get_answer(query):
    query = (query or "").strip()

    if not query:
        return "Bir şeyler yaz, birlikte bakalım.", "sistem"

    parts = analyze_query(query)

    # Greeting must NOT trigger search.
    if parts["is_greeting"]:
        return random.choice([
            "Selam! 👋 Ben Vantorium. Ne arıyoruz?",
            "Merhaba! Hazırım. Sorunu yaz, araştırıp en uygun cevabı vereyim.",
            "Selam kral 😎 Ne hakkında araştırma yapalım?"
        ]), "selamlama"

    if parts["is_math"]:
        try:
            result = safe_math(query)
            return f"Sonuç: {result}", "matematik"
        except Exception:
            return "Bu matematik ifadesini güvenli şekilde çözemedim.", "hata"

    normalized = normalize(query)

    if normalized in DATASET and DATASET[normalized]:
        return random.choice(DATASET[normalized]), "veri_seti"

    cached = memory_get(normalized)
    if cached:
        return cached, "hafiza"

    results = search_everywhere(query, parts)

    if results:
        answer = synthesize_answer(query, results, parts)

        if answer:
            memory_save(normalized, answer, 0.86, "web")
            return answer, "web"

    return (
        "Aradım ama güvenilir ve yeterli bir sonuç bulamadım. "
        "İstersen soruyu biraz daha açık yaz.",
        "bulunamadi"
    )

# =========================================================
# AUTH
# =========================================================

def get_current_user():
    token = request.cookies.get("session_token")

    if not token:
        return None

    conn = db()

    row = conn.execute("""
        SELECT u.*
        FROM users u
        JOIN sessions s ON u.id = s.user_id
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
# UI
# =========================================================

BASE_STYLE = """
<style>
:root{
  --bg:#07090d;
  --panel:#0d1117;
  --panel2:#111821;
  --line:rgba(255,255,255,.08);
  --muted:#8b96a7;
  --text:#f5f7fa;
  --green:#16d39a;
  --green2:#0bbf89;
  --danger:#ff5c70;
  --shadow:0 20px 70px rgba(0,0,0,.38);
}

*{box-sizing:border-box;margin:0;padding:0}

html{scroll-behavior:smooth}

body{
  font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  background:
    radial-gradient(circle at 50% -20%,rgba(22,211,154,.11),transparent 32%),
    var(--bg);
  color:var(--text);
  min-height:100vh;
  -webkit-font-smoothing:antialiased;
}

a{color:inherit;text-decoration:none}

button,input{font:inherit}

.navbar{
  height:68px;
  padding:0 22px;
  display:flex;
  align-items:center;
  justify-content:space-between;
  position:sticky;
  top:0;
  z-index:100;
  background:rgba(7,9,13,.76);
  backdrop-filter:blur(18px);
  border-bottom:1px solid var(--line);
}

.logo{
  display:flex;
  align-items:center;
  gap:11px;
  font-weight:800;
  font-size:18px;
  letter-spacing:-.5px;
}

.logo-icon{
  width:36px;
  height:36px;
  border-radius:12px;
  display:grid;
  place-items:center;
  background:linear-gradient(135deg,#20e4aa,#08a97b);
  box-shadow:0 8px 28px rgba(22,211,154,.2);
  font-weight:900;
}

.nav-actions{
  display:flex;
  gap:4px;
  align-items:center;
}

.btn-nav{
  padding:9px 13px;
  color:#aeb7c5;
  border-radius:10px;
  font-size:14px;
  font-weight:650;
  transition:.18s;
}

.btn-nav:hover{
  color:#fff;
  background:rgba(255,255,255,.06);
}

.btn-nav.primary{
  background:var(--green);
  color:#03130e;
  box-shadow:0 8px 25px rgba(22,211,154,.15);
}

.container{
  width:min(430px,calc(100% - 28px));
  margin:auto;
  padding:32px;
  background:linear-gradient(180deg,rgba(17,24,33,.94),rgba(11,15,21,.96));
  border:1px solid var(--line);
  border-radius:22px;
  box-shadow:var(--shadow);
}

.container.wide{
  width:min(980px,calc(100% - 28px));
  margin:38px auto;
}

.auth-wrapper{
  min-height:calc(100vh - 68px);
  display:grid;
  place-items:center;
  padding:25px 0;
}

h1.page-title{
  font-size:32px;
  letter-spacing:-1px;
  margin-bottom:8px;
}

h2{
  font-size:25px;
  margin-bottom:7px;
}

.subtitle{
  color:var(--muted);
  line-height:1.6;
  font-size:14px;
  margin-bottom:25px;
}

label{
  display:block;
  color:#cbd2dc;
  font-size:13px;
  font-weight:650;
  margin-bottom:7px;
}

input[type=text],
input[type=password]{
  width:100%;
  padding:13px 14px;
  margin-bottom:17px;
  border:1px solid rgba(255,255,255,.09);
  border-radius:12px;
  background:#080b10;
  color:#fff;
  outline:none;
  transition:.18s;
}

input:focus{
  border-color:rgba(22,211,154,.7);
  box-shadow:0 0 0 4px rgba(22,211,154,.09);
}

.btn{
  width:100%;
  padding:13px 15px;
  border:0;
  border-radius:12px;
  background:linear-gradient(135deg,#1ce0a5,#0dbd89);
  color:#03130e;
  font-weight:800;
  cursor:pointer;
  transition:.18s;
}

.btn:hover{
  transform:translateY(-1px);
  filter:brightness(1.05);
}

.btn-small{
  width:auto;
  padding:10px 15px;
  font-size:13px;
}

.btn.danger{
  background:#ef4c61;
  color:white;
}

.btn.secondary{
  background:#1b222c;
  color:#fff;
}

.link-row{
  text-align:center;
  margin-top:21px;
  color:#818b99;
  font-size:14px;
}

.link-row a{color:var(--green)}

.error{
  padding:12px;
  border-radius:12px;
  background:rgba(255,92,112,.09);
  border:1px solid rgba(255,92,112,.2);
  color:#ff8b99;
  margin-bottom:18px;
  font-size:13px;
}

.card{
  padding:25px;
  margin-bottom:18px;
  background:linear-gradient(180deg,#0e141c,#0b1016);
  border:1px solid var(--line);
  border-radius:18px;
}

.card h3{
  display:flex;
  gap:9px;
  align-items:center;
  margin-bottom:14px;
  font-size:16px;
}

.card p{
  color:#a8b1be;
  line-height:1.75;
  font-size:14px;
  margin-bottom:12px;
}

.code-block,
.api-key-box{
  background:#070a0f;
  border:1px solid var(--line);
  border-radius:12px;
  padding:15px;
  overflow:auto;
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
  font-size:12px;
  line-height:1.7;
}

.api-key-box{
  color:var(--green);
  word-break:break-all;
}

.section-title{
  margin:34px 0 14px;
  font-size:18px;
}

.card ul{
  list-style:none;
}

.card li{
  padding:11px 0;
  border-bottom:1px solid var(--line);
  color:#a8b1be;
  line-height:1.6;
  font-size:14px;
}

.card li:last-child{border-bottom:0}

.card li:before{
  content:"✓";
  color:var(--green);
  margin-right:9px;
  font-weight:800;
}

.footer{
  color:#5d6775;
  text-align:center;
  padding:35px 15px;
  font-size:12px;
}

/* CHAT */

.chat-shell{
  height:calc(100vh - 68px);
  display:flex;
  flex-direction:column;
}

.chat-history{
  flex:1;
  overflow-y:auto;
  padding:30px 16px 24px;
  width:min(920px,100%);
  margin:auto;
}

.chat-row{
  display:flex;
  gap:12px;
  max-width:860px;
  margin:0 auto 28px;
  align-items:flex-start;
}

.chat-row.user{
  flex-direction:row-reverse;
}

.avatar{
  flex:0 0 38px;
  width:38px;
  height:38px;
  border-radius:13px;
  display:grid;
  place-items:center;
  font-size:13px;
  font-weight:900;
  background:#1a222d;
}

.chat-row.ai .avatar{
  background:linear-gradient(135deg,#1ce0a5,#09ae7e);
  color:#03130e;
  box-shadow:0 8px 24px rgba(22,211,154,.15);
}

.bubble{
  max-width:calc(100% - 50px);
  line-height:1.75;
  font-size:15px;
  color:#e9edf2;
  white-space:pre-wrap;
}

.chat-row.user .bubble{
  background:#151c25;
  border:1px solid rgba(255,255,255,.05);
  padding:11px 15px;
  border-radius:17px 5px 17px 17px;
}

.chat-row.ai .bubble{
  padding-top:2px;
}

.thinking{
  display:flex;
  align-items:center;
  gap:9px;
  color:#8e99a8;
  font-size:13px;
}

.thinking-dot{
  width:7px;
  height:7px;
  border-radius:50%;
  background:var(--green);
  box-shadow:0 0 16px rgba(22,211,154,.5);
  animation:pulse 1s infinite;
}

@keyframes pulse{
  0%,100%{opacity:.25;transform:scale(.8)}
  50%{opacity:1;transform:scale(1)}
}

.status-line{
  color:#8c98a8;
  font-size:12px;
  margin-top:7px;
}

.chat-composer{
  width:min(920px,100%);
  margin:auto;
  padding:10px 16px 24px;
}

.composer{
  position:relative;
  background:rgba(14,20,28,.95);
  border:1px solid rgba(255,255,255,.1);
  border-radius:18px;
  box-shadow:0 18px 60px rgba(0,0,0,.4);
  padding:7px;
}

.composer input{
  width:100%;
  padding:14px 55px 14px 15px;
  border:0;
  outline:0;
  background:transparent;
  color:white;
}

.send-btn{
  position:absolute;
  right:7px;
  top:7px;
  width:43px;
  height:43px;
  border:0;
  border-radius:13px;
  background:var(--green);
  color:#03130e;
  display:grid;
  place-items:center;
  cursor:pointer;
}

.send-btn:disabled{
  opacity:.45;
  cursor:not-allowed;
}

/* SEARCH */

.search-page{
  width:min(1050px,calc(100% - 28px));
  margin:45px auto;
}

.search-hero{
  text-align:center;
  margin-bottom:28px;
}

.search-hero h1{
  font-size:42px;
  letter-spacing:-1.5px;
  margin-bottom:10px;
}

.search-hero p{
  color:#8792a1;
}

.search-box{
  position:relative;
  max-width:800px;
  margin:24px auto;
}

.search-box input{
  margin:0;
  padding:17px 60px 17px 18px;
  border-radius:16px;
  background:#0d141c;
}

.search-box button{
  position:absolute;
  right:7px;
  top:7px;
  height:44px;
  padding:0 17px;
  border:0;
  border-radius:12px;
  background:var(--green);
  color:#03130e;
  font-weight:800;
}

.result{
  padding:19px;
  border:1px solid var(--line);
  border-radius:16px;
  background:#0c1219;
  margin-bottom:12px;
}

.result h3{
  color:#f4f7fa;
  font-size:15px;
  margin-bottom:6px;
}

.result .source{
  color:var(--green);
  font-size:11px;
  font-weight:800;
  text-transform:uppercase;
  margin-bottom:7px;
}

.result p{
  color:#9da8b6;
  font-size:13px;
  line-height:1.65;
}

.result a{
  display:inline-block;
  margin-top:9px;
  color:#7ee9c6;
  font-size:12px;
  word-break:break-all;
}

.image-grid{
  display:grid;
  grid-template-columns:repeat(auto-fill,minmax(150px,1fr));
  gap:12px;
}

.image-card{
  overflow:hidden;
  border-radius:14px;
  border:1px solid var(--line);
  background:#0d1218;
}

.image-card img{
  width:100%;
  height:145px;
  display:block;
  object-fit:cover;
}

.image-card div{
  padding:9px;
  font-size:11px;
  color:#a8b1be;
}

.mobile-menu{
  display:none;
}

@media(max-width:720px){
  .navbar{
    height:62px;
    padding:0 12px;
  }

  .nav-actions{
    gap:0;
  }

  .btn-nav{
    padding:8px 7px;
    font-size:12px;
  }

  .logo{
    font-size:15px;
  }

  .logo-icon{
    width:32px;
    height:32px;
  }

  .chat-shell{
    height:calc(100vh - 62px);
  }

  .chat-history{
    padding:22px 10px 18px;
  }

  .bubble{
    font-size:14px;
  }

  .avatar{
    width:34px;
    height:34px;
    flex-basis:34px;
  }

  .search-hero h1{
    font-size:31px;
  }
}

/* LOGIN / REGISTER POLICY MODAL */

.policy-overlay{
  position:fixed;
  inset:0;
  z-index:1000;
  display:grid;
  place-items:center;
  padding:20px;
  background:rgba(0,0,0,.62);
  backdrop-filter:blur(12px);
}

.policy-modal{
  width:min(520px,100%);
  max-height:min(720px,88vh);
  overflow:auto;
  padding:27px;
  border-radius:24px;
  background:linear-gradient(180deg,#121923,#0c1118);
  border:1px solid rgba(255,255,255,.1);
  box-shadow:0 30px 100px rgba(0,0,0,.6);
}

.policy-icon{
  width:48px;
  height:48px;
  border-radius:15px;
  display:grid;
  place-items:center;
  background:rgba(22,211,154,.12);
  color:var(--green);
  margin-bottom:14px;
  font-weight:900;
}

.policy-modal h3{
  font-size:21px;
  margin-bottom:7px;
}

.policy-modal p{
  color:#98a4b3;
  font-size:13px;
  line-height:1.7;
}

.policy-list{
  margin:17px 0;
  display:grid;
  gap:9px;
}

.policy-item{
  padding:11px 12px;
  border-radius:12px;
  background:rgba(255,255,255,.035);
  color:#cbd2dc;
  font-size:13px;
}

.policy-buttons{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:10px;
  margin-top:18px;
}

.policy-buttons a{
  padding:12px;
  border-radius:12px;
  text-align:center;
  background:#1a222d;
  font-size:13px;
  font-weight:750;
}

.policy-buttons a.primary{
  background:var(--green);
  color:#03130e;
}

.close-policy{
  display:block;
  text-align:center;
  margin-top:13px;
  color:#6f7a89;
  font-size:12px;
  cursor:pointer;
}
</style>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
"""

def policy_modal():
    return """
    <div class="policy-overlay" id="policyOverlay">
      <div class="policy-modal">
        <div class="policy-icon">V</div>
        <h3>Vantorium'a hoş geldin</h3>
        <p>
          Devam etmeden önce Vantorium kullanım kurallarını ve
          gizlilik politikasını inceleyebilirsin.
        </p>

        <div class="policy-list">
          <div class="policy-item">✓ API anahtarını kimseyle paylaşma.</div>
          <div class="policy-item">✓ Sistemi kötüye kullanma veya aşırı istek gönderme.</div>
          <div class="policy-item">✓ Zararlı, yasa dışı veya saldırı amaçlı kullanım yasaktır.</div>
          <div class="policy-item">✓ Web sonuçları her zaman doğrulanmalıdır.</div>
          <div class="policy-item">✓ Hizmet zaman zaman güncellenebilir veya bakım nedeniyle durabilir.</div>
        </div>

        <div class="policy-buttons">
          <a href="https://api-vantorium-xyz-production.up.railway.app/info">
            Kurallar & Politikalar
          </a>
          <a href="#" class="primary" onclick="closePolicy();return false;">
            Devam Et
          </a>
        </div>

        <span class="close-policy" onclick="closePolicy()">Şimdi kapat</span>
      </div>
    </div>

    <script>
      function closePolicy(){
        const el=document.getElementById("policyOverlay");
        if(el) el.remove();
        try{localStorage.setItem("vantorium_policy_seen","1")}catch(e){}
      }

      // Her giriş/kayıt ekranında bir kez göster.
      try{
        if(localStorage.getItem("vantorium_policy_seen")==="1"){
          const el=document.getElementById("policyOverlay");
          if(el) el.remove();
        }
      }catch(e){}
    </script>
    """

def render_page(title, content, user=None, show_nav=True, modal=False):
    if show_nav:
        if user:
            actions = """
              <a href="/chat" class="btn-nav">Sohbet</a>
              <a href="/search" class="btn-nav">Arama</a>
              <a href="/dashboard" class="btn-nav">Dashboard</a>
              <a href="/info" class="btn-nav">Bilgi</a>
              <a href="/logout" class="btn-nav">Çıkış</a>
            """
        else:
            actions = """
              <a href="/info" class="btn-nav">Bilgi</a>
              <a href="/login" class="btn-nav">Giriş</a>
              <a href="/register" class="btn-nav primary">Kayıt Ol</a>
            """

        nav = f"""
        <header class="navbar">
          <a href="/" class="logo">
            <span class="logo-icon">V</span>
            Vantorium
          </a>
          <nav class="nav-actions">{actions}</nav>
        </header>
        """
    else:
        nav = ""

    modal_html = policy_modal() if modal else ""

    return f"""
    <!doctype html>
    <html lang="tr">
    <head>
      <meta charset="utf-8">
      <meta name="viewport"
            content="width=device-width,initial-scale=1,viewport-fit=cover">
      <meta name="theme-color" content="#07090d">
      <title>{html.escape(title)} | Vantorium</title>
      {BASE_STYLE}
    </head>
    <body>
      {nav}
      {content}
      {modal_html}
    </body>
    </html>
    """

# =========================================================
# ROUTES
# =========================================================

@app.route("/")
def index():
    if get_current_user():
        return redirect("/chat")
    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if get_current_user():
        return redirect("/chat")

    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3 or len(username) > 32:
            error = "Kullanıcı adı 3-32 karakter arasında olmalı."
        elif len(password) < 6:
            error = "Şifre en az 6 karakter olmalı."
        else:
            conn = db()

            exists = conn.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,)
            ).fetchone()

            if exists:
                error = "Bu kullanıcı adı zaten alınmış."
                conn.close()
            else:
                api_key = "vnt_" + secrets.token_hex(24)

                conn.execute("""
                    INSERT INTO users
                    (username,password_hash,api_key,created_at)
                    VALUES (?,?,?,?)
                """, (
                    username,
                    hash_password(password),
                    api_key,
                    datetime.now().isoformat()
                ))

                conn.commit()
                conn.close()

                return redirect("/login?registered=1")

    content = f"""
    <main class="auth-wrapper">
      <section class="container">
        <h2>Hesap oluştur</h2>
        <p class="subtitle">
          Vantorium hesabını oluştur ve kendi API anahtarını al.
        </p>

        {f'<div class="error">{html.escape(error)}</div>' if error else ''}

        <form method="POST">
          <label>Kullanıcı adı</label>
          <input
            type="text"
            name="username"
            minlength="3"
            maxlength="32"
            autocomplete="username"
            placeholder="kullanici_adi"
            required
          >

          <label>Şifre</label>
          <input
            type="password"
            name="password"
            minlength="6"
            autocomplete="new-password"
            placeholder="••••••••"
            required
          >

          <button class="btn" type="submit">Hesap oluştur</button>
        </form>

        <div class="link-row">
          Zaten hesabın var mı?
          <a href="/login">Giriş yap</a>
        </div>
      </section>
    </main>
    """

    return render_page("Kayıt", content, modal=True)

@app.route("/login", methods=["GET", "POST"])
def login():
    if get_current_user():
        return redirect("/chat")

    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = db()

        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if user and user["password_hash"] == hash_password(password):
            token = secrets.token_hex(32)

            conn.execute("""
                INSERT INTO sessions(token,user_id,created_at)
                VALUES (?,?,?)
            """, (
                token,
                user["id"],
                datetime.now().isoformat()
            ))

            conn.commit()
            conn.close()

            response = make_response(redirect("/chat"))
            response.set_cookie(
                "session_token",
                token,
                httponly=True,
                samesite="Lax",
                max_age=30 * 24 * 3600
            )
            return response

        conn.close()
        error = "Kullanıcı adı veya şifre hatalı."

    content = f"""
    <main class="auth-wrapper">
      <section class="container">
        <h2>Tekrar hoş geldin</h2>
        <p class="subtitle">
          Vantorium'a giriş yap ve araştırmaya devam et.
        </p>

        {f'<div class="error">{html.escape(error)}</div>' if error else ''}

        <form method="POST">
          <label>Kullanıcı adı</label>
          <input
            type="text"
            name="username"
            autocomplete="username"
            placeholder="kullanici_adi"
            required
          >

          <label>Şifre</label>
          <input
            type="password"
            name="password"
            autocomplete="current-password"
            placeholder="••••••••"
            required
          >

          <button class="btn" type="submit">Giriş yap</button>
        </form>

        <div class="link-row">
          Hesabın yok mu?
          <a href="/register">Kayıt ol</a>
        </div>
      </section>
    </main>
    """

    return render_page("Giriş", content, modal=True)

@app.route("/logout")
def logout():
    token = request.cookies.get("session_token")

    if token:
        conn = db()
        conn.execute(
            "DELETE FROM sessions WHERE token = ?",
            (token,)
        )
        conn.commit()
        conn.close()

    response = make_response(redirect("/login"))
    response.delete_cookie("session_token")
    return response

# =========================================================
# CHAT
# =========================================================

@app.route("/chat")
@login_required
def chat():
    user = get_current_user()

    content = """
    <main class="chat-shell">
      <div class="chat-history" id="chatHistory">

        <div class="chat-row ai">
          <div class="avatar">V</div>
          <div class="bubble">
            Merhaba! 👋 Ben Vantorium.
            Web'de araştırabilir, kelimelerin anlamını bulabilir,
            teknik sorularda GitHub'a bakabilir ve en uygun kısa cevabı
            hazırlayabilirim.
          </div>
        </div>

      </div>

      <div class="chat-composer">
        <div class="composer">
          <input
            id="chatInput"
            type="text"
            autocomplete="off"
            placeholder="Vantorium'a bir şey sor..."
          >
          <button class="send-btn" id="sendBtn" onclick="sendChat()">
            <svg width="19" height="19" viewBox="0 0 24 24"
                 fill="none" stroke="currentColor"
                 stroke-width="2.4" stroke-linecap="round"
                 stroke-linejoin="round">
              <path d="M12 19V5"></path>
              <path d="M5 12l7-7 7 7"></path>
            </svg>
          </button>
        </div>
      </div>
    </main>

    <script>
    const historyEl=document.getElementById("chatHistory");
    const input=document.getElementById("chatInput");
    const sendBtn=document.getElementById("sendBtn");

    input.focus();

    input.addEventListener("keydown",(e)=>{
      if(e.key==="Enter" && !e.shiftKey){
        e.preventDefault();
        sendChat();
      }
    });

    function esc(text){
      const d=document.createElement("div");
      d.textContent=text;
      return d.innerHTML;
    }

    function addMessage(text,type){
      const row=document.createElement("div");
      row.className="chat-row "+type;

      const avatar=document.createElement("div");
      avatar.className="avatar";
      avatar.textContent=type==="user"?"K":"V";

      const bubble=document.createElement("div");
      bubble.className="bubble";
      bubble.textContent=text;

      row.appendChild(avatar);
      row.appendChild(bubble);
      historyEl.appendChild(row);
      historyEl.scrollTop=historyEl.scrollHeight;

      return bubble;
    }

    function addThinking(){
      const row=document.createElement("div");
      row.className="chat-row ai";
      row.id="thinkingRow";

      row.innerHTML=`
        <div class="avatar">V</div>
        <div class="bubble">
          <div class="thinking">
            <span class="thinking-dot"></span>
            <span id="thinkingText">Düşünüyor...</span>
          </div>
          <div class="status-line" id="thinkingSub">
            Sorunu analiz ediyor
          </div>
        </div>
      `;

      historyEl.appendChild(row);
      historyEl.scrollTop=historyEl.scrollHeight;
      return row;
    }

    function setThinking(main,sub){
      const a=document.getElementById("thinkingText");
      const b=document.getElementById("thinkingSub");

      if(a) a.textContent=main;
      if(b) b.textContent=sub;
    }

    function removeThinking(){
      const row=document.getElementById("thinkingRow");
      if(row) row.remove();
    }

    async function sendChat(){
      const text=input.value.trim();

      if(!text || sendBtn.disabled) return;

      input.value="";
      sendBtn.disabled=true;

      addMessage(text,"user");

      const thinking=addThinking();

      const stages=[
        ["Düşünüyor...","Sorunun ne istediğini belirliyor"],
        ["Web'de arıyor...","Google sonuçlarını tarıyor"],
        ["Kaynakları inceliyor...","En alakalı bilgileri karşılaştırıyor"],
        ["GitHub'da kod arıyor...","Teknik sonuçları kontrol ediyor"],
        ["En uygun cevabı hazırlıyor...","Gereksiz bilgileri eliyor"]
      ];

      let stage=0;

      const timer=setInterval(()=>{
        stage=Math.min(stage+1,stages.length-1);
        setThinking(stages[stage][0],stages[stage][1]);
      },850);

      try{
        const response=await fetch("/api/chat",{
          method:"POST",
          headers:{"Content-Type":"application/json"},
          body:JSON.stringify({message:text})
        });

        clearInterval(timer);

        if(!response.ok){
          throw new Error("HTTP "+response.status);
        }

        const data=await response.json();

        removeThinking();

        const bubble=addMessage(data.answer || "Cevap alınamadı.","ai");

        // Basit markdown görünümü.
        bubble.innerHTML=esc(data.answer || "")
          .replace(/\\*\\*(.*?)\\*\\*/g,"<strong>$1</strong>")
          .replace(/\\n/g,"<br>");

        historyEl.scrollTop=historyEl.scrollHeight;

      }catch(error){
        clearInterval(timer);
        removeThinking();
        addMessage(
          "Bağlantı sırasında bir hata oluştu. Birkaç saniye sonra tekrar dene.",
          "ai"
        );
      }finally{
        sendBtn.disabled=false;
        input.focus();
      }
    }
    </script>
    """

    return render_page("Sohbet", content, user)

@app.route("/api/chat", methods=["POST"])
@login_required
def api_chat():
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip()

    if not message:
        return jsonify({
            "answer": "Bir mesaj yazmalısın.",
            "source": "sistem"
        }), 400

    answer, source = get_answer(message)

    return jsonify({
        "answer": answer,
        "source": source
    })

# =========================================================
# SEARCH ENGINE
# =========================================================

@app.route("/search")
@login_required
def search_page():
    user = get_current_user()

    content = """
    <main class="search-page">
      <section class="search-hero">
        <h1>Vantorium Arama</h1>
        <p>Web, Wikipedia, GitHub ve görseller üzerinde ara.</p>

        <form class="search-box" onsubmit="doSearch(event)">
          <input
            id="searchInput"
            type="text"
            placeholder="Ne aramak istiyorsun?"
            autocomplete="off"
          >
          <button type="submit">Ara</button>
        </form>
      </section>

      <section id="results"></section>
    </main>

    <script>
    async function doSearch(e){
      e.preventDefault();

      const q=document.getElementById("searchInput").value.trim();
      const box=document.getElementById("results");

      if(!q) return;

      box.innerHTML=`
        <div class="card">
          <div class="thinking">
            <span class="thinking-dot"></span>
            <span>Web'de aranıyor...</span>
          </div>
        </div>
      `;

      try{
        const r=await fetch("/api/search?q="+encodeURIComponent(q));
        const data=await r.json();

        let html="";

        if(data.answer){
          html+=`
            <div class="card">
              <h3>Vantorium'un özeti</h3>
              <p>${escapeHtml(data.answer).replace(/\\n/g,"<br>")}</p>
            </div>
          `;
        }

        if(data.images && data.images.length){
          html+=`
            <div class="card">
              <h3>Görseller</h3>
              <div class="image-grid">
                ${data.images.map(x=>`
                  <a class="image-card" href="${escapeAttr(x.url)}" target="_blank" rel="noopener">
                    <img src="${escapeAttr(x.thumbnail)}" loading="lazy">
                    <div>${escapeHtml(x.title)}</div>
                  </a>
                `).join("")}
              </div>
            </div>
          `;
        }

        if(data.results && data.results.length){
          html+=`<div class="card"><h3>Kaynaklar</h3>`;

          data.results.forEach(x=>{
            html+=`
              <article class="result">
                <div class="source">${escapeHtml(x.source || "WEB")}</div>
                <h3>${escapeHtml(x.title || "Sonuç")}</h3>
                <p>${escapeHtml(x.snippet || "")}</p>
                <a href="${escapeAttr(x.url)}" target="_blank" rel="noopener">
                  ${escapeHtml(x.url)}
                </a>
              </article>
            `;
          });

          html+=`</div>`;
        }

        if(!html){
          html=`<div class="card"><p>Sonuç bulunamadı.</p></div>`;
        }

        box.innerHTML=html;

      }catch(err){
        box.innerHTML=`
          <div class="error">
            Arama sırasında bir hata oluştu.
          </div>
        `;
      }
    }

    function escapeHtml(v){
      const d=document.createElement("div");
      d.textContent=v ?? "";
      return d.innerHTML;
    }

    function escapeAttr(v){
      return String(v ?? "").replace(/"/g,"&quot;");
    }
    </script>
    """

    return render_page("Arama", content, user)

@app.route("/api/search")
@login_required
def api_search():
    q = request.args.get("q", "").strip()

    if not q:
        return jsonify({
            "error": "q parametresi gerekli"
        }), 400

    parts = analyze_query(q)
    results = search_everywhere(q, parts)
    images = cse_image_search(extract_target(q, parts), 8)
    answer = synthesize_answer(q, results, parts)

    return jsonify({
        "query": q,
        "answer": answer,
        "results": results,
        "images": images
    })

# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()
    base = request.host_url.rstrip("/")
    example = (
        f"{base}/api-key={user['api_key']}"
        "?word=merhaba"
    )

    content = f"""
    <main class="container wide">
      <h1 class="page-title">Dashboard</h1>
      <p class="subtitle">
        Hoş geldin, <strong>{html.escape(user["username"])}</strong>.
        API anahtarını buradan yönetebilirsin.
      </p>

      <div class="card">
        <h3>🔑 API anahtarın</h3>

        <div class="api-key-box">
          {html.escape(user["api_key"])}
        </div>

        <p>
          Bu anahtarı gizli tut. Sızarsa aşağıdaki butondan yenileyebilirsin.
        </p>

        <form method="POST" action="/regenerate-key">
          <button class="btn danger btn-small" type="submit">
            Anahtarı yenile
          </button>
        </form>
      </div>

      <div class="card">
        <h3>⚡ API kullanımı</h3>
        <p>GET isteği gönder:</p>
        <div class="code-block">{html.escape(example)}</div>
      </div>
    </main>
    """

    return render_page("Dashboard", content, user)

@app.route("/regenerate-key", methods=["POST"])
@login_required
def regenerate_key():
    user = get_current_user()
    new_key = "vnt_" + secrets.token_hex(24)

    conn = db()
    conn.execute(
        "UPDATE users SET api_key = ? WHERE id = ?",
        (new_key, user["id"])
    )
    conn.commit()
    conn.close()

    return redirect("/dashboard")

# =========================================================
# INFO
# =========================================================

@app.route("/info")
def info():
    user = get_current_user()
    base = request.host_url.rstrip("/")

    content = f"""
    <main class="container wide">
      <h1 class="page-title">Bilgi Merkezi</h1>
      <p class="subtitle">
        Vantorium kullanım kuralları, API ve gizlilik bilgileri.
      </p>

      <div class="card">
        <h3>Vantorium nedir?</h3>
        <p>
          Vantorium; yerel bilgi tabanı, web araması, Wikipedia ve
          teknik sorularda GitHub sonuçlarını kullanarak kısa ve
          anlaşılır cevaplar hazırlayan bir asistandır.
        </p>
      </div>

      <h2 class="section-title">API</h2>

      <div class="card">
        <p>API kullanım örneği:</p>
        <div class="code-block">
          {html.escape(base)}/api-key=SENIN_ANAHTARIN?word=merhaba
        </div>
      </div>

      <h2 class="section-title">Kurallar</h2>

      <div class="card">
        <ul>
          <li>API anahtarını başkalarıyla paylaşma.</li>
          <li>DDoS, SQL Injection, XSS veya benzeri saldırılar yapma.</li>
          <li>Yasa dışı faaliyetlerde kullanma.</li>
          <li>Aşırı otomatik isteklerle sistemi zorlamama.</li>
          <li>Web sonuçlarını kritik kararlar öncesinde doğrula.</li>
          <li>Hizmet zaman zaman bakım veya güncelleme nedeniyle değişebilir.</li>
        </ul>
      </div>

      <h2 class="section-title">Gizlilik</h2>

      <div class="card">
        <p>
          Hesap işlemleri için kullanıcı adı, şifre özeti ve API anahtarı
          tutulur. Arama sonuçları üçüncü taraf kaynaklardan gelir.
          Hassas bilgilerini sohbetlere göndermemen önerilir.
        </p>
      </div>

      <div class="footer">
        © 2026 Vantorium AI
      </div>
    </main>
    """

    return render_page("Bilgi", content, user)

# =========================================================
# EXTERNAL API
# =========================================================

@app.route("/api-key=<apikey>", methods=["GET"])
def api_word(apikey):
    word = request.args.get("word", "").strip()

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

    answer, source = get_answer(word)

    return jsonify({
        "input": word,
        "answer": answer,
        "meta": {
            "source": source,
            "time_ms": round(
                (time.time() - start) * 1000,
                2
            ),
            "engine": "Vantorium v5.0",
            "timestamp": datetime.now().astimezone().isoformat()
        }
    })

# =========================================================
# START
# =========================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )

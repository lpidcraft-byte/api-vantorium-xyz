import os
import re
import json
import ast
import html
import math
import time
import random
import socket
import hashlib
import logging
import secrets
import sqlite3
import operator
import tempfile
import ipaddress
import requests
import urllib.parse
from datetime import datetime, timedelta
from functools import wraps
from contextlib import contextmanager
from collections import Counter, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, wait
from threading import Lock
from werkzeug.security import generate_password_hash, check_password_hash
from flask import (
    Flask, request, jsonify, Response, redirect, make_response, session,
    send_from_directory, stream_with_context,
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)

# Railway / proxy arkasında doğru IP ve https algısı için (Variables: TRUST_PROXY=1)
if os.environ.get("TRUST_PROXY", "").lower() == "1":
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# =========================================================
# DATABASE — Kalıcı ve güvenilir SQLite
# =========================================================

def _resolve_db_path():
    """
    Railway / Docker / yerel ortamda kalıcı DB yolu seçer.
    Öncelik:
      1. DB_PATH ortam değişkeni
      2. /data/vantorium.db  (volume mount için)
      3. uygulamanın yanındaki data/ klasörü
    """
    env_path = os.environ.get("DB_PATH", "").strip()
    if env_path:
        return env_path

    for candidate in ("/data/vantorium.db", "/app/data/vantorium.db"):
        parent = os.path.dirname(candidate)
        if os.path.isdir(parent) or os.access(os.path.dirname(parent) or "/", os.W_OK):
            try:
                os.makedirs(parent, exist_ok=True)
                return candidate
            except Exception:
                pass

    base = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base, "data")
    try:
        os.makedirs(data_dir, exist_ok=True)
    except Exception:
        data_dir = tempfile.gettempdir()
    return os.path.join(data_dir, "vantorium.db")


DB_FILE = _resolve_db_path()
GOOGLE_CX = os.environ.get("GOOGLE_CX", "f79f63e39ec7f4c78")
CODE_FILES_DIR = os.path.join(os.path.dirname(DB_FILE), "code_files")
try:
    os.makedirs(CODE_FILES_DIR, exist_ok=True)
except Exception:
    CODE_FILES_DIR = tempfile.mkdtemp(prefix="vantorium_code_")


def _persistent_secret():
    """SECRET_KEY verilmediyse bir kez üretip diske yazar; böylece yeniden başlatmada oturumlar düşmez."""
    env = os.environ.get("SECRET_KEY", "").strip()
    if env:
        return env
    path = os.path.join(os.path.dirname(DB_FILE), ".secret_key")
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                saved = f.read().strip()
            if saved:
                return saved
        key = secrets.token_hex(32)
        with open(path, "w", encoding="utf-8") as f:
            f.write(key)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        return key
    except Exception:
        return secrets.token_hex(32)


app.secret_key = _persistent_secret()


def db():
    """Her çağrıda yeni bağlantı; WAL + timeout ile güvenli."""
    conn = sqlite3.connect(DB_FILE, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


@contextmanager
def db_cursor():
    """Context manager — bağlantı sızıntısını önler."""
    conn = db()
    try:
        cur = conn.cursor()
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Tabloları oluşturur. Birden fazla çağrı güvenli."""
    max_retries = 5
    for attempt in range(max_retries):
        try:
            with db_cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        api_key TEXT UNIQUE NOT NULL,
                        created_at TEXT NOT NULL,
                        last_login TEXT,
                        is_active INTEGER DEFAULT 1
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS memory (
                        word TEXT PRIMARY KEY,
                        answer TEXT,
                        confidence REAL,
                        source TEXT,
                        created_at TEXT
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS sessions (
                        token TEXT PRIMARY KEY,
                        user_id INTEGER NOT NULL,
                        created_at TEXT NOT NULL,
                        expires_at TEXT,
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS code_files (
                        id TEXT PRIMARY KEY,
                        user_id INTEGER,
                        filename TEXT NOT NULL,
                        language TEXT,
                        content TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        expires_at TEXT,
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS rate_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip TEXT NOT NULL,
                        endpoint TEXT,
                        created_at REAL NOT NULL
                    )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_code_files_user ON code_files(user_id)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_rate_ip ON rate_events(ip, created_at)")
            print(f"[Vantorium] SQLite hazır → {DB_FILE}")
            return
        except sqlite3.OperationalError as e:
            if attempt < max_retries - 1:
                time.sleep(0.3 * (attempt + 1))
                continue
            raise RuntimeError(f"Veritabanı başlatılamadı ({DB_FILE}): {e}") from e


init_db()


def hash_password(password):
    """Tuzlu PBKDF2 özeti üretir."""
    return generate_password_hash(password, method="pbkdf2:sha256")


def verify_password(stored, password):
    """(geçerli_mi, yeniden_özetlenmeli_mi) döner. Eski SHA-256 kayıtlar da kabul edilir."""
    stored = stored or ""
    if stored.startswith(("pbkdf2:", "scrypt:")):
        return check_password_hash(stored, password), False
    legacy = hashlib.sha256(password.encode("utf-8")).hexdigest()
    ok = secrets.compare_digest(stored, legacy)
    return ok, ok


def normalize(text):
    text = (text or "").lower().strip()
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"[?!.,;:]+$", "", text)
    return text


def memory_get(word):
    try:
        with db_cursor() as cur:
            row = cur.execute(
                "SELECT answer FROM memory WHERE word = ?", (word,)
            ).fetchone()
            return row["answer"] if row else None
    except Exception:
        return None


def memory_save(word, answer, confidence, source):
    try:
        with db_cursor() as cur:
            cur.execute("""
                INSERT OR REPLACE INTO memory
                (word, answer, confidence, source, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (word, answer, confidence, source, datetime.now().isoformat()))
    except Exception as e:
        print(f"[memory_save] hata: {e}")


def save_code_file(content, language, filename=None, user_id=None, ttl_hours=48):
    """Uzun kodları geçici dosya olarak saklar, indirme ID'si döner."""
    file_id = secrets.token_urlsafe(16)
    ext_map = {
        "python": ".py", "html": ".html", "css": ".css",
        "javascript": ".js", "php": ".php", "java": ".java",
        "csharp": ".cs", "cpp": ".cpp", "sql": ".sql",
        "bash": ".sh", "typescript": ".ts", "go": ".go",
        "rust": ".rs", "ruby": ".rb", "swift": ".swift",
    }
    ext = ext_map.get(language, ".txt")
    if not filename:
        filename = f"vantorium_{language}_{file_id[:8]}{ext}"
    elif not filename.endswith(ext):
        filename = filename + ext

    expires = (datetime.now() + timedelta(hours=ttl_hours)).isoformat()
    try:
        with db_cursor() as cur:
            cur.execute("""
                INSERT INTO code_files (id, user_id, filename, language, content, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (file_id, user_id, filename, language, content, datetime.now().isoformat(), expires))
        return file_id, filename
    except Exception as e:
        print(f"[save_code_file] hata: {e}")
        return None, None


def get_code_file(file_id):
    try:
        with db_cursor() as cur:
            row = cur.execute(
                "SELECT * FROM code_files WHERE id = ?", (file_id,)
            ).fetchone()
            if not row:
                return None
            if row["expires_at"] and row["expires_at"] < datetime.now().isoformat():
                cur.execute("DELETE FROM code_files WHERE id = ?", (file_id,))
                return None
            return dict(row)
    except Exception:
        return None


def cleanup_expired():
    """Eski oturum ve kod dosyalarını temizler."""
    try:
        now = datetime.now().isoformat()
        with db_cursor() as cur:
            cur.execute("DELETE FROM sessions WHERE expires_at IS NOT NULL AND expires_at < ?", (now,))
            cur.execute("DELETE FROM code_files WHERE expires_at IS NOT NULL AND expires_at < ?", (now,))
            cutoff = time.time() - 7 * 86400
            cur.execute("DELETE FROM rate_events WHERE created_at < ?", (cutoff,))
    except Exception as e:
        print(f"[cleanup] hata: {e}")

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
                    current_q = normalize(line.replace("Input:", "", 1).strip())
                    data.setdefault(current_q, [])

                elif line.startswith("Reply:") and current_q:
                    data[current_q].append(line.replace("Reply:", "", 1).strip())

        break

    return data

DATASET = load_dataset()

# =========================================================
# QUERY INTELLIGENCE
# =========================================================

GREETING_RE = re.compile(
    r"^\s*(selam|selamün aleyküm|selamun aleykum|merhaba|"
    r"hello|hi|hey|günaydın|iyi akşamlar|iyi geceler|"
    r"naber|nbr|nasılsın|sa|s\.a|selam kral|selam abim|"
    r"naber kral|naber ya|naber ya kral|ne haber|ne haber kral|"
    r"nasıl gidiyor|nasilsin|naber lan|selamlar)\s*[!.?]*\s*$",
    re.I
)

SMALLTALK_RE = re.compile(
    r"^\s*("
    r"naber.*|ne haber.*|nasıl(sın|sin)?.*|iyi misin.*|"
    r"ne yapıyorsun|ne yapıyosun|napıyorsun|napıyosun|"
    r"teşekkür(ler)?|sağol|sagol|eyvallah|eyv|"
    r"tamam|ok|okey|anladım|süper|harika|güzel|"
    r"kimsin|sen kimsin|ne iş yapıyorsun|ne yapabilirsin|"
    r"yardım et|yardımcı ol|bana yardım|"
    r"kral|abi|kardes|kardeş|lan|ya kral|ya abi"
    r")\s*[!.?]*\s*$",
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
    raw = (query or "").strip()

    return {
        "is_greeting": bool(GREETING_RE.match(raw)),
        "is_smalltalk": bool(SMALLTALK_RE.match(raw)) or (
            len(raw.split()) <= 5 and bool(re.search(
                r"\b(naber|nasıl|nasilsin|selam|kral|teşekkür|sağol|eyvallah|"
                r"napıyo|ne haber|iyi misin|kimsin)\b", q, re.I
            ))
        ),
        "is_math": bool(
            re.fullmatch(r"[\d\s+\-*/().,%^]+", raw)
            and re.search(r"[+\-*/%^]", raw)
        ),
        "is_code": bool(re.search(
            r"\b(kod|python|php|javascript|js|html|css|api|"
            r"flask|discord|telegram|github|programlama|hata|error|debug)\b",
            q
        )) or is_code_request(query),
        "is_code_request": is_code_request(query),
        "is_definition": bool(DEFINITION_RE.match(raw)),
        "is_response_advice": bool(RESPONSE_RE.search(raw)),
        "is_recommendation": bool(re.search(
            r"\b(öner|önerir misin|tavsiye et|fikir ver|konu öner|"
            r"kaç tane.*öner|\d+.*(konu|fikir|teknoloji).*(öner|listele))\b",
            q, re.I
        )),
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

        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
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
    Google Programmable Search Element endpoint'ini kullanır.
    Google API anahtarı gerekmez.
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
        r = requests.get(url, params=params, headers=headers, timeout=7)

        if r.status_code != 200:
            return []

        match = re.search(r"vantoriumCallback\((.*)\)\s*;?\s*$", r.text, re.S)

        if not match:
            return []

        data = json.loads(match.group(1))
        raw_results = data.get("results", [])

        results = []

        for item in raw_results:
            link = item.get("unescapedUrl") or item.get("url") or ""
            title = item.get("titleNoFormatting") or item.get("title") or ""
            snippet = item.get("contentNoFormatting") or item.get("content") or ""

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

    headers = {"User-Agent": "Mozilla/5.0 Chrome/131 Safari/537.36"}

    try:
        r = requests.get(url, params=params, headers=headers, timeout=7)

        if r.status_code != 200:
            return []

        match = re.search(r"vantoriumCallback\((.*)\)\s*;?\s*$", r.text, re.S)

        if not match:
            return []

        data = json.loads(match.group(1))
        images = []

        for item in data.get("results", []):
            image = item.get("image", {})

            thumbnail = image.get("thumbnailLink") or image.get("source") or ""

            context = (
                image.get("contextLink")
                or item.get("unescapedUrl")
                or item.get("url")
                or ""
            )

            if thumbnail:
                images.append({
                    "title": html.unescape(
                        item.get("titleNoFormatting") or item.get("title") or query
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
            url, params=params,
            headers={"User-Agent": "VantoriumAI/5.0"}, timeout=7
        )

        data = r.json()
        results = []

        for item in data.get("query", {}).get("search", []):
            title = item.get("title", "")
            snippet = re.sub(r"<[^>]+>", "", item.get("snippet", ""))

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
    """GitHub repository search. Teknik sorularda öncelik verilir."""

    try:
        url = "https://api.github.com/search/repositories"

        params = {"q": query, "sort": "stars", "order": "desc", "per_page": num}

        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "VantoriumAI",
        }

        r = requests.get(url, params=params, headers=headers, timeout=7)

        if r.status_code != 200:
            return []

        results = []

        for item in r.json().get("items", []):
            results.append({
                "title": item.get("full_name", ""),
                "url": item.get("html_url", ""),
                "snippet": item.get("description") or "GitHub deposu.",
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
    text = normalize(result.get("title", "") + " " + result.get("snippet", ""))

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

    results.sort(key=lambda x: x.get("_score", 0), reverse=True)

    return results[:limit]

# =========================================================
# CODE REQUEST INTELLIGENCE
# =========================================================

CODE_END_RE = re.compile(
    r"(?:\b(?:kodu|kodunu|python kodu|python kodunu|python|html kodu|html kodunu|html|css kodu|javascript kodu|js kodu|php kodu|java kodu|sql kodu|bash kodu|kdunu|kod vr|kodu vr|kodunu vr|python vr|html kdu vr)\b)\s*(?:ver|vr|yap|yaz|oluştur|gönder)?\s*[.!?]*$",
    re.I
)

CODE_LANG_RE = [
    ("python", re.compile(r"\bpython\b|\.py\b", re.I)),
    ("html", re.compile(r"\bhtml\b|\.html?\b", re.I)),
    ("css", re.compile(r"\bcss\b|\.css\b", re.I)),
    ("javascript", re.compile(r"\bjavascript\b|\bjs\b|\.js\b", re.I)),
    ("php", re.compile(r"\bphp\b|\.php\b", re.I)),
    ("java", re.compile(r"\bjava\b|\.java\b", re.I)),
    ("csharp", re.compile(r"\bc#\b|\bcsharp\b|\.cs\b", re.I)),
    ("cpp", re.compile(r"\bc\+\+\b|\bcpp\b|\.cpp\b", re.I)),
    ("sql", re.compile(r"\bsql\b|\.sql\b", re.I)),
    ("bash", re.compile(r"\bbash\b|\bshell\b|\.sh\b", re.I)),
]

DANGEROUS_CODE_RE = re.compile(
    r"\b(ddos|dos attack|botnet|ransomware|credential stealer|keylogger|malware|trojan|virus|reverse shell|steal cookies|cookie stealer|password stealer|token stealer|phishing kit)\b",
    re.I
)

def is_code_request(query):
    q = normalize(query)
    if CODE_END_RE.search(q):
        return True
    return bool(re.search(r"\b(kodu|kodunu|kod|kdunu|kodu vr|kodunu vr|python vr|html kdu vr)\b", q, re.I))

def detect_code_language(query):
    for language, pattern in CODE_LANG_RE:
        if pattern.search(query or ""):
            return language
    return "python"

def code_request_subject(query):
    q = query or ""
    q = re.sub(
        r"\b(?:bana|bir|bir tane|şu|bunun|bunu|lütfen|kodunu|kodu|kod|python|html|css|javascript|js|php|java|c\+\+|c#|sql|bash|kdunu|vr|ver|yap|yaz|oluştur|gönder)\b",
        " ", q, flags=re.I
    )
    q = re.sub(r"\s+", " ", q).strip(" .,!?:;-_")
    return q or "genel örnek uygulama"

def github_repo_code_search(query, language="python", num_repos=4):
    try:
        repo_query = query + (f" language:{language}" if language else "")
        r = requests.get(
            "https://api.github.com/search/repositories",
            params={"q": repo_query, "sort": "stars", "order": "desc", "per_page": num_repos},
            headers={"Accept": "application/vnd.github+json", "User-Agent": "VantoriumAI/6.0"},
            timeout=7
        )
        if r.status_code != 200:
            return []
        candidates = []
        for repo in r.json().get("items", []):
            owner = repo.get("owner", {}).get("login", "")
            name = repo.get("name", "")
            branch = repo.get("default_branch", "main") or "main"
            if not owner or not name:
                continue
            try:
                tree_r = requests.get(
                    f"https://api.github.com/repos/{owner}/{name}/git/trees/{urllib.parse.quote(branch, safe='')}",
                    params={"recursive": "1"},
                    headers={"Accept": "application/vnd.github+json", "User-Agent": "VantoriumAI/6.0"},
                    timeout=7
                )
                if tree_r.status_code != 200:
                    continue
                tree = tree_r.json().get("tree", [])
            except Exception:
                continue
            extensions = {
                "python": (".py",), "html": (".html", ".htm"), "css": (".css",),
                "javascript": (".js", ".mjs"), "php": (".php",), "java": (".java",),
                "csharp": (".cs",), "cpp": (".cpp", ".cc", ".h", ".hpp"),
                "sql": (".sql",), "bash": (".sh",),
            }.get(language, (".py",))
            files = [x for x in tree if x.get("type") == "blob" and x.get("path", "").lower().endswith(extensions)]
            files = sorted(files, key=lambda x: (0 if any(k in x.get("path", "").lower() for k in ("main", "app", "index", "server")) else 1, len(x.get("path", ""))))
            for file_item in files[:3]:
                path = file_item.get("path", "")
                raw_url = f"https://raw.githubusercontent.com/{owner}/{name}/{urllib.parse.quote(branch, safe='')}/{path}"
                try:
                    code_r = requests.get(raw_url, headers={"User-Agent": "VantoriumAI/6.0"}, timeout=7)
                    if code_r.status_code != 200:
                        continue
                    code = code_r.text
                    if not code.strip() or len(code) < 20:
                        continue
                    if len(code) > 14000:
                        code = code[:14000] + "\n# ... dosya kısaltıldı ..."
                    candidates.append({
                        "title": f"{owner}/{name} — {path}",
                        "url": raw_url,
                        "repo_url": repo.get("html_url", ""),
                        "snippet": repo.get("description") or "GitHub kodu",
                        "code": code,
                        "language": language,
                        "stars": repo.get("stargazers_count", 0),
                        "source": "GitHub",
                    })
                except Exception:
                    continue
            if len(candidates) >= 5:
                break
        return candidates
    except Exception:
        return []

def generate_code_fallback(query, language):
    subject = code_request_subject(query)
    safe_subject = re.sub(r"[^a-zA-Z0-9_ -]", "", subject).strip()[:60] or "Vantorium"
    if language == "html":
        return f'''<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{html.escape(safe_subject)}</title>
  <style>
    *{{box-sizing:border-box}}body{{margin:0;font-family:Inter,Arial,sans-serif;background:#080b10;color:#fff;display:grid;place-items:center;min-height:100vh;padding:24px}}
    .card{{width:min(720px,100%);padding:32px;border:1px solid #24303d;border-radius:20px;background:#101720;box-shadow:0 25px 80px #0008}}
    button{{border:0;border-radius:12px;padding:12px 18px;background:#16d39a;color:#03130e;font-weight:800;cursor:pointer}}
  </style>
</head>
<body>
  <main class="card">
    <h1>{html.escape(safe_subject)}</h1>
    <p>Vantorium tarafından oluşturulan başlangıç arayüzü.</p>
    <button onclick="alert('Hazır!')">Başlat</button>
  </main>
</body>
</html>'''
    if language == "javascript":
        return f'''// {safe_subject}
const app = {{
  name: {safe_subject!r},
  start() {{
    console.log(`${{this.name}} hazır.`);
  }}
}};

app.start();
'''
    if language == "php":
        return f'''<?php
// {safe_subject}
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
echo json_encode([
    'ok' => true,
    'message' => '{safe_subject}',
], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
'''
    if language == "sql":
        escaped = safe_subject.replace("'", "''")
        return f'''-- {safe_subject}
CREATE TABLE IF NOT EXISTS vantorium_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO vantorium_items (name) VALUES ('{escaped}');
SELECT * FROM vantorium_items ORDER BY id DESC;
'''
    if language == "bash":
        return f'''#!/usr/bin/env bash
set -euo pipefail
# {safe_subject}
echo "{safe_subject} hazır."
'''
    return f'''#!/usr/bin/env python3
# {safe_subject} — Vantorium tarafından oluşturulan başlangıç.

from __future__ import annotations


def main() -> None:
    print({safe_subject!r})


if __name__ == "__main__":
    main()
'''

def _format_code_answer(code, language, title="Kod", source="uretilen_kod", user_id=None):
    """Kod 40 KB'dan büyükse dosya olarak saklar ve indirme linki verir."""
    code = code or ""
    size = len(code.encode("utf-8"))
    FILE_THRESHOLD = 40 * 1024

    if size >= FILE_THRESHOLD:
        file_id, filename = save_code_file(code, language, user_id=user_id)
        if file_id:
            return (
                f"**{title}**\n\n"
                f"Kod {size // 1024} KB olduğu için dosya olarak hazırladım.\n\n"
                f"📥 **İndir:** [{filename}](/download/code/{file_id})\n\n"
                f"Dosya 48 saat boyunca geçerli. İndirdikten sonra bilgisayarında açabilirsin.",
                source + "_dosya"
            )
        preview = code[:8000] + "\n\n# ... (dosya çok büyük, tamamı kaydedilemedi) ..."
        return (f"**{title}**\n\n```{language}\n{preview}\n```", source)

    return (f"**{title}**\n\n```{language}\n{code}\n```", source)


def code_response(query, user_id=None):
    language = detect_code_language(query)
    if DANGEROUS_CODE_RE.search(query):
        return (
            "Bu istek saldırı/zararlı yazılım koduna giriyorsa onu GitHub'dan çekip veremem. "
            "Kendi sistemini test ediyorsan güvenli bir yük testi veya laboratuvar örneği hazırlayabilirim.",
            "guvenlik"
        )
    subject = code_request_subject(query)
    candidates = github_repo_code_search(subject, language)
    if candidates:
        best = candidates[0]
        title = f"GitHub örneği — {best.get('title', 'repo')}"
        return _format_code_answer(best["code"], language, title=title, source="github_kod", user_id=user_id)

    generated = generate_code_fallback(query, language)
    return _format_code_answer(
        generated, language,
        title="Başlangıç kodu (yerel üretildi)",
        source="uretilen_kod",
        user_id=user_id
    )

# =========================================================
# SMART ANSWER
# =========================================================

def extract_target(query, parts):
    if parts["is_definition"]:
        match = DEFINITION_RE.match(query)
        if match:
            return match.group(1).strip(" \"“”'")

    if parts["is_response_advice"]:
        cleaned = re.sub(
            r"\b(bana|birisi|biri|dediğim|dediğim kelime|"
            r"derse|dedi|söylerse|söyledi|ne demeliyim|"
            r"ne diyeyim|nasıl cevap vereyim|ne cevap vereyim)\b",
            " ", query, flags=re.I
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
    """Ham arama metinlerini kısa, çok kaynaklı özete dönüştürür (arama sayfası için)."""
    if not results:
        return None
    ranked = best_results(results, make_search_query(query, parts), 8)
    target = extract_target(query, parts)
    snippets, seen = [], set()
    for item in ranked:
        snippet = clean_snippet(item.get("snippet", ""), 520)
        if not snippet or normalize(snippet) in seen:
            continue
        seen.add(normalize(snippet))
        snippets.append(snippet)
        if len(snippets) >= 4:
            break
    if not snippets:
        return None
    if parts.get("is_definition"):
        return f"**{target}**: {snippets[0]}"
    if parts.get("is_response_advice"):
        return (
            "Bu ifadeye verebileceğin kısa cevap: **“Anladım, biraz daha açar mısın?”**\n\n"
            "Daha samimi bir seçenek: **“Neden öyle düşünüyorsun?”**\n\n"
            f"Arama sonuçlarından ilgili bilgi: {snippets[0]}"
        )
    sentences = []
    for snippet in snippets:
        for sentence in re.split(r"(?<=[.!?])\s+", snippet):
            sentence = sentence.strip(" -•")
            if len(sentence) >= 35 and normalize(sentence) not in {normalize(x) for x in sentences}:
                sentences.append(sentence)
            if len(sentences) >= 4:
                break
        if len(sentences) >= 4:
            break
    if not sentences:
        sentences = snippets[:2]
    return (
        f"**{query.strip()}** hakkında bulabildiğim bilgilerin özeti:\n\n"
        + "\n\n".join(sentences[:4])
    )

def search_everywhere(query, parts=None):
    if parts is None:
        parts = analyze_query(query)
    search_query = make_search_query(query, parts)
    google_results = cse_search(search_query, "web", 6)
    wiki_results = wikipedia_search(search_query, 3)
    github_results = github_search(search_query, 5) if parts.get("is_code") else []
    results = best_results(google_results + github_results + wiki_results, search_query, 8)
    query_terms = [w for w in normalize(search_query).split() if len(w) >= 3]
    relevant = []
    for item in results:
        haystack = normalize(item.get("title", "") + " " + item.get("snippet", ""))
        matched = sum(1 for word in query_terms if word in haystack)
        if not query_terms or matched >= min(2, len(query_terms)):
            relevant.append(item)
    return relevant

# =========================================================
# LOCAL GENERATION ENGINE
# =========================================================

LOCAL_KNOWLEDGE = {
    "python": "Python; okunabilir sözdizimiyle öne çıkan, otomasyon, web geliştirme, veri analizi ve yazılım projelerinde kullanılan genel amaçlı bir programlama dilidir.",
    "html": "HTML, web sayfalarının başlık, paragraf, görsel, bağlantı ve form gibi yapısal öğelerini tanımlayan işaretleme dilidir. Tek başına programlama dili değildir.",
    "css": "CSS, HTML ile oluşturulan web sayfalarının renk, yerleşim, tipografi, animasyon ve farklı ekranlara uyum gibi görsel özelliklerini belirler.",
    "javascript": "JavaScript, web sayfalarına etkileşim kazandıran ve tarayıcıda veya Node.js gibi ortamlarda çalışabilen programlama dilidir.",
    "api": "API, farklı yazılımların belirli kurallar üzerinden birbiriyle veri alışverişi yapmasını ve işlevlerini kullanmasını sağlayan arayüzdür.",
    "yapay zeka": "Yapay zekâ, bilgisayar sistemlerinin dil anlama, örüntü bulma, tahmin ve karar desteği gibi görevleri yerine getirmesini sağlayan yöntemler bütünüdür.",
    "algoritma": "Algoritma, bir problemi çözmek veya bir işi tamamlamak için izlenen açık ve sıralı adımlar bütünüdür.",
    "internet": "İnternet, dünya genelindeki bilgisayar ağlarını ortak iletişim kurallarıyla birbirine bağlayan küresel ağ sistemidir.",
    "veritabanı": "Veritabanı, bilgilerin düzenli biçimde saklanmasını, aranmasını, güncellenmesini ve yönetilmesini sağlayan sistemdir.",
    "ddos": "DDoS, bir hizmeti çok sayıda kaynaktan gelen yoğun trafikle erişilemez hâle getirmeyi amaçlayan dağıtık hizmet engelleme saldırısıdır. Savunmada trafik filtreleme, hız sınırı, CDN ve sağlayıcı koruması kullanılır.",
    "makine öğrenmesi": "Makine öğrenmesi, bilgisayarların verilerdeki örüntülerden model oluşturmasını sağlayan yapay zekâ alanıdır."
}

WORD_SYLLABLES = (
    "va", "ven", "tor", "ium", "zi", "ra", "lun", "tek", "no", "mir",
    "ka", "ro", "zen", "ari", "sol", "nev", "ora", "dex", "el", "on"
)

def generate_original_words(count=10, short=False):
    count = max(1, min(int(count), 20))
    words = set()
    attempts = 0
    while len(words) < count and attempts < count * 40:
        attempts += 1
        word = "".join(random.choice(WORD_SYLLABLES) for _ in range(random.choice((2, 2, 3))))
        if short:
            word = word[:random.choice((4, 5, 6))]
        word = word.capitalize()
        if 4 <= len(word) <= 12:
            words.add(word)
    return list(words)

def local_creative_answer(query):
    q = normalize(query)
    count_match = re.search(r"\b(\d{1,2})\b", q)
    count = min(20, max(1, int(count_match.group(1)))) if count_match else 8

    if re.search(r"\b(kelime|kelimeler|uydurma kelime)\b", q) and re.search(r"\b(üret|oluştur|bul|ver|yaz)\b", q):
        words = generate_original_words(count, short=True)
        return (
            "İşte özgün kelimeler:\n\n"
            + " · ".join(words)
            + "\n\nBunlar sözlük kelimesi değil; hece birleştirmesiyle oluşturulmuş yeni isim fikirleridir."
        ), "yerel_uretim"

    if re.search(r"\b(nick|kullanıcı adı|username|oyuncu adı)\b", q):
        words = generate_original_words(count, short=True)
        return "Kullanıcı adı önerileri:\n\n" + "\n".join(
            f"{i+1}. **{w}**" for i, w in enumerate(words)
        ), "yerel_uretim"

    if re.search(r"\b(isim|marka adı|proje adı|uygulama adı)\b", q):
        words = generate_original_words(count)
        return "İsim fikirleri:\n\n" + "\n".join(
            f"{i+1}. **{w}**" for i, w in enumerate(words)
        ), "yerel_uretim"

    if re.search(r"\b(slogan|motto)\b", q):
        options = [
            "Fikrini gerçeğe dönüştür.",
            "Küçük başla, büyük düşün.",
            "Gelecek, bugün attığın adımla başlar.",
            "Sınırları değil, olasılıkları keşfet.",
            "Her fikrin güçlü bir başlangıcı vardır.",
            "Üret, dene, geliştir, yeniden keşfet."
        ]
        random.shuffle(options)
        return "Slogan önerileri:\n\n" + "\n".join(
            f"{i+1}. {item}" for i, item in enumerate(options[:count])
        ), "yerel_uretim"

    if re.search(r"\b(fikir|proje fikri|uygulama fikri)\b", q) and re.search(r"\b(üret|öner|ver|bul|oluştur)\b", q):
        ideas = [
            "Notları etiketleyip aranabilir hâle getiren kişisel arşiv.",
            "Günlük harcamaları çevrimdışı takip eden bütçe uygulaması.",
            "Dosyaları tür ve tarihe göre düzenleyen masaüstü aracı.",
            "Kelime öğrenmek için aralıklı tekrar kartları.",
            "Web sitelerinin erişilebilirliğini kontrol eden denetleyici.",
            "Kod parçacıklarını etiketleyip arayan kişisel kütüphane.",
            "Alışkanlıkları takvim üzerinde takip eden günlük uygulama.",
            "Uzun metinleri başlık ve maddelere ayıran düzenleyici.",
            "Yerel ağdaki cihazları listeleyen yönetim paneli.",
            "Kişisel görevleri önceliğe göre sıralayan mini planlayıcı."
        ]
        random.shuffle(ideas)
        return "Proje fikirleri:\n\n" + "\n".join(
            f"{i+1}. {item}" for i, item in enumerate(ideas[:count])
        ), "yerel_uretim"

    return None

def local_knowledge_answer(query):
    q = normalize(query)
    for key, answer in LOCAL_KNOWLEDGE.items():
        if key in q:
            return answer
    return None

def local_fallback_answer(query):
    q = (query or "").strip()
    if len(q.split()) <= 2:
        return (
            f"“{q}” hakkında hangi yönden bilgi istediğini biraz açar mısın? "
            "Anlamını, kullanımını, örneklerini veya nasıl yapılacağını açıklayabilirim."
        )
    return (
        "Bu soruya özel doğrulanmış bilgi bulamadım. "
        "Arama sonuçları da yeterince ilgili değil; yanlış bilgi uydurmak istemem. "
        "Soruyu biraz daha ayrıntılandırırsan tekrar araştırabilirim."
    )


def recommendation_answer(query):
    q = normalize(query)
    if re.search(r"teknoloji|technology|teknolojik", q):
        return (
            "Bugün öğrenmeye değer 5 teknoloji konusu:\n\n"
            "1. **Yapay zekâ ajanları:** Araç kullanabilen ve çok adımlı işleri "
            "tamamlayabilen akıllı sistemler.\n\n"
            "2. **Siber güvenlik:** Kimlik avı, veri sızıntısı ve güvenli yazılım "
            "geliştirme yöntemleri.\n\n"
            "3. **Kuantum bilişim:** Kuantum bilgisayarların çalışma mantığı "
            "ve kullanım alanları.\n\n"
            "4. **Robotik ve otonom sistemler:** Sensörler, bilgisayarlı görü "
            "ve kendi kararlarını verebilen makineler.\n\n"
            "5. **Edge AI:** Yapay zekânın bulut yerine telefon ve diğer "
            "cihazların üzerinde çalıştırılması.\n\n"
            "**Başlangıç önerim:** Python temeliyle küçük bir yapay zekâ "
            "asistanı geliştirerek başla.",
            "öneri"
        )
    return None


def smalltalk_answer(query):
    q = normalize(query)
    if re.search(r"\b(teşekkür|sağol|sagol|eyvallah|eyv)\b", q):
        return random.choice([
            "Rica ederim 🙌 Başka bir şey var mı?",
            "Ne demek, buradayım.",
            "Her zaman. Devam edelim mi?"
        ])
    if re.search(r"\b(kimsin|sen kimsin|ne iş|ne yapabilirsin)\b", q):
        return (
            "Ben Vantorium — araştırma, kod ve fikir asistanınım.\n"
            "Web'de arar, kod yazar, konular anlatırım. Ne yapmak istersin?"
        )
    if re.search(r"\b(naber|ne haber|nasıl|nasilsin|iyi misin|napıyo)\b", q):
        return random.choice([
            "İyiyim kral 😎 Sen nasılsın? Ne yapalım?",
            "Buradayım, hazırım. Söyle neye bakıyoruz.",
            "Her şey yolunda. Kod mu, araştırma mı, yoksa sohbet mi?"
        ])
    if re.search(r"\b(selam|merhaba|hello|hi)\b", q):
        return random.choice([
            "Selam! 👋 Ne yapmak istiyorsun?",
            "Merhaba kral. Hazırım, yaz gelsin.",
            "Selam! Sorunu yaz, birlikte çözelim."
        ])
    return random.choice([
        "Anladım. Ne üzerinde çalışmak istersin?",
        "Tamam, buradayım. Detay verirsen daha iyi yardımcı olurum.",
        "Peki. Kod, araştırma ya da fikir — ne diyorsun?"
    ])


def get_answer(query):
    query = (query or "").strip()
    if not query:
        return "Bir şeyler yaz, birlikte bakalım.", "sistem"

    parts = analyze_query(query)

    if parts["is_greeting"] or parts.get("is_smalltalk"):
        return smalltalk_answer(query), "sohbet"

    if parts["is_math"]:
        try:
            return f"Sonuç: {safe_math(query)}", "matematik"
        except Exception:
            return "Bu matematik ifadesini güvenli şekilde çözemedim.", "hata"

    creative = local_creative_answer(query)
    if creative:
        return creative

    if parts.get("is_recommendation"):
        recommendation = recommendation_answer(query)
        if recommendation:
            return recommendation

    if parts.get("is_code_request"):
        uid = None
        try:
            u = get_current_user()
            if u:
                uid = u.get("id")
        except Exception:
            pass
        return code_response(query, user_id=uid)

    normalized = normalize(query)
    if normalized in DATASET and DATASET[normalized]:
        return random.choice(DATASET[normalized]), "veri_seti"

    cached = memory_get(normalized)
    if cached and "Kaynak:" not in cached and not re.search(r"https?://", cached):
        return cached, "hafiza"

    local_fact = local_knowledge_answer(query)
    if local_fact:
        memory_save(normalized, local_fact, 0.90, "yerel_bilgi")
        return local_fact, "yerel_bilgi"

    if len(query.split()) <= 2 and not parts.get("is_definition"):
        return smalltalk_answer(query), "sohbet"

    results = search_everywhere(query, parts)
    answer = synthesize_answer(query, results, parts)
    if answer:
        memory_save(normalized, answer, 0.72, "web_sentez")
        return answer, "web_sentez"

    return local_fallback_answer(query), "yerel_fallback"

# =========================================================
# AUTH — Kalıcı oturum + güvenli kullanıcı yönetimi
# =========================================================

def get_current_user():
    token = request.cookies.get("session_token")
    if not token:
        return None
    try:
        with db_cursor() as cur:
            row = cur.execute("""
                SELECT u.id, u.username, u.api_key, u.created_at, u.last_login, u.is_active
                FROM users u
                JOIN sessions s ON u.id = s.user_id
                WHERE s.token = ?
                  AND (s.expires_at IS NULL OR s.expires_at > ?)
                  AND u.is_active = 1
            """, (token, datetime.now().isoformat())).fetchone()
            return dict(row) if row else None
    except Exception as e:
        print(f"[get_current_user] {e}")
        return None


def create_session(user_id, days=30):
    token = secrets.token_hex(32)
    now = datetime.now()
    expires = (now + timedelta(days=days)).isoformat()
    try:
        with db_cursor() as cur:
            cur.execute("""
                INSERT INTO sessions (token, user_id, created_at, expires_at)
                VALUES (?, ?, ?, ?)
            """, (token, user_id, now.isoformat(), expires))
            cur.execute("UPDATE users SET last_login = ? WHERE id = ?", (now.isoformat(), user_id))
        return token
    except Exception as e:
        print(f"[create_session] {e}")
        return None


def destroy_session(token):
    if not token:
        return
    try:
        with db_cursor() as cur:
            cur.execute("DELETE FROM sessions WHERE token = ?", (token,))
    except Exception:
        pass


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
:root{--bg:#07090d;--panel:#0d1117;--panel2:#111821;--line:rgba(255,255,255,.08);--muted:#8b96a7;--text:#f5f7fa;--green:#16d39a;--green2:#0bbf89;--danger:#ff5c70;--shadow:0 20px 70px rgba(0,0,0,.38)}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(circle at 50% -20%,rgba(22,211,154,.11),transparent 32%),var(--bg);color:var(--text);min-height:100vh;-webkit-font-smoothing:antialiased}
a{color:inherit;text-decoration:none}
button,input{font:inherit}
.navbar{height:68px;padding:0 22px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;background:rgba(7,9,13,.76);backdrop-filter:blur(18px);border-bottom:1px solid var(--line)}
.logo{display:flex;align-items:center;gap:11px;font-weight:800;font-size:18px;letter-spacing:-.5px}
.logo-icon{width:36px;height:36px;border-radius:12px;display:block;object-fit:contain;background:transparent}
.nav-actions{display:flex;gap:4px;align-items:center}
.btn-nav{padding:9px 13px;color:#aeb7c5;border-radius:10px;font-size:14px;font-weight:650;transition:.18s}
.btn-nav:hover{color:#fff;background:rgba(255,255,255,.06)}
.btn-nav.primary{background:var(--green);color:#03130e;box-shadow:0 8px 25px rgba(22,211,154,.15)}
.container{width:min(430px,calc(100% - 28px));margin:auto;padding:32px;background:linear-gradient(180deg,rgba(17,24,33,.94),rgba(11,15,21,.96));border:1px solid var(--line);border-radius:22px;box-shadow:var(--shadow)}
.container.wide{width:min(980px,calc(100% - 28px));margin:38px auto}
.auth-wrapper{min-height:calc(100vh - 68px);display:grid;place-items:center;padding:25px 0}
h1.page-title{font-size:32px;letter-spacing:-1px;margin-bottom:8px}
h2{font-size:25px;margin-bottom:7px}
.subtitle{color:var(--muted);line-height:1.6;font-size:14px;margin-bottom:25px}
label{display:block;color:#cbd2dc;font-size:13px;font-weight:650;margin-bottom:7px}
input[type=text],input[type=password]{width:100%;padding:13px 14px;margin-bottom:17px;border:1px solid rgba(255,255,255,.09);border-radius:12px;background:#080b10;color:#fff;outline:none;transition:.18s}
input:focus{border-color:rgba(22,211,154,.7);box-shadow:0 0 0 4px rgba(22,211,154,.09)}
.btn{width:100%;padding:13px 15px;border:0;border-radius:12px;background:linear-gradient(135deg,#1ce0a5,#0dbd89);color:#03130e;font-weight:800;cursor:pointer;transition:.18s}
.btn:hover{transform:translateY(-1px);filter:brightness(1.05)}
.btn-small{width:auto;padding:10px 15px;font-size:13px}
.btn.danger{background:#ef4c61;color:#fff}
.btn.secondary{background:#1b222c;color:#fff}
.link-row{text-align:center;margin-top:21px;color:#818b99;font-size:14px}
.link-row a{color:var(--green)}
.error{padding:12px;border-radius:12px;background:rgba(255,92,112,.09);border:1px solid rgba(255,92,112,.2);color:#ff8b99;margin-bottom:18px;font-size:13px}
.card{padding:25px;margin-bottom:18px;background:linear-gradient(180deg,#0e141c,#0b1016);border:1px solid var(--line);border-radius:18px}
.card h3{display:flex;gap:9px;align-items:center;margin-bottom:14px;font-size:16px}
.card p{color:#a8b1be;line-height:1.75;font-size:14px;margin-bottom:12px}
.code-block,.api-key-box{background:#070a0f;border:1px solid var(--line);border-radius:12px;padding:15px;overflow:auto;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;line-height:1.7}
.api-key-box{color:var(--green);word-break:break-all}
.section-title{margin:34px 0 14px;font-size:18px}
.card ul{list-style:none}
.card li{padding:11px 0;border-bottom:1px solid var(--line);color:#a8b1be;line-height:1.6;font-size:14px}
.card li:last-child{border-bottom:0}
.card li:before{content:"✓";color:var(--green);margin-right:9px;font-weight:800}
.footer{color:#5d6775;text-align:center;padding:35px 15px;font-size:12px}
.search-page{width:min(1050px,calc(100% - 28px));margin:45px auto}
.search-hero{text-align:center;margin-bottom:28px}
.search-hero h1{font-size:42px;letter-spacing:-1.5px;margin-bottom:10px}
.search-hero p{color:#8792a1}
.search-box{position:relative;max-width:800px;margin:24px auto}
.search-box input{margin:0;padding:17px 60px 17px 18px;border-radius:16px;background:#0d141c}
.search-box button{position:absolute;right:7px;top:7px;height:44px;padding:0 17px;border:0;border-radius:12px;background:var(--green);color:#03130e;font-weight:800}
.result{padding:19px;border:1px solid var(--line);border-radius:16px;background:#0c1219;margin-bottom:12px}
.result h3{color:#f4f7fa;font-size:15px;margin-bottom:6px}
.result .source{color:var(--green);font-size:11px;font-weight:800;text-transform:uppercase;margin-bottom:7px}
.result p{color:#9da8b6;font-size:13px;line-height:1.65}
.result a{display:inline-block;margin-top:9px;color:#7ee9c6;font-size:12px;word-break:break-all}
.image-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px}
.image-card{overflow:hidden;border-radius:14px;border:1px solid var(--line);background:#0d1218}
.image-card img{width:100%;height:145px;display:block;object-fit:cover}
.image-card div{padding:9px;font-size:11px;color:#a8b1be}
.thinking{display:flex;align-items:center;gap:9px;color:#dce5f5;font-weight:650}
.thinking-dot{width:8px;height:8px;border-radius:50%;background:#9bbcf2;box-shadow:0 0 0 5px rgba(155,188,242,.12);animation:vPulse 1s infinite}
@keyframes vPulse{50%{opacity:.35;transform:scale(.8)}}
@media(max-width:720px){.navbar{height:62px;padding:0 12px}.nav-actions{gap:0}.btn-nav{padding:8px 7px;font-size:12px}.logo{font-size:15px}.logo-icon{width:32px;height:32px}.search-hero h1{font-size:31px}}
.policy-overlay{position:fixed;inset:0;z-index:1000;display:grid;place-items:center;padding:20px;background:rgba(0,0,0,.62);backdrop-filter:blur(12px)}
.policy-modal{width:min(520px,100%);max-height:min(720px,88vh);overflow:auto;padding:27px;border-radius:24px;background:linear-gradient(180deg,#121923,#0c1118);border:1px solid rgba(255,255,255,.1);box-shadow:0 30px 100px rgba(0,0,0,.6)}
.policy-icon{width:48px;height:48px;border-radius:15px;display:grid;place-items:center;background:rgba(22,211,154,.12);color:var(--green);margin-bottom:14px;font-weight:900}
.policy-modal h3{font-size:21px;margin-bottom:7px}
.policy-modal p{color:#98a4b3;font-size:13px;line-height:1.7}
.policy-list{margin:17px 0;display:grid;gap:9px}
.policy-item{padding:11px 12px;border-radius:12px;background:rgba(255,255,255,.035);color:#cbd2dc;font-size:13px}
.policy-buttons{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:18px}
.policy-buttons a{padding:12px;border-radius:12px;text-align:center;background:#1a222d;font-size:13px;font-weight:750}
.policy-buttons a.primary{background:var(--green);color:#03130e}
.close-policy{display:block;text-align:center;margin-top:13px;color:#6f7a89;font-size:12px;cursor:pointer}
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
        <p>Devam etmeden önce Vantorium kullanım kurallarını ve gizlilik politikasını inceleyebilirsin.</p>
        <div class="policy-list">
          <div class="policy-item">✓ API anahtarını kimseyle paylaşma.</div>
          <div class="policy-item">✓ Sistemi kötüye kullanma veya aşırı istek gönderme.</div>
          <div class="policy-item">✓ Zararlı, yasa dışı veya saldırı amaçlı kullanım yasaktır.</div>
          <div class="policy-item">✓ Web sonuçları her zaman doğrulanmalıdır.</div>
          <div class="policy-item">✓ Hizmet zaman zaman güncellenebilir veya bakım nedeniyle durabilir.</div>
        </div>
        <div class="policy-buttons">
          <a href="/info">Kurallar & Politikalar</a>
          <a href="#" class="primary" onclick="closePolicy();return false;">Devam Et</a>
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
            <img class="logo-icon" src="/icon.png" alt="Vantorium">
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
      <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
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
# SITE PROTECTION: HUMAN GATE + RATE LIMITING
# =========================================================

_RATE_BUCKETS = defaultdict(deque)
_RATE_LOCK = Lock()
_FAIL_BUCKETS = defaultdict(deque)
_BLOCKED_IPS = {}

def client_ip():
    # TRUST_PROXY=1 iken ProxyFix, remote_addr'ı doğru istemci IP'sine çevirir.
    return (request.remote_addr or "unknown")[:64]


def is_ip_blocked(ip):
    until = _BLOCKED_IPS.get(ip)
    if until and until > time.time():
        return True
    if until:
        _BLOCKED_IPS.pop(ip, None)
    return False


def record_failure(ip, kind="login", limit=8, window=600, ban_seconds=1800):
    """Başarısız denemeleri sayar, eşiği aşınca IP'yi geçici banlar."""
    key = f"{kind}:{ip}"
    now = time.time()
    with _RATE_LOCK:
        bucket = _FAIL_BUCKETS[key]
        while bucket and now - bucket[0] > window:
            bucket.popleft()
        bucket.append(now)
        if len(bucket) >= limit:
            _BLOCKED_IPS[ip] = now + ban_seconds
            bucket.clear()
            return True
    return False


def rate_limit(limit=12, window=60):
    def decorator(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            ip = client_ip()
            if is_ip_blocked(ip):
                retry = max(1, int(_BLOCKED_IPS.get(ip, time.time()) - time.time()))
                resp = jsonify({
                    "error": "Çok fazla başarısız deneme. IP geçici olarak engellendi.",
                    "retry_after": retry
                })
                resp.status_code = 429
                resp.headers["Retry-After"] = str(retry)
                return resp

            key = f"{func.__name__}:{ip}"
            now = time.time()
            with _RATE_LOCK:
                bucket = _RATE_BUCKETS[key]
                while bucket and now - bucket[0] > window:
                    bucket.popleft()
                if len(bucket) >= limit:
                    retry = max(1, int(window - (now - bucket[0])))
                    if len(bucket) > limit * 3:
                        _BLOCKED_IPS[ip] = now + 300
                    resp = jsonify({
                        "error": "Çok fazla istek gönderildi. Biraz bekleyip tekrar dene.",
                        "retry_after": retry
                    })
                    resp.status_code = 429
                    resp.headers["Retry-After"] = str(retry)
                    return resp
                bucket.append(now)
            return func(*args, **kwargs)
        return wrapped
    return decorator


def captcha_page():
    nonce = secrets.token_urlsafe(24)
    session["human_nonce"] = nonce
    session["human_started"] = time.time()
    icon_url = "/icon.png"
    page = f"""<!doctype html>
<html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#101114"><title>Güvenlik doğrulaması | Vantorium</title>
<style>
*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:center;padding:22px;
background:#101114;color:#e8eaed;font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif}}
.card{{width:min(420px,100%);padding:32px 26px;border:1px solid #30343b;border-radius:22px;
background:#17191e;box-shadow:0 22px 80px #0007;text-align:center}}
.brand{{width:58px;height:58px;object-fit:contain;margin:0 auto 22px;display:block}}
h1{{font-size:20px;font-weight:600;margin:0 0 9px}}p{{font-size:14px;line-height:1.6;color:#aab1bd;margin:0 0 24px}}
.checkrow{{display:flex;align-items:center;gap:13px;padding:16px;border:1px solid #3a404a;
border-radius:12px;background:#20242b;text-align:left;cursor:pointer;user-select:none}}
.checkrow input{{width:22px;height:22px;accent-color:#8ab4f8;cursor:pointer}}
.checkrow span{{font-size:14px;color:#e8eaed}}
.spinner{{display:none;width:27px;height:27px;border:3px solid #424955;border-top-color:#a8c7fa;
border-radius:50%;animation:spin .8s linear infinite;margin-left:auto}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
#status{{min-height:22px;margin-top:17px;color:#aab1bd;font-size:12px}}
.small{{margin-top:22px;color:#707987;font-size:11px}}
</style></head><body><main class="card">
<img class="brand" src="{icon_url}" alt="Vantorium">
<h1>Güvenlik kontrolü</h1>
<p>Bot Olmadığınızı doğrulamak için basın.</p>
<div class="checkrow" id="checkLabel">
<input id="humanCheck" type="checkbox">
<span>Ben robot değilim</span><span class="spinner" id="spinner"></span>
</div>
<div id="status" role="status" aria-live="polite"></div>
<div class="small">Vantorium güvenlik doğrulaması</div>
</main>
<script>
(() => {{
 const box=document.getElementById("humanCheck"), label=document.getElementById("checkLabel");
 const spinner=document.getElementById("spinner"), status=document.getElementById("status");
 let pointerCount=0, started=performance.now(), moved=false, busy=false;
 document.addEventListener("pointermove",()=>{{pointerCount++;moved=true;}},{{passive:true}});
 document.addEventListener("pointerdown",()=>{{pointerCount++;moved=true;}},{{passive:true,once:true}});
 box.addEventListener("click", async (event)=>{{
   if(event.target!==box) return;
   if(busy) return;
   if(!box.checked) return;
   busy=true; box.disabled=true; spinner.style.display="block";
   status.textContent="Kontrol ediliyor...";
   const elapsed=Math.round(performance.now()-started);
   try {{
     const r=await fetch("/_human-check",{{method:"POST",headers:{{"Content-Type":"application/json"}},
       body:JSON.stringify({{nonce:{json.dumps(nonce)},elapsed:elapsed,pointerCount:pointerCount,moved:moved}}),
       credentials:"same-origin"}});
     const data=await r.json();
     if(!r.ok || !data.ok) throw new Error(data.error||"Doğrulama başarısız.");
     status.textContent="Doğrulandı. Yönlendiriliyorsun...";
     location.replace(data.next||"/");
   }} catch(e) {{
     status.textContent=e.message||"Tekrar deneyin.";
     box.checked=false;box.disabled=false;spinner.style.display="none";busy=false;
   }}
 }});
}})();
</script></body></html>"""
    return make_response(page, 200)


@app.before_request
def site_human_gate():
    # API istekleri hiçbir zaman tarayıcı doğrulamasına yönlendirilmez.
    path = request.path or "/"
    if path.startswith("/api") or path.startswith("/api-key=") or path in ("/_human-check", "/icon.png", "/favicon.ico"):
        return None
    if request.method != "GET":
        return None
    if session.get("human_verified_at") and time.time() - float(session["human_verified_at"]) < 12 * 3600:
        return None
    return captcha_page()


@app.route("/_human-check", methods=["POST"])
@rate_limit(10, 120)
def human_check():
    ip = client_ip()
    if is_ip_blocked(ip):
        return jsonify({"ok": False, "error": "Çok fazla deneme. Daha sonra tekrar dene."}), 429

    data = request.get_json(silent=True) or {}
    try:
        elapsed = int(data.get("elapsed", 0) or 0)
        pointer_count = int(data.get("pointerCount", 0) or 0)
    except (TypeError, ValueError):
        elapsed, pointer_count = 0, 0
    expected = session.get("human_nonce")
    nonce = str(data.get("nonce", ""))
    moved = bool(data.get("moved"))
    started = float(session.get("human_started", 0) or 0)
    server_elapsed = time.time() - started

    ok = (
        expected
        and secrets.compare_digest(expected, nonce)
        and elapsed >= 700
        and 0.7 <= server_elapsed <= 180
        and pointer_count >= 1
        and moved
    )
    if not ok:
        record_failure(ip, kind="captcha", limit=12, window=600, ban_seconds=900)
        return jsonify({"ok": False, "error": "Doğrulama tamamlanamadı. Kutucuğa tekrar basıp deneyin."}), 400

    session.pop("human_nonce", None)
    session.pop("human_started", None)
    session["human_verified_at"] = time.time()
    return jsonify({"ok": True, "next": "/"})


@app.route("/icon.png")
def site_icon():
    folder = os.path.dirname(os.path.abspath(__file__))
    icon_path = os.path.join(folder, "icon.png")
    if not os.path.isfile(icon_path):
        return Response(status=404)
    return send_from_directory(folder, "icon.png", mimetype="image/png", max_age=86400)


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cache-Control", "no-store" if request.path.startswith("/api") else "private, max-age=0")
    return response


# =========================================================
# ROUTES
# =========================================================

@app.route("/")
def index():
    if get_current_user():
        return redirect("/chat")
    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
@rate_limit(5, 300)
def register():
    if get_current_user():
        return redirect("/chat")

    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not re.fullmatch(r"[a-zA-Z0-9_.-]{3,32}", username):
            error = "Kullanıcı adı 3-32 karakter olmalı (harf, rakam, _ . -)."
        elif len(password) < 6:
            error = "Şifre en az 6 karakter olmalı."
        else:
            try:
                with db_cursor() as cur:
                    exists = cur.execute(
                        "SELECT id FROM users WHERE username = ?", (username,)
                    ).fetchone()
                    if exists:
                        error = "Bu kullanıcı adı zaten alınmış."
                    else:
                        api_key = "vnt_" + secrets.token_hex(24)
                        cur.execute("""
                            INSERT INTO users
                            (username, password_hash, api_key, created_at, is_active)
                            VALUES (?, ?, ?, ?, 1)
                        """, (username, hash_password(password), api_key, datetime.now().isoformat()))
                        return redirect("/login?registered=1")
            except sqlite3.IntegrityError:
                error = "Bu kullanıcı adı zaten alınmış."
            except Exception as e:
                print(f"[register] {e}")
                error = "Kayıt sırasında bir hata oluştu. Tekrar dene."

    content = f"""
    <main class="auth-wrapper">
      <section class="container">
        <h2>Hesap oluştur</h2>
        <p class="subtitle">Vantorium hesabını oluştur ve kendi API anahtarını al.</p>

        {f'<div class="error">{html.escape(error)}</div>' if error else ''}

        <form method="POST">
          <label>Kullanıcı adı</label>
          <input type="text" name="username" minlength="3" maxlength="32"
                 autocomplete="username" placeholder="kullanici_adi"
                 pattern="[a-zA-Z0-9_.-]{{3,32}}" required>

          <label>Şifre</label>
          <input type="password" name="password" minlength="6"
                 autocomplete="new-password" placeholder="••••••••" required>

          <button class="btn" type="submit">Hesap oluştur</button>
        </form>

        <div class="link-row">Zaten hesabın var mı? <a href="/login">Giriş yap</a></div>
      </section>
    </main>
    """

    return render_page("Kayıt", content, modal=True)

@app.route("/login", methods=["GET", "POST"])
@rate_limit(8, 300)
def login():
    if get_current_user():
        return redirect("/chat")

    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        try:
            with db_cursor() as cur:
                user = cur.execute(
                    "SELECT * FROM users WHERE username = ? AND is_active = 1",
                    (username,)
                ).fetchone()

            valid, upgrade = (False, False)
            if user:
                valid, upgrade = verify_password(user["password_hash"], password)

            if valid:
                if upgrade:  # eski SHA-256 kaydı tuzlu özete çevir
                    with db_cursor() as cur:
                        cur.execute(
                            "UPDATE users SET password_hash = ? WHERE id = ?",
                            (hash_password(password), user["id"])
                        )
                token = create_session(user["id"])
                if token:
                    response = make_response(redirect("/chat"))
                    response.set_cookie(
                        "session_token", token, httponly=True, samesite="Lax",
                        max_age=30 * 24 * 3600, secure=request.is_secure
                    )
                    return response
                error = "Oturum oluşturulamadı. Tekrar dene."
            else:
                record_failure(client_ip(), kind="login", limit=8, window=600, ban_seconds=1800)
                error = "Kullanıcı adı veya şifre hatalı."
        except Exception as e:
            print(f"[login] {e}")
            error = "Giriş sırasında bir hata oluştu."

    content = f"""
    <main class="auth-wrapper">
      <section class="container">
        <h2>Tekrar hoş geldin</h2>
        <p class="subtitle">Vantorium'a giriş yap ve araştırmaya devam et.</p>

        {f'<div class="error">{html.escape(error)}</div>' if error else ''}

        <form method="POST">
          <label>Kullanıcı adı</label>
          <input type="text" name="username" autocomplete="username"
                 placeholder="kullanici_adi" required>

          <label>Şifre</label>
          <input type="password" name="password" autocomplete="current-password"
                 placeholder="••••••••" required>

          <button class="btn" type="submit">Giriş yap</button>
        </form>

        <div class="link-row">Hesabın yok mu? <a href="/register">Kayıt ol</a></div>
      </section>
    </main>
    """

    return render_page("Giriş", content, modal=True)

@app.route("/logout")
def logout():
    token = request.cookies.get("session_token")
    destroy_session(token)
    response = make_response(redirect("/login"))
    response.delete_cookie("session_token")
    return response

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
          <input id="searchInput" type="text" placeholder="Ne aramak istiyorsun?" autocomplete="off">
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
              <p>${escapeHtml(data.answer).replace(/\\*\\*(.+?)\\*\\*/g,"<strong>$1</strong>").replace(/\\n/g,"<br>")}</p>
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
        box.innerHTML=`<div class="error">Arama sırasında bir hata oluştu.</div>`;
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
@rate_limit(20, 60)
@login_required
def api_search():
    q = request.args.get("q", "").strip()

    if not q:
        return jsonify({"error": "q parametresi gerekli"}), 400

    parts = analyze_query(q)
    results = search_everywhere(q, parts)
    images = cse_image_search(extract_target(q, parts), 8)
    answer = synthesize_answer(q, results, parts)

    return jsonify({"query": q, "answer": answer, "results": results, "images": images})

# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()
    base = request.host_url.rstrip("/")
    example = f"{base}/api-key={user['api_key']}?word=merhaba"

    content = f"""
    <main class="container wide">
      <h1 class="page-title">Dashboard</h1>
      <p class="subtitle">
        Hoş geldin, <strong>{html.escape(user["username"])}</strong>.
        API anahtarını buradan yönetebilirsin.
      </p>

      <div class="card">
        <h3>🔑 API anahtarın</h3>
        <div class="api-key-box">{html.escape(user["api_key"])}</div>
        <p>Bu anahtarı gizli tut. Sızarsa aşağıdaki butondan yenileyebilirsin.</p>
        <form method="POST" action="/regenerate-key">
          <button class="btn danger btn-small" type="submit">Anahtarı yenile</button>
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
    try:
        with db_cursor() as cur:
            cur.execute("UPDATE users SET api_key = ? WHERE id = ?", (new_key, user["id"]))
    except Exception as e:
        print(f"[regenerate_key] {e}")
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
      <p class="subtitle">Vantorium kullanım kuralları, API ve gizlilik bilgileri.</p>

      <div class="card">
        <h3>Vantorium nedir?</h3>
        <p>
          Vantorium; Wikipedia, web sayfaları ve yerel bilgi tabanından
          araştırma yaparak uzun, kaynaklı cevaplar hazırlayan; ayrıca
          hazır kod örnekleri sunan bir asistandır.
        </p>
      </div>

      <h2 class="section-title">API</h2>

      <div class="card">
        <p>API kullanım örneği:</p>
        <div class="code-block">{html.escape(base)}/api-key=SENIN_ANAHTARIN?word=merhaba</div>
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
          Sohbet geçmişin yalnızca kendi tarayıcında saklanır.
          Hassas bilgilerini sohbetlere göndermemen önerilir.
        </p>
      </div>

      <div class="footer">© 2026 Vantorium AI</div>
    </main>
    """

    return render_page("Bilgi", content, user)

# =========================================================
# EXTERNAL API
# =========================================================

@app.route("/api-key=<apikey>", methods=["GET"])
@rate_limit(30, 60)
def api_word(apikey):
    word = request.args.get("word", "").strip()

    if not word:
        return jsonify({
            "error": "word parametresi gerekli",
            "usage": "/api-key=...?word=kelime"
        }), 400

    try:
        with db_cursor() as cur:
            user = cur.execute(
                "SELECT * FROM users WHERE api_key = ? AND is_active = 1", (apikey,)
            ).fetchone()
    except Exception:
        user = None

    if not user:
        return jsonify({"error": "Geçersiz API anahtarı"}), 401

    start = time.time()
    answer, source = get_answer(word)

    return jsonify({
        "input": word,
        "answer": answer,
        "meta": {
            "source": source,
            "time_ms": round((time.time() - start) * 1000, 2),
            "engine": "Vantorium Engine 10.0",
            "timestamp": datetime.now().astimezone().isoformat()
        }
    })

# =========================================================
# CODE FILE DOWNLOAD
# =========================================================

@app.route("/download/code/<file_id>")
@login_required
def download_code(file_id):
    data = get_code_file(file_id)
    user = get_current_user()
    # Dosya bir kullanıcıya aitse yalnızca o kullanıcı indirebilir.
    if not data or (data.get("user_id") and user and data["user_id"] != user["id"]):
        return "Dosya bulunamadı veya süresi dolmuş.", 404

    language = data.get("language") or "txt"
    mime_map = {
        "python": "text/x-python", "html": "text/html", "css": "text/css",
        "javascript": "application/javascript", "php": "application/x-httpd-php",
        "sql": "application/sql", "bash": "application/x-sh", "java": "text/x-java-source",
    }
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", data["filename"]) or "kod.txt"

    resp = Response(data["content"].encode("utf-8"), mimetype=mime_map.get(language, "text/plain"))
    resp.headers["Content-Disposition"] = f'attachment; filename="{safe_name}"'
    return resp


@app.before_request
def maybe_cleanup():
    if random.random() < 0.015:
        cleanup_expired()


# =========================================================
# ARAŞTIRMA MOTORU + SOHBET ARAYÜZÜ
# =========================================================

log = logging.getLogger("vantorium.ai")

_G = {}  # app.py'nin globals() sözlüğü
UA = {"User-Agent": "Mozilla/5.0 (compatible; VantoriumBot/2.0)", "Accept-Language": "tr-TR,tr;q=0.9,en;q=0.5"}


# =========================================================
# ÖNBELLEK
# =========================================================

_CACHE = {}


def _cache_get(key):
    hit = _CACHE.get(key)
    if hit and hit[0] > time.time():
        return hit[1]
    return None


def _cache_put(key, value, ttl=3 * 3600):
    if len(_CACHE) > 300:
        now = time.time()
        for k in [k for k, v in _CACHE.items() if v[0] <= now] or list(_CACHE)[:150]:
            _CACHE.pop(k, None)
    _CACHE[key] = (time.time() + ttl, value)


# =========================================================
# METİN İŞLEME (Türkçe)
# =========================================================

_STOP = set(
    "ve veya ile bir bu şu o de da ki mi mı mu mü için gibi çok daha en ama fakat ancak ise olan olarak her hem "
    "ne nasıl neden niçin hangi kadar sonra önce üzere göre kendi bunu şunu onu bunun şunun onun olur oldu "
    "olduğu değil var yok ya yani nedir kimdir demek anlama gelir hakkında bilgi ver anlat açıkla".split()
)
_NOISE = re.compile(
    r"(çerez|cookie|abone ol|bültenimiz|tıklayın|tıklayınız|©|tüm hakları|reklam|giriş yap|üye ol|"
    r"yorum yap|okuma süresi|paylaş|gizlilik politika|kvkk|javascript)",
    re.I,
)
_QPHRASE = re.compile(
    r"\b(nedir|kimdir|kimdi|ne demek|ne anlama gelir|nasıl çalışır|hakkında|bilgi ver|bilgi|anlatır mısın|anlat|"
    r"açıklar mısın|açıkla|detaylı|ayrıntılı|örneklerle|özetle|nasıl|neden|nedenleri|farkı|arasındaki fark)\b",
    re.I,
)


def _lower(text):
    return (text or "").replace("İ", "i").replace("I", "ı").lower()


def _tokens(text):
    return [w[:5] for w in re.findall(r"[a-zçğıöşü0-9]+", _lower(text)) if len(w) > 2 and w not in _STOP]


def _strip_tags(s):
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"(?s)<[^>]+>", " ", s or ""))).strip()


def _clean_topic(q):
    t = _QPHRASE.sub(" ", q or "")
    t = re.sub(r"[?!.,;:\"“”]+", " ", t)
    return re.sub(r"\s+", " ", t).strip() or (q or "").strip()


def _sentences(text, lo=40, hi=380):
    out = []
    for para in re.split(r"\n+", text or ""):
        para = re.sub(r"\s+", " ", para).strip()
        for s in re.split(r"(?<=[.!?…])\s+(?=[\"“'(]?[A-ZÇĞİÖŞÜ0-9])", para):
            s = s.strip()
            if lo <= len(s) <= hi and s[-1:] in ".!?…\"”":
                out.append(s)
    return out


def _domain(url):
    try:
        return urllib.parse.urlparse(url).netloc.replace("www.", "", 1)
    except Exception:
        return ""


# =========================================================
# KAYNAK TOPLAMA: Google CSE + Vikipedi + sayfa okuma
# =========================================================

_SKIP_DOMAINS = ("youtube.com", "youtu.be", "facebook.com", "instagram.com", "twitter.com", "x.com",
                 "tiktok.com", "pinterest.", "linkedin.com", "wikipedia.org")


def _public_url(url):
    try:
        p = urllib.parse.urlparse(url)
        if p.scheme not in ("http", "https") or not p.hostname:
            return False
        return all(ipaddress.ip_address(i[4][0]).is_global for i in socket.getaddrinfo(p.hostname, None))
    except Exception:
        return False


def fetch_page(url):
    """Sayfayı indirip {title, paras, steps} döner; olmazsa None."""
    cached = _cache_get(("page", url))
    if cached is not None:
        return cached or None
    if not _public_url(url) or url.lower().split("?")[0].endswith(".pdf"):
        return None
    raw, enc = b"", None
    try:
        with requests.get(url, headers=UA, timeout=(4, 6), stream=True) as r:
            if r.status_code != 200 or "html" not in r.headers.get("content-type", "").lower():
                _cache_put(("page", url), False, 600)
                return None
            for chunk in r.iter_content(65536):
                raw += chunk
                if len(raw) > 600_000:
                    break
            if r.encoding and r.encoding.lower() != "iso-8859-1":
                enc = r.encoding
    except Exception:
        return None
    if not enc:
        m = re.search(rb"charset=[\"']?([\w-]+)", raw[:3000])
        enc = m.group(1).decode("ascii", "ignore") if m else "utf-8"
    try:
        text = raw.decode(enc, "replace")
    except LookupError:
        text = raw.decode("utf-8", "replace")

    tm = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
    title = _strip_tags(tm.group(1)) if tm else _domain(url)
    body = re.sub(r"(?is)<(script|style|noscript|svg|header|footer|nav|aside|form|iframe|figure)\b.*?</\1>", " ", text)

    steps = []
    for ol in re.finditer(r"(?is)<ol\b[^>]*>(.*?)</ol>", body):
        items = [_strip_tags(x) for x in re.findall(r"(?is)<li\b[^>]*>(.*?)</li>", ol.group(1))]
        items = [x for x in items if 15 <= len(x) <= 260 and not _NOISE.search(x)]
        if 3 <= len(items) <= 15:
            steps.append(items)
    paras = []
    for m in re.finditer(r"(?is)<(p|li)\b[^>]*>(.*?)</\1>", body):
        t = _strip_tags(m.group(2))
        if len(t) >= 60 and not _NOISE.search(t):
            paras.append(t)
    page = {"url": url, "title": title[:120], "paras": paras[:80], "steps": steps}
    _cache_put(("page", url), page)
    return page


def wiki_article(title):
    """Vikipedi makalesini (başlık, [(bölüm, metin)]) olarak döner."""
    cached = _cache_get(("wiki", title))
    if cached is not None:
        return cached or None
    try:
        r = requests.get(
            "https://tr.wikipedia.org/w/api.php",
            params={"action": "query", "prop": "extracts", "explaintext": 1, "redirects": 1,
                    "titles": title, "format": "json", "utf8": 1},
            headers=UA, timeout=7,
        )
        page = next(iter(r.json()["query"]["pages"].values()))
        extract = page.get("extract", "")[:70000]
        real = page.get("title", title)
    except Exception:
        return None
    if len(extract) < 300:
        _cache_put(("wiki", title), False, 600)
        return None
    skip = {"kaynakça", "dış bağlantılar", "notlar", "ayrıca bakınız", "kaynaklar", "dipnotlar", "ileri okuma",
            "bibliyografya", "harici bağlantılar"}
    chunks = re.split(r"\n(={2,4})\s*(.+?)\s*\1\s*\n", extract)
    sections = [("Genel bakış", chunks[0])]
    for i in range(1, len(chunks) - 2, 3):
        if _lower(chunks[i + 1]) not in skip and len(chunks[i + 2]) > 80:
            sections.append((chunks[i + 1], chunks[i + 2]))
    result = (real, sections)
    _cache_put(("wiki", title), result)
    return result


def gather(query, parts, max_pages=3, timeout=7.5):
    """Paralel arama: web sonuçları, Vikipedi makalesi ve en iyi sayfaların metni."""
    G = _G
    key = ("gather", G["normalize"](query), max_pages)
    cached = _cache_get(key)
    if cached is not None:
        return cached

    sq = G["make_search_query"](query, parts)
    topic = _clean_topic(G["extract_target"](query, parts))
    ex = ThreadPoolExecutor(max_workers=6)
    try:
        f_web = ex.submit(G["cse_search"], sq, "web", 8)
        f_wiki = ex.submit(G["wikipedia_search"], topic, 3)
        wait([f_web, f_wiki], timeout=timeout)
        web = f_web.result() if f_web.done() and not f_web.exception() else []
        hits = f_wiki.result() if f_wiki.done() and not f_wiki.exception() else []

        qt = set(_tokens(topic))
        title = None
        for h in hits:
            if qt & set(_tokens(h.get("title", ""))):
                title = h["title"]
                break
        page_urls = [r["url"] for r in web if r.get("url") and not any(d in r["url"].lower() for d in _SKIP_DOMAINS)][:max_pages]

        f_art = ex.submit(wiki_article, title) if title else None
        f_pages = [ex.submit(fetch_page, u) for u in page_urls]
        wait(([f_art] if f_art else []) + f_pages, timeout=6.5)
        article = f_art.result() if f_art and f_art.done() and not f_art.exception() else None
        pages = [f.result() for f in f_pages if f.done() and not f.exception() and f.result()]
    finally:
        ex.shutdown(wait=False, cancel_futures=True)

    bundle = {"topic": topic, "web": web, "wiki": article, "pages": pages, "wiki_title": title}
    if web or article:
        _cache_put(key, bundle, 1800)
    return bundle


# =========================================================
# ÖZETLEME: puanlama + MMR
# =========================================================

def _build_corpus(bundle, sources):
    """Cümle havuzu üretir; kaynakları ortak `sources` listesine ekler (1 tabanlı numaralama)."""
    items = []

    def add_source(title, url):
        for i, s in enumerate(sources, 1):
            if s["url"] == url:
                return i
        sources.append({"title": title, "url": url, "domain": _domain(url)})
        return len(sources)

    if bundle.get("wiki"):
        title, sections = bundle["wiki"]
        sid = add_source(title + " — Vikipedi", "https://tr.wikipedia.org/wiki/" + urllib.parse.quote(title.replace(" ", "_")))
        for si, (heading, text) in enumerate(sections):
            for pos, s in enumerate(_sentences(text)[:40]):
                items.append({"text": s, "src": sid, "sec": heading, "sec_i": si, "pos": pos, "kind": "wiki"})
    used = set()
    for page in bundle.get("pages", []):
        sid = add_source(page["title"], page["url"])
        used.add(page["url"])
        pos = 0
        for p in page["paras"]:
            for s in _sentences(p):
                items.append({"text": s, "src": sid, "sec": "web", "sec_i": 0, "pos": pos, "kind": "web"})
                pos += 1
    for r in bundle.get("web", []):
        if r.get("url") in used or not r.get("url"):
            continue
        sents = _sentences(_G["clean_snippet"](r.get("snippet", ""), 600), lo=30)
        if sents:
            sid = add_source(r.get("title") or _domain(r["url"]), r["url"])
            for pos, s in enumerate(sents):
                items.append({"text": s, "src": sid, "sec": "web", "sec_i": 0, "pos": pos, "kind": "web"})
    return items[:800]


def _rank(items, qterms):
    toks = [set(_tokens(it["text"])) for it in items]
    n = len(items)
    df = Counter(t for s in toks for t in s)
    idf = lambda t: math.log(1 + n / (1 + df.get(t, 0)))
    qmax = sum(idf(t) for t in qterms) or 1.0
    cent = [0.0] * n
    for i in range(n):
        a = toks[i]
        if not a:
            continue
        for j in range(i + 1, n):
            inter = len(a & toks[j])
            if inter:
                sim = inter / len(a | toks[j])
                cent[i] += sim
                cent[j] += sim
    cmax = max(cent) or 1.0
    for i, it in enumerate(items):
        it["toks"] = toks[i]
        it["qs"] = sum(idf(t) for t in qterms if t in toks[i]) / qmax
        score = 1.2 * it["qs"] + 0.5 * cent[i] / cmax + 0.15 / it["src"]
        if it["kind"] == "wiki":
            score += 0.25
        if it["pos"] < 2:
            score += 0.15
        if not 60 <= len(it["text"]) <= 320:
            score -= 0.2
        if _NOISE.search(it["text"]):
            score -= 1.0
        it["score"] = score
    return sorted(items, key=lambda x: -x["score"])


def _mmr(ranked, k):
    pool, sel = list(ranked[:140]), []
    while pool and len(sel) < k:
        best, bv = None, -9.0
        for it in pool:
            sim = max((len(it["toks"] & s["toks"]) / max(1, len(it["toks"] | s["toks"])) for s in sel), default=0.0)
            v = it["score"] - 0.9 * sim
            if v > bv:
                best, bv = it, v
        sel.append(best)
        pool.remove(best)
    return sel


def _cites(items):
    return " " + "".join(f"[{n}]" for n in sorted({it["src"] for it in items}))


def _write(items, qterms, k, level="##", intro_lead=False, local_fact=None, steps=None):
    """Seçilen cümlelerden başlıklı markdown cevap yazar. (markdown, ilk_cümle) döner."""
    if not items:
        return None
    ranked = [it for it in _rank(items, qterms) if it["kind"] == "wiki" or it["qs"] > 0]
    if sum(1 for it in ranked if it["qs"] > 0) < 2 and not local_fact:
        return None
    chosen = _mmr(ranked, k)
    if not chosen:
        return None

    lead = []
    if intro_lead:
        lead = [it for it in items if it["kind"] == "wiki" and it["sec_i"] == 0][:2]
    if not lead:
        lead = sorted(chosen[:2], key=lambda x: (x["src"], x["pos"]))
    lead_text = " ".join(it["text"] for it in lead)
    if local_fact:
        lead_text = local_fact + " " + (lead[0]["text"] if lead else "")
    out = [f"{level} Kısa cevap", "", lead_text.strip() + _cites(lead), ""]

    rest = [it for it in chosen if all(it is not l for l in lead)]
    groups = {}
    for it in rest:
        key = (0, it["sec_i"], it["sec"]) if it["kind"] == "wiki" else (1, 0, "web")
        groups.setdefault(key, []).append(it)
    has_wiki = any(k0[0] == 0 for k0 in groups)
    for key in sorted(groups):
        heading = key[2] if key[0] == 0 else ("Kaynaklardan ek bilgiler" if has_wiki else "Ayrıntılar")
        out += [f"{level} {heading}", ""]
        grp = sorted(groups[key], key=lambda x: (x["src"], x["pos"]))
        for i in range(0, len(grp), 3):
            chunk = grp[i:i + 3]
            out += [" ".join(it["text"] for it in chunk) + _cites(chunk), ""]

    if steps:
        out += [f"{level} Adım adım", ""]
        out += [f"{i}. {s}" for i, s in enumerate(steps[0][:10], 1)]
        out.append(f" [{steps[1]}]")
        out.append("")
    first = re.sub(r"\s+", " ", lead[0]["text"] if lead else chosen[0]["text"])
    return "\n".join(out).rstrip() + "\n", first


# =========================================================
# ARAŞTIRMA AKIŞI
# =========================================================

_CMP = re.compile(
    r"^(.+?)\s+(?:ile|ve|vs\.?|mı|mi|mu|mü)\s+(.+?)\s+(?:arasındaki\s+)?(?:fark\w*|karşılaştır\w*|hangisi\w*)\b.*$", re.I)
_CMP2 = re.compile(r"^(.+?)\s+vs\.?\s+(.+)$", re.I)
_DETAIL_RE = re.compile(r"^(devam|daha (fazla|detaylı|ayrıntılı|uzun)|detaylandır|ayrıntılandır|biraz daha|genişlet|uzat)\b")
_PRON_RE = re.compile(r"^(peki|ya |bunu|onu|bunun|onun|şunu|şunun|bunlar|bu |o )")


def _contextualize(query, history):
    """Devam sorularını önceki konuyla birleştirir. (sorgu, derinlik) döner."""
    q = _G["normalize"](query)
    prev = None
    for m in reversed(history or []):
        if m["role"] == "user" and not _DETAIL_RE.match(_G["normalize"](m["content"])):
            prev = m["content"]
            break
    if not prev:
        return query, 1
    if _DETAIL_RE.match(q):
        return prev, 2
    if len(q.split()) <= 4 and _PRON_RE.match(q):
        return prev + " " + query, 1
    return query, 1


def _split_compare(query):
    m = _CMP.match(query.strip()) or _CMP2.match(query.strip())
    if not m:
        return None
    a, b = (_clean_topic(m.group(1)), _clean_topic(m.group(2)))
    return (a, b) if a and b and _lower(a) != _lower(b) else None


def research_events(query, parts, depth=1):
    """Durum olayları üretir; sonunda ("result", {"md":..., "sources":[...]} | None)."""
    G = _G
    cmp_pair = _split_compare(query)
    yield "status", {"text": "Web'de ve Vikipedi'de araştırıyor…"}

    if cmp_pair:
        with ThreadPoolExecutor(max_workers=2) as ex:
            futs = [ex.submit(gather, e, G["analyze_query"](e), 2) for e in cmp_pair]
            bundles = [f.result() for f in futs]
        yield "status", {"text": "Kaynakları okuyor…"}
        sources, blocks = [], []
        for ent, b in zip(cmp_pair, bundles):
            items = _build_corpus(b, sources)
            res = _write(items, set(_tokens(ent)), 5 * depth + 1, level="###", intro_lead=True)
            blocks.append((ent, res))
        if not all(r for _, r in blocks):
            yield "result", None
            return
        cell = lambda s: re.sub(r"\s+", " ", s).replace("|", "/")[:230]
        md = ["## Karşılaştırma", "", f"| | {cmp_pair[0]} | {cmp_pair[1]} |", "|---|---|---|",
              f"| Kısa tanım | {cell(blocks[0][1][1])} | {cell(blocks[1][1][1])} |", ""]
        for ent, res in blocks:
            md += [f"## {ent}", "", res[0]]
        yield "result", {"md": "\n".join(md), "sources": sources}
        return

    bundle = gather(query, parts)
    yield "status", {"text": "Kaynakları okuyor…"}
    sources = []
    items = _build_corpus(bundle, sources)
    if not items:
        yield "result", None
        return
    yield "status", {"text": "Cevabı derliyor…"}

    topic = bundle["topic"]
    qn = G["normalize"](query)
    qterms = set(_tokens(topic))
    definition = bool(parts.get("is_definition") or re.search(r"\b(nedir|kimdir|ne demek|hakkında|anlat|açıkla)\b", qn)
                      or len(topic.split()) <= 3)
    steps = None
    if "nasıl" in qn and "çalışır" not in qn:
        best = None
        for p in bundle["pages"]:
            for lst in p["steps"]:
                ov = sum(1 for t in _tokens(" ".join(lst)) if t in qterms)
                if best is None or ov > best[0]:
                    best = (ov, lst, p["url"])
        if best and best[0] > 0:
            sid = next((i for i, s in enumerate(sources, 1) if s["url"] == best[2]), 1)
            steps = (best[1], sid)
    local_fact = G["local_knowledge_answer"](query) if definition else None
    res = _write(items, qterms, 9 * depth + 1, intro_lead=definition and bool(bundle["wiki"]),
                 local_fact=local_fact, steps=steps)
    if not res:
        yield "result", None
        return
    md = res[0]
    if depth == 1:
        md += "\n> Daha fazlası için «daha detaylı anlat» yazabilirsin.\n"
    yield "result", {"md": md, "sources": sources}


# =========================================================
# HAZIR KOD ŞABLONLARI
# =========================================================

TEMPLATES = [
    {
        "id": "telegram", "lang": "python", "keys": r"telegram",
        "title": "Telegram botu (Python)",
        "desc": "python-telegram-bot v20+ ile asenkron çalışan bir bot: /start, /yardim, /tekrar ve /id komutları, "
                "düz mesajlara cevap ve hata kaydı içerir.",
        "code": '''
import logging
import os

from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

logging.basicConfig(format="%(asctime)s %(levelname)s %(name)s: %(message)s", level=logging.INFO)
log = logging.getLogger("bot")

TOKEN = os.environ.get("BOT_TOKEN", "")


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ad = update.effective_user.first_name if update.effective_user else "dostum"
    await update.message.reply_text(f"Merhaba {ad}! Komutlar için /yardim yaz.")


async def yardim(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "/start - Botu başlat\\n/yardim - Bu mesaj\\n/tekrar <metin> - Yazdığını tekrarlar\\n/id - Sohbet kimliğin"
    )


async def tekrar(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    metin = " ".join(context.args)
    await update.message.reply_text(metin or "Kullanım: /tekrar merhaba")


async def kimlik(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(f"Sohbet ID: {update.effective_chat.id}")


async def mesaj(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(f"Şunu yazdın: {update.message.text}")


async def hata(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    log.error("Beklenmeyen hata", exc_info=context.error)


def main() -> None:
    if not TOKEN:
        raise SystemExit("BOT_TOKEN ortam değişkenini ayarla (BotFather'dan alınır).")
    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("yardim", yardim))
    app.add_handler(CommandHandler("tekrar", tekrar))
    app.add_handler(CommandHandler("id", kimlik))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, mesaj))
    app.add_error_handler(hata)
    log.info("Bot çalışıyor…")
    app.run_polling()


if __name__ == "__main__":
    main()
''',
        "setup": ["Telegram'da @BotFather'a /newbot yaz ve verdiği token'ı kopyala.",
                  "`pip install python-telegram-bot` komutuyla kütüphaneyi kur.",
                  "Token'ı ortam değişkeni yap: `export BOT_TOKEN=123:ABC` (Windows: `set BOT_TOKEN=123:ABC`).",
                  "`python bot.py` ile çalıştır ve botuna /start yaz."],
        "ideas": ["Kullanıcıları SQLite'ta saklayıp kişisel selamlama ekle.",
                  "InlineKeyboardMarkup ile butonlu menüler yap.",
                  "Zamanlı hatırlatma için `app.job_queue.run_repeating` kullan."],
    },
    {
        "id": "discord", "lang": "python", "keys": r"discord",
        "title": "Discord botu (Python)",
        "desc": "discord.py 2.x ile prefix komutlu bot: !ping, !yardim ve yetki kontrollü !temizle komutu var.",
        "code": '''
import logging
import os

import discord
from discord.ext import commands

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("bot")

TOKEN = os.environ.get("DISCORD_TOKEN", "")

intents = discord.Intents.default()
intents.message_content = True  # Developer Portal'da "Message Content Intent" açık olmalı
bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)


@bot.event
async def on_ready():
    log.info("Giriş yapıldı: %s", bot.user)


@bot.command(name="ping")
async def ping(ctx: commands.Context):
    await ctx.send(f"Pong! {round(bot.latency * 1000)} ms")


@bot.command(name="yardim")
async def yardim(ctx: commands.Context):
    embed = discord.Embed(title="Komutlar", color=0x2DD4A7)
    embed.add_field(name="!ping", value="Gecikmeyi gösterir", inline=False)
    embed.add_field(name="!temizle [adet]", value="Son mesajları siler (yetki gerekir)", inline=False)
    await ctx.send(embed=embed)


@bot.command(name="temizle")
@commands.has_permissions(manage_messages=True)
async def temizle(ctx: commands.Context, adet: int = 5):
    silinen = await ctx.channel.purge(limit=min(max(adet, 1), 100) + 1)
    await ctx.send(f"{len(silinen) - 1} mesaj silindi.", delete_after=5)


@bot.event
async def on_command_error(ctx: commands.Context, error: commands.CommandError):
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("Bu komut için yetkin yok.")
    elif not isinstance(error, commands.CommandNotFound):
        log.error("Komut hatası", exc_info=error)
        await ctx.send("Bir hata oluştu.")


if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("DISCORD_TOKEN ortam değişkenini ayarla.")
    bot.run(TOKEN)
''',
        "setup": ["discord.com/developers adresinde uygulama ve bot oluştur, token'ı kopyala.",
                  "Bot sayfasında **Message Content Intent** seçeneğini aç.",
                  "`pip install discord.py` ile kur, `DISCORD_TOKEN` ortam değişkenini ayarla.",
                  "OAuth2 → URL Generator'dan `bot` kapsamıyla sunucuna davet et, sonra `python bot.py` çalıştır."],
        "ideas": ["Slash komutları için `bot.tree.command` ekle.",
                  "Yeni üyeye `on_member_join` ile karşılama mesajı gönder.",
                  "Seviye/puan sistemi için SQLite kullan."],
    },
    {
        "id": "scraper", "lang": "python", "keys": r"scraper|scraping|web kazı|kazıma|veri çek|site(den|den) veri",
        "title": "Web scraper (Python)",
        "desc": "requests + BeautifulSoup ile sayfadaki bağlantıları ve başlıkları toplayıp CSV'ye yazan, "
                "zaman aşımı ve hata yönetimi olan örnek.",
        "code": '''
import csv
import sys
import time

import requests
from bs4 import BeautifulSoup

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; VeriBot/1.0)"}


def sayfa_indir(url: str) -> str:
    cevap = requests.get(url, headers=HEADERS, timeout=10)
    cevap.raise_for_status()
    return cevap.text


def ayikla(html: str, taban: str) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")
    satirlar = []
    for a in soup.select("a[href]"):
        metin = a.get_text(strip=True)
        if metin:
            satirlar.append({"baslik": metin, "baglanti": requests.compat.urljoin(taban, a["href"])})
    return satirlar


def kaydet(satirlar: list[dict], dosya: str = "sonuc.csv") -> None:
    with open(dosya, "w", newline="", encoding="utf-8") as f:
        yazici = csv.DictWriter(f, fieldnames=["baslik", "baglanti"])
        yazici.writeheader()
        yazici.writerows(satirlar)


def main() -> None:
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    try:
        satirlar = ayikla(sayfa_indir(url), url)
    except requests.RequestException as e:
        raise SystemExit(f"İstek başarısız: {e}")
    kaydet(satirlar)
    print(f"{len(satirlar)} kayıt sonuc.csv dosyasına yazıldı.")
    time.sleep(1)  # siteye nazik davran


if __name__ == "__main__":
    main()
''',
        "setup": ["`pip install requests beautifulsoup4` ile kur.",
                  "`python scraper.py https://site-adresi.com` şeklinde çalıştır.",
                  "Çıktı aynı klasörde `sonuc.csv` olarak oluşur."],
        "ideas": ["Belirli öğeleri almak için `soup.select(\"div.urun h2\")` gibi CSS seçiciler kullan.",
                  "Birden fazla sayfa için döngü ekle ve her istek arasında bekle.",
                  "Sitenin robots.txt ve kullanım şartlarına uy."],
    },
    {
        "id": "password", "lang": "python", "keys": r"(şifre|parola|password).*(üret|oluştur|generat)|(üret|oluştur).*(şifre|parola)",
        "title": "Güvenli şifre üretici (Python)",
        "desc": "`secrets` modülüyle kriptografik olarak güvenli rastgele şifre üretir; uzunluk ve karakter türleri "
                "komut satırından ayarlanır.",
        "code": '''
import argparse
import secrets
import string


def sifre_uret(uzunluk: int = 16, sembol: bool = True) -> str:
    havuz = string.ascii_letters + string.digits + (string.punctuation if sembol else "")
    while True:
        sifre = "".join(secrets.choice(havuz) for _ in range(uzunluk))
        # En az bir küçük, büyük harf ve rakam içermesini garanti et
        if (any(c.islower() for c in sifre) and any(c.isupper() for c in sifre)
                and any(c.isdigit() for c in sifre)):
            return sifre


def main() -> None:
    ap = argparse.ArgumentParser(description="Güvenli şifre üretici")
    ap.add_argument("-u", "--uzunluk", type=int, default=16, help="Şifre uzunluğu (en az 8)")
    ap.add_argument("-a", "--adet", type=int, default=1, help="Kaç şifre üretilsin")
    ap.add_argument("--sembolsuz", action="store_true", help="Özel karakter kullanma")
    args = ap.parse_args()
    if args.uzunluk < 8:
        raise SystemExit("Uzunluk en az 8 olmalı.")
    for _ in range(args.adet):
        print(sifre_uret(args.uzunluk, not args.sembolsuz))


if __name__ == "__main__":
    main()
''',
        "setup": ["Dosyayı `sifre.py` olarak kaydet (ek kütüphane gerekmez).",
                  "`python sifre.py` ile 16 karakterlik şifre al.",
                  "`python sifre.py -u 24 -a 5 --sembolsuz` gibi seçeneklerle özelleştir."],
        "ideas": ["Sonucu panoya kopyalamak için `pyperclip` ekle.",
                  "Okunabilir parolalar için kelime listesinden `secrets.choice` ile seçim yap."],
    },
    {
        "id": "organizer", "lang": "python", "keys": r"dosya.*(düzenle|sırala|organiz|ayır)|organizer",
        "title": "Dosya düzenleyici (Python)",
        "desc": "Bir klasördeki dosyaları uzantısına göre alt klasörlere taşır. Önce `--dene` ile ne yapacağını "
                "gösterir, hiçbir şey silmez.",
        "code": '''
import argparse
import shutil
from pathlib import Path

KATEGORILER = {
    "Resimler": {".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg"},
    "Belgeler": {".pdf", ".doc", ".docx", ".txt", ".xlsx", ".pptx", ".csv"},
    "Videolar": {".mp4", ".mkv", ".avi", ".mov"},
    "Müzik": {".mp3", ".wav", ".flac"},
    "Arşivler": {".zip", ".rar", ".7z", ".tar", ".gz"},
    "Kodlar": {".py", ".js", ".html", ".css", ".json"},
}


def kategori(uzanti: str) -> str:
    for ad, uzantilar in KATEGORILER.items():
        if uzanti.lower() in uzantilar:
            return ad
    return "Diğer"


def duzenle(klasor: Path, dene: bool) -> None:
    for dosya in sorted(klasor.iterdir()):
        if not dosya.is_file():
            continue
        hedef_klasor = klasor / kategori(dosya.suffix)
        hedef = hedef_klasor / dosya.name
        sayac = 1
        while hedef.exists():  # aynı isim varsa üzerine yazma
            hedef = hedef_klasor / f"{dosya.stem}_{sayac}{dosya.suffix}"
            sayac += 1
        print(f"{dosya.name} -> {hedef_klasor.name}/")
        if not dene:
            hedef_klasor.mkdir(exist_ok=True)
            shutil.move(str(dosya), str(hedef))


def main() -> None:
    ap = argparse.ArgumentParser(description="Dosyaları türüne göre düzenler")
    ap.add_argument("klasor", type=Path, help="Düzenlenecek klasör")
    ap.add_argument("--dene", action="store_true", help="Sadece ne yapılacağını göster")
    args = ap.parse_args()
    if not args.klasor.is_dir():
        raise SystemExit("Geçerli bir klasör ver.")
    duzenle(args.klasor, args.dene)


if __name__ == "__main__":
    main()
''',
        "setup": ["Dosyayı `duzenle.py` olarak kaydet (ek kütüphane gerekmez).",
                  "Önce deneme: `python duzenle.py ~/Downloads --dene`.",
                  "Çıktıdan memnunsan `--dene` olmadan çalıştır."],
        "ideas": ["Dosyaları tarihe göre (`YYYY-MM`) klasörlemek için `dosya.stat().st_mtime` kullan.",
                  "Değişiklikleri bir log dosyasına yazıp geri alma özelliği ekle."],
    },
    {
        "id": "flaskapi", "lang": "python", "keys": r"\b(flask|rest api|api|crud|backend)\b",
        "title": "Flask REST API + SQLite (görev listesi)",
        "desc": "Görev ekleme, listeleme, güncelleme ve silme (CRUD) uçları olan küçük bir REST API. "
                "Veriler SQLite'ta tutulur ve girdiler doğrulanır.",
        "code": '''
import os
import sqlite3

from flask import Flask, g, jsonify, request

app = Flask(__name__)
DB = os.environ.get("DB_PATH", "gorevler.db")


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def kapat(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def tablo_olustur() -> None:
    with sqlite3.connect(DB) as c:
        c.execute(
            "CREATE TABLE IF NOT EXISTS gorevler ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, baslik TEXT NOT NULL, "
            "tamam INTEGER NOT NULL DEFAULT 0, olusturma TEXT DEFAULT CURRENT_TIMESTAMP)"
        )


def gorev_json(row: sqlite3.Row) -> dict:
    return {"id": row["id"], "baslik": row["baslik"], "tamam": bool(row["tamam"]), "olusturma": row["olusturma"]}


@app.get("/gorevler")
def listele():
    rows = get_db().execute("SELECT * FROM gorevler ORDER BY id DESC").fetchall()
    return jsonify([gorev_json(r) for r in rows])


@app.post("/gorevler")
def ekle():
    veri = request.get_json(silent=True) or {}
    baslik = str(veri.get("baslik", "")).strip()
    if not baslik or len(baslik) > 200:
        return jsonify(hata="baslik gerekli (en fazla 200 karakter)"), 400
    db = get_db()
    cur = db.execute("INSERT INTO gorevler (baslik) VALUES (?)", (baslik,))
    db.commit()
    row = db.execute("SELECT * FROM gorevler WHERE id = ?", (cur.lastrowid,)).fetchone()
    return jsonify(gorev_json(row)), 201


@app.put("/gorevler/<int:gid>")
def guncelle(gid: int):
    veri = request.get_json(silent=True) or {}
    db = get_db()
    row = db.execute("SELECT * FROM gorevler WHERE id = ?", (gid,)).fetchone()
    if row is None:
        return jsonify(hata="bulunamadı"), 404
    baslik = str(veri.get("baslik", row["baslik"])).strip() or row["baslik"]
    tamam = int(bool(veri.get("tamam", row["tamam"])))
    db.execute("UPDATE gorevler SET baslik = ?, tamam = ? WHERE id = ?", (baslik, tamam, gid))
    db.commit()
    return jsonify(gorev_json(db.execute("SELECT * FROM gorevler WHERE id = ?", (gid,)).fetchone()))


@app.delete("/gorevler/<int:gid>")
def sil(gid: int):
    db = get_db()
    cur = db.execute("DELETE FROM gorevler WHERE id = ?", (gid,))
    db.commit()
    return ("", 204) if cur.rowcount else (jsonify(hata="bulunamadı"), 404)


tablo_olustur()

if __name__ == "__main__":
    app.run(port=int(os.environ.get("PORT", 5000)), debug=False)
''',
        "setup": ["`pip install flask` ile kur ve dosyayı `api.py` olarak kaydet.",
                  "`python api.py` ile başlat.",
                  "Dene: `curl -X POST localhost:5000/gorevler -H \"Content-Type: application/json\" -d '{\"baslik\":\"Süt al\"}'`",
                  "Listele: `curl localhost:5000/gorevler`"],
        "ideas": ["API anahtarı veya JWT ile uçları koru.",
                  "Sayfalama için `?limit=` ve `?offset=` parametreleri ekle.",
                  "Canlıya alırken `gunicorn api:app` kullan."],
    },
    {
        "id": "todo", "lang": "html", "keys": r"(yapılacak|todo|to-do|görev listesi|not defteri)",
        "title": "Yapılacaklar listesi (HTML + CSS + JavaScript)",
        "desc": "Tek dosyalık, mobil uyumlu görev listesi: ekleme, tamamlama, silme, filtreleme. Veriler tarayıcıda "
                "(localStorage) saklanır.",
        "code": '''
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Yapılacaklar</title>
<style>
:root{--bg:#10151b;--panel:#18202a;--line:#273140;--text:#e9eef4;--muted:#8d9bab;--accent:#4cc9a0}
*{box-sizing:border-box;margin:0}
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:grid;place-items:start center;padding:40px 16px}
main{width:min(520px,100%)}
h1{font-size:28px;margin-bottom:18px}
form{display:flex;gap:8px;margin-bottom:16px}
input[type=text]{flex:1;padding:12px 14px;border-radius:12px;border:1px solid var(--line);background:var(--panel);color:var(--text);font-size:16px}
button{padding:12px 16px;border:0;border-radius:12px;background:var(--accent);color:#06241b;font-weight:700;cursor:pointer}
.filters{display:flex;gap:8px;margin-bottom:12px}
.filters button{background:var(--panel);color:var(--muted);border:1px solid var(--line);padding:7px 12px;font-weight:500}
.filters button.on{color:var(--text);border-color:var(--accent)}
ul{list-style:none;padding:0;display:grid;gap:8px}
li{display:flex;align-items:center;gap:10px;padding:12px 14px;background:var(--panel);border:1px solid var(--line);border-radius:12px}
li span{flex:1;overflow-wrap:anywhere}
li.done span{text-decoration:line-through;color:var(--muted)}
li button{background:none;color:var(--muted);padding:4px 8px}
.empty,.count{color:var(--muted);font-size:14px;margin-top:12px}
</style>
</head>
<body>
<main>
  <h1>Yapılacaklar</h1>
  <form id="form"><input id="text" type="text" placeholder="Yeni görev…" maxlength="200" required><button>Ekle</button></form>
  <div class="filters" id="filters"></div>
  <ul id="list"></ul>
  <p class="count" id="count"></p>
</main>
<script>
let todos = [], filter = "hepsi";
try { todos = JSON.parse(localStorage.getItem("todos") || "[]"); } catch (e) {}
const save = () => { try { localStorage.setItem("todos", JSON.stringify(todos)); } catch (e) {} };

function render() {
  const shown = todos.filter(t => filter === "hepsi" || (filter === "aktif" ? !t.done : t.done));
  const list = document.getElementById("list");
  list.innerHTML = "";
  shown.forEach(t => {
    const li = document.createElement("li");
    li.className = t.done ? "done" : "";
    const cb = document.createElement("input");
    cb.type = "checkbox"; cb.checked = t.done;
    cb.onchange = () => { t.done = cb.checked; save(); render(); };
    const span = document.createElement("span");
    span.textContent = t.text;           // textContent: XSS'e karşı güvenli
    const del = document.createElement("button");
    del.textContent = "Sil"; del.setAttribute("aria-label", "Görevi sil");
    del.onclick = () => { todos = todos.filter(x => x.id !== t.id); save(); render(); };
    li.append(cb, span, del);
    list.append(li);
  });
  document.getElementById("count").textContent = todos.filter(t => !t.done).length + " görev kaldı";
  const f = document.getElementById("filters");
  f.innerHTML = "";
  ["hepsi", "aktif", "biten"].forEach(name => {
    const b = document.createElement("button");
    b.textContent = name[0].toUpperCase() + name.slice(1);
    b.className = filter === name ? "on" : "";
    b.onclick = () => { filter = name; render(); };
    f.append(b);
  });
}

document.getElementById("form").addEventListener("submit", e => {
  e.preventDefault();
  const input = document.getElementById("text");
  const text = input.value.trim();
  if (!text) return;
  todos.unshift({ id: Date.now(), text, done: false });
  input.value = "";
  save(); render();
});
render();
</script>
</body>
</html>
''',
        "setup": ["Kodu `index.html` olarak kaydet.", "Dosyaya çift tıkla; tarayıcıda açılır, sunucu gerekmez."],
        "ideas": ["Sürükle-bırak ile sıralama ekle.", "Görevlere son tarih ve hatırlatma ekle.",
                  "Verileri bir API'ye göndererek cihazlar arası senkronla."],
    },
    {
        "id": "portfolio", "lang": "html", "keys": r"(web sitesi|website|portfolyo|portfolio|landing|açılış sayfası|kişisel site|site tasarla|html sayfa)",
        "title": "Portfolyo web sitesi (HTML + CSS + JavaScript)",
        "desc": "Mobil uyumlu, tek dosyalık koyu temalı portfolyo: sabit menü, tanıtım alanı, proje kartları, "
                "hakkımda ve iletişim bölümleri.",
        "code": '''
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ad Soyad — Portfolyo</title>
<style>
:root{--bg:#0f1419;--panel:#171e26;--line:#26313d;--text:#e8edf2;--muted:#93a1b1;--accent:#4cc9a0}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--text);line-height:1.65}
a{color:inherit;text-decoration:none}
.wrap{width:min(960px,100% - 32px);margin:0 auto}
header{position:sticky;top:0;z-index:10;background:rgba(15,20,25,.88);backdrop-filter:blur(12px);border-bottom:1px solid var(--line)}
nav{display:flex;justify-content:space-between;align-items:center;height:60px}
nav ul{display:flex;gap:20px;list-style:none;font-size:15px;color:var(--muted)}
nav a:hover{color:var(--text)}
.hero{padding:96px 0 72px}
.hero h1{font-size:clamp(34px,6vw,56px);line-height:1.1;letter-spacing:-1.5px}
.hero p{margin-top:18px;max-width:52ch;color:var(--muted);font-size:18px}
.btn{display:inline-block;margin-top:28px;padding:12px 22px;border-radius:12px;background:var(--accent);color:#06241b;font-weight:700}
section{padding:56px 0;border-top:1px solid var(--line)}
h2{font-size:26px;margin-bottom:22px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px}
.card{padding:20px;background:var(--panel);border:1px solid var(--line);border-radius:16px}
.card h3{font-size:18px;margin-bottom:8px}
.card p{color:var(--muted);font-size:15px}
.tags{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}
.tags span{padding:3px 10px;border:1px solid var(--line);border-radius:999px;font-size:13px;color:var(--muted)}
footer{padding:32px 0;border-top:1px solid var(--line);color:var(--muted);font-size:14px}
@media(max-width:600px){nav ul{gap:14px;font-size:14px}.hero{padding:64px 0 48px}}
</style>
</head>
<body>
<header>
  <div class="wrap"><nav>
    <a href="#"><strong>Ad Soyad</strong></a>
    <ul><li><a href="#projeler">Projeler</a></li><li><a href="#hakkimda">Hakkımda</a></li><li><a href="#iletisim">İletişim</a></li></ul>
  </nav></div>
</header>
<main class="wrap">
  <div class="hero">
    <h1>Merhaba, ben Ad Soyad.<br>Web ve yazılım geliştiriciyim.</h1>
    <p>Hızlı, sade ve kullanışlı dijital ürünler tasarlıyorum. Aşağıda seçili işlerimi bulabilirsin.</p>
    <a class="btn" href="#projeler">Projeleri gör</a>
  </div>
  <section id="projeler">
    <h2>Projeler</h2>
    <div class="grid">
      <article class="card"><h3>Proje bir</h3><p>Ne yaptığını ve çözdüğü problemi bir iki cümleyle anlat.</p><div class="tags"><span>Python</span><span>Flask</span></div></article>
      <article class="card"><h3>Proje iki</h3><p>Kullandığın yöntemleri ve elde ettiğin sonucu yaz.</p><div class="tags"><span>JavaScript</span><span>API</span></div></article>
      <article class="card"><h3>Proje üç</h3><p>Canlı bağlantı veya GitHub deposunu ekle.</p><div class="tags"><span>HTML</span><span>CSS</span></div></article>
    </div>
  </section>
  <section id="hakkimda">
    <h2>Hakkımda</h2>
    <p style="max-width:60ch;color:var(--muted)">Kendini, deneyimini ve neye değer verdiğini kısaca anlat. Okuyucu seninle çalışmanın nasıl olacağını görmek ister.</p>
  </section>
  <section id="iletisim">
    <h2>İletişim</h2>
    <a class="btn" style="margin-top:0" href="mailto:ornek@eposta.com">ornek@eposta.com</a>
  </section>
</main>
<footer><div class="wrap">© <span id="yil"></span> Ad Soyad</div></footer>
<script>document.getElementById("yil").textContent = new Date().getFullYear();</script>
</body>
</html>
''',
        "setup": ["Kodu `index.html` olarak kaydet ve tarayıcıda aç.",
                  "Metinleri, renkleri (`:root` değişkenleri) ve e-posta adresini kendine göre değiştir.",
                  "Yayınlamak için dosyayı GitHub Pages, Netlify veya Cloudflare Pages'e yükle."],
        "ideas": ["Proje kartlarına ekran görüntüsü ekle.", "Açık/koyu tema anahtarı ekle.",
                  "İletişim formu için Formspree gibi bir servis bağla."],
    },
]

_ACTION_RE = re.compile(r"\b(yaz|oluştur|hazırla|yap|ver|kodla|geliştir|tasarla|göster|lazım|istiyorum|kodu|kod)\b", re.I)


def match_template(query, parts):
    q = _G["normalize"](query)
    if not (parts.get("is_code_request") or _ACTION_RE.search(q)):
        return None
    found = {lang for lang, pat in _G["CODE_LANG_RE"] if pat.search(query)}
    for tpl in TEMPLATES:
        if not re.search(tpl["keys"], q):
            continue
        if found and tpl["lang"] not in found and not (tpl["lang"] == "html" and found <= {"html", "css", "javascript"}):
            continue
        return tpl
    return None


def template_answer(tpl):
    out = [f"## {tpl['title']}", "", tpl["desc"], "", f"```{tpl['lang']}", tpl["code"].strip("\n"), "```", "",
           "## Kurulum ve çalıştırma", ""]
    out += [f"{i}. {s}" for i, s in enumerate(tpl["setup"], 1)]
    out += ["", "## Geliştirme fikirleri", ""] + [f"- {s}" for s in tpl["ideas"]]
    return "\n".join(out) + "\n"


# =========================================================
# CEVAP AKIŞI
# =========================================================

def _clean_history(raw, limit=12):
    """İstemciden gelen geçmişi güvenli ve dönüşümlü (user/assistant) hâle getirir."""
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw[-limit * 2:]:
        if not isinstance(item, dict):
            continue
        role = "assistant" if item.get("role") == "assistant" else "user"
        text = str(item.get("content", "")).strip()[:4000]
        if not text:
            continue
        if out and out[-1]["role"] == role:
            out[-1]["content"] += "\n\n" + text
        else:
            out.append({"role": role, "content": text})
    return out[-limit:]


def _chunks(text, size=24):
    buf = ""
    for piece in re.split(r"(\s+)", text):
        buf += piece
        if len(buf) >= size:
            yield buf
            buf = ""
    if buf:
        yield buf


def _stream_text(text, source):
    for piece in _chunks(text or ""):
        yield "delta", {"text": piece}
        time.sleep(0.004)
    yield "done", {"source": source}


def answer_events(query, history, uid=None):
    """(olay, veri) çiftleri üretir: status, sources, delta, done."""
    G = _G
    parts = G["analyze_query"](query)
    q_norm = G["normalize"](query)
    dataset = G.get("DATASET", {})

    # 1) Hızlı yerel yollar: selam, sohbet, matematik, riskli istekler, veri seti
    if (parts.get("is_greeting") or parts.get("is_smalltalk") or parts.get("is_math")
            or G["DANGEROUS_CODE_RE"].search(query) or (q_norm in dataset and dataset[q_norm])):
        answer, source = G["get_answer"](query)
        yield from _stream_text(answer, source)
        return

    # 2) Hazır, çalışan kod şablonları
    tpl = match_template(query, parts)
    if tpl:
        yield "status", {"text": "Kodu hazırlıyor…"}
        yield from _stream_text(template_answer(tpl), "kod_sablon")
        return

    # 3) Yaratıcı üretim, öneri, şablonu olmayan kod istekleri
    local = G["local_creative_answer"](query)
    if not local and parts.get("is_recommendation"):
        local = G["recommendation_answer"](query)
    if not local and parts.get("is_code_request"):
        yield "status", {"text": "GitHub'da uygun kod arıyor…"}
        local = G["code_response"](query, user_id=uid)
    if local:
        yield from _stream_text(local[0], local[1])
        return

    # 4) Araştırma: Vikipedi + web sayfaları → uzun, kaynaklı cevap
    topic_query, depth = _contextualize(query, history)
    topic_parts = G["analyze_query"](topic_query)
    result = None
    try:
        for ev, payload in research_events(topic_query, topic_parts, depth):
            if ev == "result":
                result = payload
            else:
                yield ev, payload
    except Exception:
        log.exception("araştırma hatası")

    if result:
        yield "sources", {"items": result["sources"]}
        yield from _stream_text(result["md"], "arastirma")
        return

    # 5) Hiçbir şey bulunamadıysa eski yerel motor
    answer, source = G["get_answer"](topic_query)
    yield from _stream_text(answer, source)


def _sse(event, payload):
    return f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"


# =========================================================
# ROUTE'LAR
# =========================================================

def _read_message():
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip()
    if not message:
        return None, None, (jsonify({"error": "Bir mesaj yazmalısın.", "answer": ""}), 400)
    if len(message) > 6000:
        return None, None, (jsonify({"error": "Mesaj çok uzun (en fazla 6000 karakter).", "answer": ""}), 413)
    return message, _clean_history(data.get("history")), None


def chat_stream_view():
    message, history, err = _read_message()
    if err:
        return err
    user = _G["get_current_user"]()
    uid = user["id"] if user else None

    def gen():
        try:
            for event, payload in answer_events(message, history, uid):
                yield _sse(event, payload)
        except GeneratorExit:
            raise
        except Exception:
            log.exception("stream hatası")
            yield _sse("error", {"message": "Yanıt hazırlanırken sunucuda bir hata oluştu. Tekrar dene."})

    resp = Response(stream_with_context(gen()), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache, no-transform"
    resp.headers["X-Accel-Buffering"] = "no"
    return resp


def api_chat_view():
    """Akış kullanmayan istemciler için (eski /api/chat sözleşmesi korunur)."""
    message, history, err = _read_message()
    if err:
        return err
    user = _G["get_current_user"]()
    uid = user["id"] if user else None
    text, sources, source = [], [], "yerel"
    try:
        for event, payload in answer_events(message, history, uid):
            if event == "delta":
                text.append(payload["text"])
            elif event == "sources":
                sources = payload["items"]
            elif event == "done":
                source = payload.get("source", source)
        answer = "".join(text).strip() or "Boş yanıt oluştu, bir kez daha dener misin?"
        if sources:
            answer += "\n\n## Kaynaklar\n\n" + "\n".join(
                f"{i}. [{s['title']}]({s['url']})" for i, s in enumerate(sources, 1))
        return jsonify({"answer": answer, "source": source})
    except Exception:
        log.exception("api_chat hatası")
        return jsonify({"answer": "Yanıt hazırlanırken sunucuda bir hata oluştu. Lütfen tekrar dene.",
                        "source": "server_error"}), 200


def _js(value):
    return json.dumps(value, ensure_ascii=False).replace("</", "<\\/")


def chat_view():
    user = _G["get_current_user"]()
    mode = {"ai": True, "label": "Vantorium motoru",
            "hint": "Cevaplar Vikipedi, web sayfaları ve yerel bilgi tabanından derleniyor."}
    page = CHAT_HTML.replace("__USER_JSON__", _js(user["username"])).replace("__MODE_JSON__", _js(mode))
    return _G["render_page"]("Sohbet", page, user, show_nav=False)


def register_ai(app, ns):
    """app.py'de: register_ai(app, globals())"""
    global _G
    _G = ns
    rate_limit, login_required = ns["rate_limit"], ns["login_required"]
    routes = [
        ("/chat", "chat", login_required(chat_view), ["GET"]),
        ("/api/chat", "api_chat", rate_limit(12, 60)(login_required(api_chat_view)), ["POST"]),
        ("/api/chat/stream", "api_chat_stream", rate_limit(15, 60)(login_required(chat_stream_view)), ["POST"]),
    ]
    for rule, endpoint, view, methods in routes:
        if endpoint in app.view_functions:
            app.view_functions[endpoint] = view
        else:
            app.add_url_rule(rule, endpoint, view, methods=methods)
    print("[Vantorium AI] motor hazır")


# =========================================================
# SOHBET ARAYÜZÜ
# =========================================================

CHAT_HTML = r"""
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Source+Serif+4:opsz,wght@8..60,400;8..60,600&family=JetBrains+Mono:wght@400;500&display=swap">
<style>
html,body{height:100%;overflow:hidden}
[hidden]{display:none!important}
.vx-shell{--ink:#0c1117;--ink2:#111922;--ink3:#18222d;--line:#243242;--text:#e8eef5;--soft:#c5d0dc;--muted:#8a98aa;--accent:#2dd4a7;--accent-ink:#04211a;--danger:#ff8d9a;
  position:fixed;inset:0;height:100%;height:100dvh;display:grid;grid-template-columns:272px minmax(0,1fr);
  background:var(--ink);color:var(--text);font-family:Inter,system-ui,-apple-system,'Segoe UI',sans-serif;z-index:50}
.vx-shell :focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.vx-shell button{cursor:pointer;color:inherit;background:none;border:0}

/* Kenar çubuğu */
.vx-side{display:flex;flex-direction:column;gap:14px;padding:16px 12px;background:var(--ink2);border-right:1px solid var(--line);min-height:0}
.vx-side-head{display:flex;align-items:center;justify-content:space-between;padding:0 6px}
.vx-brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:16px;letter-spacing:-.3px}
.vx-brand img{width:28px;height:28px;object-fit:contain}
.vx-new{display:flex;align-items:center;gap:9px;padding:11px 13px;border:1px solid var(--line)!important;border-radius:12px;font-size:14px;font-weight:600;color:var(--text)}
.vx-new:hover{background:var(--ink3)}
.vx-side-title{padding:2px 8px;color:var(--muted);font-size:12.5px;font-weight:600}
.vx-list{flex:1;min-height:0;overflow-y:auto;display:flex;flex-direction:column;gap:2px}
.vx-empty{padding:8px;color:var(--muted);font-size:13px;line-height:1.5}
.vx-conv{display:flex;align-items:center;border-radius:10px}
.vx-conv:hover,.vx-conv[aria-current="true"]{background:var(--ink3)}
.vx-conv[aria-current="true"]{box-shadow:inset 2px 0 0 var(--accent)}
.vx-conv-open{flex:1;min-width:0;text-align:left;padding:9px 10px;font-size:13.5px;color:var(--soft);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.vx-conv[aria-current="true"] .vx-conv-open{color:#fff}
.vx-conv-del{width:30px;height:30px;margin-right:4px;border-radius:8px;display:grid;place-items:center;color:var(--muted);opacity:0}
.vx-conv:hover .vx-conv-del,.vx-conv:focus-within .vx-conv-del{opacity:1}
.vx-conv-del:hover{color:var(--danger);background:rgba(255,141,154,.1)}
@media(hover:none){.vx-conv-del{opacity:.7}}
.vx-side-foot{display:grid;gap:2px;padding-top:10px;border-top:1px solid var(--line)}
.vx-side-foot a{padding:9px 10px;border-radius:10px;color:var(--soft);font-size:13.5px}
.vx-side-foot a:hover{background:var(--ink3);color:#fff}

/* Ana alan */
.vx-main{position:relative;display:flex;flex-direction:column;min-width:0;min-height:0;height:100%}
.vx-top{flex:0 0 auto;height:54px;display:flex;align-items:center;gap:8px;padding:0 14px;border-bottom:1px solid var(--line)}
.vx-icon{width:36px;height:36px;border-radius:10px;display:grid;place-items:center;color:var(--soft)}
.vx-icon:hover{background:var(--ink3);color:#fff}
.vx-menu,.vx-close,.vx-scrim{display:none}
.vx-title{flex:1;min-width:0;font-size:14.5px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.vx-mode{display:flex;align-items:center;gap:7px;padding:5px 11px;border:1px solid var(--line);border-radius:999px;font-size:12.5px;color:var(--soft)}
.vx-mode i{width:7px;height:7px;border-radius:50%;background:var(--muted)}
.vx-mode.ai i{background:var(--accent)}
.vx-scroll{flex:1 1 auto;min-height:0;overflow-y:auto;overscroll-behavior:contain;-webkit-overflow-scrolling:touch;scrollbar-width:thin;scrollbar-color:#2b3947 transparent}
.vx-thread{max-width:740px;margin:0 auto;padding:28px 20px 170px}

/* Karşılama */
.vx-welcome{padding-top:7vh}
.vx-welcome h1{font-size:clamp(27px,4.6vw,38px);line-height:1.15;letter-spacing:-1px;font-weight:650}
.vx-welcome p{margin-top:12px;max-width:52ch;color:var(--muted);font-size:15.5px;line-height:1.6}
.vx-chips{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:28px}
.vx-chip{text-align:left;padding:14px 15px;border:1px solid var(--line)!important;border-radius:14px;background:var(--ink2)!important}
.vx-chip:hover{border-color:var(--accent)!important}
.vx-chip b{display:block;font-size:14px;font-weight:650}
.vx-chip span{display:block;margin-top:4px;color:var(--muted);font-size:12.5px;line-height:1.45}

/* Mesajlar */
.vx-msg{margin:0 0 30px}
.vx-msg.user{display:flex;justify-content:flex-end}
.vx-bubble{max-width:84%;padding:10px 15px;background:#1a2736;border:1px solid var(--line);border-radius:18px 18px 4px 18px;font-size:15px;line-height:1.55;white-space:pre-wrap;overflow-wrap:anywhere}
.vx-msg.ai{display:flex;gap:14px}
.vx-avatar{width:28px;height:28px;flex:0 0 28px;margin-top:3px;object-fit:contain}
.vx-body{flex:1;min-width:0}
.vx-prose{font-family:'Source Serif 4',Georgia,'Times New Roman',serif;font-size:16.5px;line-height:1.78;color:#dce5ee;overflow-wrap:anywhere}
.vx-prose>*:first-child{margin-top:0}
.vx-prose p{margin:0 0 15px}
.vx-prose h2,.vx-prose h3,.vx-prose h4{font-family:Inter,system-ui,sans-serif;color:#fff;letter-spacing:-.3px;line-height:1.3;margin:26px 0 10px}
.vx-prose h2{font-size:21px;font-weight:700}
.vx-prose h3{font-size:17.5px;font-weight:650}
.vx-prose h4{font-size:15.5px;font-weight:650}
.vx-prose ul,.vx-prose ol{margin:0 0 16px;padding-left:24px}
.vx-prose li{margin:6px 0;padding-left:2px}
.vx-prose li::marker{color:var(--accent)}
.vx-prose strong{color:#fff;font-weight:600}
.vx-prose a{color:var(--accent);text-decoration:underline;text-underline-offset:3px;text-decoration-thickness:1px}
.vx-prose blockquote{margin:0 0 16px;padding:2px 0 2px 16px;border-left:3px solid var(--line);color:var(--muted)}
.vx-prose hr{border:0;border-top:1px solid var(--line);margin:22px 0}
.vx-prose code{font-family:'JetBrains Mono',ui-monospace,Menlo,Consolas,monospace;font-size:.84em;padding:2px 6px;border-radius:6px;background:var(--ink3);color:#f0d9a8}
.vx-table{overflow-x:auto;margin:0 0 18px;border:1px solid var(--line);border-radius:12px}
.vx-table table{border-collapse:collapse;width:100%;font-family:Inter,system-ui,sans-serif;font-size:14px;line-height:1.5}
.vx-table th,.vx-table td{padding:10px 14px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
.vx-table th{background:var(--ink2);color:#fff;font-weight:600;white-space:nowrap}
.vx-table tr:last-child td{border-bottom:0}
.vx-cite{display:inline-grid;place-items:center;min-width:19px;height:19px;margin:0 2px;padding:0 5px;border-radius:6px!important;background:rgba(45,212,167,.14)!important;color:var(--accent)!important;font:600 11px Inter,sans-serif;vertical-align:2px}
.vx-cite:hover{background:rgba(45,212,167,.28)!important}
.vx-code{margin:4px 0 18px;border:1px solid var(--line);border-radius:12px;overflow:hidden;background:#090e13}
.vx-code-head{display:flex;align-items:center;justify-content:space-between;padding:7px 8px 7px 14px;background:var(--ink2);border-bottom:1px solid var(--line);font:500 12.5px Inter,sans-serif;color:var(--muted)}
.vx-code-head button{display:inline-flex;align-items:center;gap:6px;padding:6px 10px;border-radius:8px;font:500 12.5px Inter,sans-serif;color:var(--soft)}
.vx-code-head button:hover{background:var(--ink3);color:#fff}
.vx-code pre{margin:0;padding:14px 16px;max-height:540px;overflow:auto;font:400 13px/1.68 'JetBrains Mono',ui-monospace,Menlo,Consolas,monospace;color:#e2e9f1;tab-size:4}
.vx-code code{padding:0;background:none;color:inherit;font:inherit;white-space:pre}
.vx-caret{display:inline-block;width:8px;height:1.05em;margin-left:3px;background:var(--accent);vertical-align:-3px;animation:vxBlink 1s steps(2,start) infinite}
@keyframes vxBlink{to{visibility:hidden}}
.vx-status{display:flex;align-items:center;gap:10px;min-height:34px;color:var(--muted);font-size:14px}
.vx-status i{width:6px;height:6px;border-radius:50%;background:var(--accent);animation:vxPulse 1.1s infinite}
.vx-status i:nth-child(2){animation-delay:.15s}.vx-status i:nth-child(3){animation-delay:.3s}
.vx-status span{margin-left:4px}
@keyframes vxPulse{0%,80%,100%{opacity:.25}40%{opacity:1}}
.vx-error{margin:6px 0;padding:12px 14px;border:1px solid rgba(255,141,154,.35);border-radius:12px;background:rgba(255,141,154,.07);color:var(--danger);font-size:14px;line-height:1.5}
.vx-sources{margin-top:16px}
.vx-src-label{margin-bottom:8px;color:var(--muted);font-size:12.5px;font-weight:600}
.vx-src-row{display:flex;flex-wrap:wrap;gap:8px}
.vx-src{display:flex;align-items:center;gap:8px;max-width:100%;padding:7px 11px 7px 8px;border:1px solid var(--line);border-radius:10px;background:var(--ink2);font-size:12.5px;color:var(--soft)}
.vx-src:hover{border-color:var(--accent);color:#fff}
.vx-src b{display:grid;place-items:center;width:19px;height:19px;flex:0 0 19px;border-radius:6px;background:rgba(45,212,167,.14);color:var(--accent);font-size:11px}
.vx-src span{min-width:0;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.vx-src em{font-style:normal;color:var(--muted)}
.vx-actions{display:flex;gap:4px;margin-top:12px}
.vx-actions button{display:inline-flex;align-items:center;gap:6px;padding:6px 10px;border-radius:8px;color:var(--muted);font-size:12.5px}
.vx-actions button:hover{background:var(--ink3);color:#fff}

/* Yazma alanı */
.vx-jump{position:absolute;left:50%;bottom:112px;transform:translateX(-50%);width:36px;height:36px;border-radius:50%!important;display:grid;place-items:center;background:var(--ink3)!important;border:1px solid var(--line)!important;box-shadow:0 6px 20px rgba(0,0,0,.4);z-index:5}
.vx-dock{position:absolute;left:0;right:0;bottom:0;padding:18px 18px calc(12px + env(safe-area-inset-bottom));background:linear-gradient(to top,var(--ink) 64%,rgba(12,17,23,0))}
.vx-composer{max-width:740px;margin:0 auto;display:flex;align-items:flex-end;gap:8px;padding:8px 8px 8px 16px;background:var(--ink3);border:1px solid var(--line);border-radius:20px;box-shadow:0 10px 36px rgba(0,0,0,.35)}
.vx-composer:focus-within{border-color:var(--accent)}
.vx-composer textarea{flex:1;min-width:0;min-height:28px;max-height:180px;padding:7px 0;resize:none;border:0;outline:0;background:transparent;color:var(--text);font:15.5px/1.5 Inter,system-ui,sans-serif}
.vx-composer textarea::placeholder{color:#6f7e91}
.vx-send{width:40px;height:40px;flex:0 0 40px;border-radius:14px!important;display:grid;place-items:center;background:var(--accent)!important;color:var(--accent-ink)!important}
.vx-send:hover{filter:brightness(1.08)}
.vx-send.stop{background:#e8eef5!important;color:#0c1117!important}
.vx-hint{margin-top:9px;text-align:center;color:#63728a;font-size:11.5px}

@media(max-width:860px){
  .vx-shell{grid-template-columns:minmax(0,1fr)}
  .vx-side{position:fixed;inset:0 auto 0 0;width:min(310px,86vw);z-index:70;transform:translateX(-104%);transition:transform .22s ease;box-shadow:12px 0 40px rgba(0,0,0,.5)}
  .vx-shell.open .vx-side{transform:none}
  .vx-scrim{display:block;position:fixed;inset:0;z-index:60;background:rgba(0,0,0,.55);opacity:0;pointer-events:none;transition:opacity .2s}
  .vx-shell.open .vx-scrim{opacity:1;pointer-events:auto}
  .vx-menu,.vx-close{display:grid}
  .vx-thread{padding:20px 14px 160px}
  .vx-msg.ai{gap:10px}
  .vx-avatar{width:24px;height:24px;flex-basis:24px}
  .vx-prose{font-size:16px}
}
@media(max-width:520px){
  .vx-chips{grid-template-columns:1fr}
  .vx-bubble{max-width:90%}
  .vx-mode span{display:none}
  .vx-mode{padding:8px}
}
@media(prefers-reduced-motion:reduce){.vx-shell *{animation:none!important;transition:none!important}}
</style>

<div class="vx-shell" id="shell">
  <aside class="vx-side" id="side" aria-label="Sohbet geçmişi">
    <div class="vx-side-head">
      <a class="vx-brand" href="/chat"><img src="/icon.png" alt="">Vantorium</a>
      <button class="vx-icon vx-close" id="closeSide" type="button" aria-label="Menüyü kapat">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>
      </button>
    </div>
    <button class="vx-new" id="newBtn" type="button">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>
      Yeni sohbet
    </button>
    <div class="vx-side-title">Sohbetler</div>
    <nav class="vx-list" id="convList"></nav>
    <div class="vx-side-foot">
      <a href="/search">Web'de ara</a>
      <a href="/dashboard">API anahtarım</a>
      <a href="/info">Kurallar ve bilgi</a>
      <a href="/logout">Çıkış yap</a>
    </div>
  </aside>
  <div class="vx-scrim" id="scrim"></div>

  <section class="vx-main">
    <header class="vx-top">
      <button class="vx-icon vx-menu" id="openSide" type="button" aria-label="Menüyü aç">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 7h16M4 12h16M4 17h10"/></svg>
      </button>
      <div class="vx-title" id="chatTitle">Yeni sohbet</div>
      <div class="vx-mode" id="modeBadge"><i></i><span></span></div>
      <button class="vx-icon" id="newTop" type="button" aria-label="Yeni sohbet">
        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>
      </button>
    </header>

    <div class="vx-scroll" id="scroll"><div class="vx-thread" id="thread" aria-live="polite"></div></div>
    <button class="vx-jump" id="jump" type="button" aria-label="En alta in" hidden>
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14M5 12l7 7 7-7"/></svg>
    </button>

    <div class="vx-dock">
      <form class="vx-composer" id="composer" autocomplete="off">
        <textarea id="input" rows="1" placeholder="Vantorium'a sor veya kod iste…" aria-label="Mesajın"></textarea>
        <button class="vx-send" id="sendBtn" type="submit" aria-label="Gönder"></button>
      </form>
      <div class="vx-hint">Vantorium hata yapabilir. Önemli bilgileri doğrula.</div>
    </div>
  </section>
</div>

<script>
(() => {
  'use strict';
  const USER = __USER_JSON__;
  const MODE = __MODE_JSON__;
  const $ = id => document.getElementById(id);
  const shell = $('shell'), thread = $('thread'), scroller = $('scroll'), input = $('input');
  const form = $('composer'), sendBtn = $('sendBtn'), jump = $('jump'), listEl = $('convList'), titleEl = $('chatTitle');
  const STORE = 'vantorium.convs.v2:' + USER;
  const coarse = window.matchMedia('(pointer:coarse)').matches;
  let convs = [], active = null, controller = null, streaming = false, stick = true, raf = 0;

  const svg = (d, s) => '<svg width="' + (s || 15) + '" height="' + (s || 15) + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' + d + '</svg>';
  const ICON = {
    copy: svg('<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/>'),
    down: svg('<path d="M12 4v11M7 11l5 5 5-5M5 20h14"/>'),
    redo: svg('<path d="M20 11a8 8 0 1 0-2.3 5.7"/><path d="M20 4v7h-7"/>'),
    x: svg('<path d="M6 6l12 12M18 6L6 18"/>', 15),
    send: svg('<path d="M12 19V5M5 12l7-7 7 7"/>', 20),
    stop: '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><rect x="5" y="5" width="14" height="14" rx="3"/></svg>'
  };

  const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

  /*MD_START*/
  function inline(raw, sources) {
    return raw.split(/(`[^`\n]+`)/g).map((seg, i) => {
      if (i % 2) return '<code>' + esc(seg.slice(1, -1)) + '</code>';
      let s = esc(seg);
      s = s.replace(/\*\*([^*\n]+?)\*\*/g, '<strong>$1</strong>')
           .replace(/(^|[\s(])\*([^*\s][^*\n]*?)\*(?=[\s).,;:!?]|$)/g, '$1<em>$2</em>')
           .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+|\/download\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>')
           .replace(/\[(\d{1,2})\]/g, (m, n) => (sources && sources[n - 1]) ? '<button class="vx-cite" type="button" data-act="cite" data-n="' + n + '">' + n + '</button>' : m);
      return s;
    }).join('');
  }

  function codeHTML(c) {
    return '<div class="vx-code"><div class="vx-code-head"><span>' + esc(c.lang) + '</span><span>' +
      '<button type="button" data-act="copy-code">' + ICON.copy + ' Kopyala</button>' +
      '<button type="button" data-act="dl-code" data-lang="' + esc(c.lang) + '">' + ICON.down + ' İndir</button>' +
      '</span></div><pre><code>' + esc(c.code) + '</code></pre></div>';
  }

  function md(src, sources, streamingNow) {
    const codes = [];
    const text = String(src).replace(/```([\w+#.-]*)[^\S\n]*\n?([\s\S]*?)(```|$)/g, (m, lang, code) => {
      codes.push({lang: lang || 'kod', code: code.replace(/\n$/, '')});
      return '\n\u0000' + (codes.length - 1) + '\u0000\n';
    });
    const lines = text.split('\n'), out = [];
    const HR = /^\s*([-*_])\1{2,}\s*$/;
    const LI = /^\s*([-*•]|\d+[.)])\s+/;
    const SEP = /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/;
    const cells = row => row.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map(c => c.trim());
    const special = l => HR.test(l) || LI.test(l) || /^\s{0,3}#{1,4}\s/.test(l) || /^\s*>/.test(l) || /^\u0000\d+\u0000$/.test(l.trim());
    let i = 0, m;
    while (i < lines.length) {
      const l = lines[i];
      if (!l.trim()) { i++; continue; }
      if ((m = l.trim().match(/^\u0000(\d+)\u0000$/))) { out.push(codeHTML(codes[+m[1]])); i++; continue; }
      if (HR.test(l)) { out.push('<hr>'); i++; continue; }
      if ((m = l.match(/^\s{0,3}(#{1,4})\s+(.*)$/))) {
        const n = Math.min(m[1].length + 1, 4);
        out.push('<h' + n + '>' + inline(m[2], sources) + '</h' + n + '>'); i++; continue;
      }
      if (/^\s*>/.test(l)) {
        const b = [];
        while (i < lines.length && /^\s*>/.test(lines[i])) { b.push(lines[i].replace(/^\s*>\s?/, '')); i++; }
        out.push('<blockquote>' + inline(b.join('\n'), sources).replace(/\n/g, '<br>') + '</blockquote>'); continue;
      }
      if (/^\s*\|/.test(l) && i + 1 < lines.length && SEP.test(lines[i + 1])) {
        const head = cells(l); i += 2; const rows = [];
        while (i < lines.length && /^\s*\|/.test(lines[i])) { rows.push(cells(lines[i])); i++; }
        out.push('<div class="vx-table"><table><thead><tr>' + head.map(c => '<th>' + inline(c, sources) + '</th>').join('') +
          '</tr></thead><tbody>' + rows.map(r => '<tr>' + r.map(c => '<td>' + inline(c, sources) + '</td>').join('') + '</tr>').join('') + '</tbody></table></div>');
        continue;
      }
      if (LI.test(l)) {
        const ordered = /^\s*\d/.test(l);
        const start = ordered ? parseInt(l.match(/^\s*(\d+)/)[1], 10) : 1;
        const items = [];
        while (i < lines.length && LI.test(lines[i])) {
          const indent = Math.min(Math.floor((lines[i].match(/^\s*/)[0].length) / 2), 3);
          items.push({t: lines[i].replace(LI, ''), indent});
          i++;
        }
        out.push((ordered ? '<ol start="' + start + '">' : '<ul>') + items.map(x =>
          '<li' + (x.indent ? ' style="margin-left:' + (x.indent * 16) + 'px"' : '') + '>' + inline(x.t, sources) + '</li>').join('') + (ordered ? '</ol>' : '</ul>'));
        continue;
      }
      const p = [];
      while (i < lines.length && lines[i].trim() && !special(lines[i])) { p.push(lines[i]); i++; }
      if (!p.length) { p.push(lines[i]); i++; }
      out.push('<p>' + inline(p.join('\n'), sources).replace(/\n/g, '<br>') + '</p>');
    }
    let html = out.join('');
    if (streamingNow) {
      const caret = '<span class="vx-caret"></span>';
      html = /<\/(p|li)>(<\/(ul|ol)>)?$/.test(html) ? html.replace(/(<\/(p|li)>)(<\/(ul|ol)>)?$/, caret + '$1$3') : html + caret;
    }
    return html;
  }
  /*MD_END*/

  function sourcesHTML(list) {
    const ok = list.filter(s => /^https?:\/\//i.test(s.url || ''));
    if (!ok.length) return '';
    return '<div class="vx-sources"><div class="vx-src-label">Kaynaklar</div><div class="vx-src-row">' + ok.map((s, i) =>
      '<a class="vx-src" href="' + esc(s.url) + '" target="_blank" rel="noopener noreferrer"><b>' + (i + 1) + '</b><span>' + esc(s.title || s.domain) + '</span><em>' + esc(s.domain || '') + '</em></a>').join('') + '</div></div>';
  }

  function aiHTML(m, isLast) {
    let h = '';
    if (m.pending && !m.content) h += '<div class="vx-status"><i></i><i></i><i></i><span>' + esc(m.status || 'Düşünüyor…') + '</span></div>';
    if (m.content) h += '<div class="vx-prose">' + md(m.content, m.sources, m.pending) + '</div>';
    if (m.error) h += '<div class="vx-error">' + esc(m.error) + '</div>';
    if (m.sources && m.sources.length) h += sourcesHTML(m.sources);
    if (!m.pending) {
      h += '<div class="vx-actions">' + (m.content ? '<button type="button" data-act="copy-msg">' + ICON.copy + ' Kopyala</button>' : '') +
        (isLast ? '<button type="button" data-act="regen">' + ICON.redo + ' Yeniden üret</button>' : '') + '</div>';
    }
    return h;
  }

  const PROMPTS = [
    {t: 'Kod yaz', d: 'Komutları ve kurulum adımları olan Telegram botu', q: 'Python ile komutları, hata yönetimi ve kurulum adımları olan bir Telegram botu yaz'},
    {t: 'Konu araştır', d: 'Yapay zekâ nasıl çalışır? Örneklerle anlat', q: 'Yapay zekâ nasıl çalışır? Ayrıntılı ve örneklerle anlat'},
    {t: 'Web sitesi tasarla', d: 'Mobil uyumlu, tek sayfalık modern portföy', q: 'Mobil uyumlu modern bir portföy web sitesi tasarla, tam HTML, CSS ve JavaScript kodunu ver'},
    {t: 'Öğrenme planı', d: 'Sıfırdan başlayanlar için 30 günde Python', q: 'Bana sıfırdan başlayan biri için 30 günlük bir Python öğrenme planı hazırla'}
  ];

  function welcomeHTML() {
    return '<section class="vx-welcome"><h1>Ne üzerinde çalışalım?</h1>' +
      '<p>Sor, kaynaklarla araştırayım. Kod iste, eksiksiz yazayım. Bir konuyu baştan sona anlatayım.</p><div class="vx-chips">' +
      PROMPTS.map((p, i) => '<button class="vx-chip" type="button" data-act="chip" data-i="' + i + '"><b>' + esc(p.t) + '</b><span>' + esc(p.d) + '</span></button>').join('') +
      '</div></section>';
  }

  function msgHTML(m, i, isLast) {
    if (m.role === 'user') return '<div class="vx-msg user" data-i="' + i + '"><div class="vx-bubble">' + esc(m.content) + '</div></div>';
    return '<article class="vx-msg ai" data-i="' + i + '"><img class="vx-avatar" src="/icon.png" alt=""><div class="vx-body">' + aiHTML(m, isLast) + '</div></article>';
  }

  /* --- Depolama --- */
  function load() {
    try {
      const v = JSON.parse(localStorage.getItem(STORE) || '[]');
      return (Array.isArray(v) ? v : []).map(c => ({
        id: c.id, title: c.title || 'Sohbet', updated: c.updated || 0,
        messages: (c.messages || []).filter(m => m && typeof m.content === 'string').map(m => Object.assign({}, m, {pending: false}))
      }));
    } catch (e) { return []; }
  }
  function save() { try { localStorage.setItem(STORE, JSON.stringify(convs.slice(0, 40))); } catch (e) {} }
  const uid = () => Math.random().toString(36).slice(2, 10);
  const cur = () => convs.find(c => c.id === active);
  function newConv() {
    const empty = convs.find(c => !c.messages.length);
    if (empty) { active = empty.id; return empty; }
    const c = {id: uid(), title: 'Yeni sohbet', messages: [], updated: Date.now()};
    convs.unshift(c); active = c.id; return c;
  }

  /* --- Çizim --- */
  function renderList() {
    const items = convs.filter(c => c.messages.length).sort((a, b) => b.updated - a.updated);
    listEl.innerHTML = items.length ? items.map(c =>
      '<div class="vx-conv"' + (c.id === active ? ' aria-current="true"' : '') + ' data-id="' + c.id + '">' +
      '<button class="vx-conv-open" type="button" data-act="open">' + esc(c.title) + '</button>' +
      '<button class="vx-conv-del" type="button" data-act="del" aria-label="Sohbeti sil">' + ICON.x + '</button></div>').join('')
      : '<p class="vx-empty">Henüz sohbet yok. İlk sorunu sor.</p>';
  }
  function renderThread() {
    const c = cur();
    if (!c || !c.messages.length) { thread.innerHTML = welcomeHTML(); titleEl.textContent = 'Yeni sohbet'; return; }
    titleEl.textContent = c.title;
    thread.innerHTML = c.messages.map((m, i) => msgHTML(m, i, i === c.messages.length - 1)).join('');
  }
  const toBottom = () => { scroller.scrollTop = scroller.scrollHeight; };
  function setBusy(on) {
    sendBtn.classList.toggle('stop', on);
    sendBtn.innerHTML = on ? ICON.stop : ICON.send;
    sendBtn.setAttribute('aria-label', on ? 'Durdur' : 'Gönder');
  }
  function resize() { input.style.height = 'auto'; input.style.height = Math.min(input.scrollHeight, 180) + 'px'; }

  /* --- Gönderme ve akış --- */
  async function send(text) {
    text = (text || '').trim();
    if (!text || streaming) return;
    const c = cur() || newConv();
    const history = c.messages.filter(m => m.content && !m.error).slice(-12)
      .map(m => ({role: m.role === 'ai' ? 'assistant' : 'user', content: m.content.slice(0, 4000)}));
    c.messages.push({role: 'user', content: text});
    const ai = {role: 'ai', content: '', pending: true, status: 'Düşünüyor…', sources: []};
    c.messages.push(ai);
    if (c.messages.length === 2) c.title = text.replace(/\s+/g, ' ').slice(0, 44);
    c.updated = Date.now();
    input.value = ''; resize();
    renderThread(); renderList(); stick = true; toBottom();
    await run(c, ai, text, history);
  }

  async function run(c, ai, text, history) {
    streaming = true; setBusy(true);
    controller = new AbortController();
    const paint = () => {
      if (raf) return;
      raf = requestAnimationFrame(() => {
        raf = 0;
        const b = thread.querySelector('.vx-msg.ai:last-child .vx-body');
        if (b) b.innerHTML = aiHTML(ai, false);
        if (stick) toBottom();
      });
    };
    const handle = raw => {
      let ev = 'message', data = '';
      raw.split('\n').forEach(line => {
        if (line.startsWith('event:')) ev = line.slice(6).trim();
        else if (line.startsWith('data:')) data += line.slice(5).trim();
      });
      if (!data) return;
      let p; try { p = JSON.parse(data); } catch (e) { return; }
      if (ev === 'status') ai.status = p.text;
      else if (ev === 'sources') ai.sources = p.items || [];
      else if (ev === 'delta') ai.content += p.text;
      else if (ev === 'error') ai.error = p.message;
      paint();
    };
    try {
      const res = await fetch('/api/chat/stream', {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json', 'Accept': 'text/event-stream'},
        body: JSON.stringify({message: text, history}), signal: controller.signal
      });
      const type = res.headers.get('content-type') || '';
      if (!type.includes('text/event-stream')) {
        if (res.redirected || type.includes('text/html')) { location.href = '/login'; return; }
        let msg = 'Sunucu hatası (' + res.status + ').';
        try { const j = await res.json(); msg = j.error || msg; } catch (e) {}
        throw new Error(msg);
      }
      const reader = res.body.getReader(), dec = new TextDecoder();
      let buf = '';
      for (;;) {
        const {value, done} = await reader.read();
        if (done) break;
        buf += dec.decode(value, {stream: true});
        let k;
        while ((k = buf.indexOf('\n\n')) >= 0) { const raw = buf.slice(0, k); buf = buf.slice(k + 2); handle(raw); }
      }
    } catch (e) {
      if (e.name !== 'AbortError') ai.error = e.message || 'Bağlantı hatası. İnternetini kontrol edip tekrar dene.';
    } finally {
      if (raf) { cancelAnimationFrame(raf); raf = 0; }
      ai.pending = false;
      if (!ai.content && !ai.error) ai.error = 'Yanıt durduruldu.';
      streaming = false; controller = null; setBusy(false);
      c.updated = Date.now(); save();
      renderThread(); renderList();
      if (stick) toBottom();
      if (!coarse) input.focus();
    }
  }

  function regen() {
    const c = cur();
    if (!c || streaming) return;
    while (c.messages.length && c.messages[c.messages.length - 1].role === 'ai') c.messages.pop();
    const u = c.messages.pop();
    if (u) send(u.content);
  }

  async function copyText(t) {
    try { await navigator.clipboard.writeText(t); }
    catch (e) { const a = document.createElement('textarea'); a.value = t; document.body.appendChild(a); a.select(); document.execCommand('copy'); a.remove(); }
  }
  const EXT = {python: 'py', py: 'py', javascript: 'js', js: 'js', typescript: 'ts', ts: 'ts', html: 'html', css: 'css', php: 'php', sql: 'sql',
    bash: 'sh', sh: 'sh', shell: 'sh', java: 'java', go: 'go', rust: 'rs', json: 'json', c: 'c', cpp: 'cpp', csharp: 'cs', ruby: 'rb', yaml: 'yml'};
  function download(code, lang) {
    const blob = new Blob([code], {type: 'text/plain;charset=utf-8'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'vantorium-kod.' + (EXT[(lang || '').toLowerCase()] || 'txt');
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }
  function flash(btn, label) {
    const old = btn.innerHTML; btn.textContent = label;
    setTimeout(() => { btn.innerHTML = old; }, 1500);
  }

  /* --- Olaylar --- */
  thread.addEventListener('click', async e => {
    const t = e.target.closest('[data-act]');
    if (!t) return;
    const act = t.dataset.act;
    const c = cur();
    if (act === 'chip') send(PROMPTS[+t.dataset.i].q);
    else if (act === 'regen') regen();
    else if (act === 'copy-code') { await copyText(t.closest('.vx-code').querySelector('code').textContent); flash(t, 'Kopyalandı ✓'); }
    else if (act === 'dl-code') download(t.closest('.vx-code').querySelector('code').textContent, t.dataset.lang);
    else if (act === 'copy-msg') { const m = c && c.messages[+t.closest('.vx-msg').dataset.i]; if (m) { await copyText(m.content); flash(t, 'Kopyalandı ✓'); } }
    else if (act === 'cite') {
      const m = c && c.messages[+t.closest('.vx-msg').dataset.i];
      const s = m && m.sources && m.sources[+t.dataset.n - 1];
      if (s && /^https?:\/\//i.test(s.url)) window.open(s.url, '_blank', 'noopener');
    }
  });

  listEl.addEventListener('click', e => {
    const t = e.target.closest('[data-act]'), row = e.target.closest('.vx-conv');
    if (!t || !row || streaming) return;
    if (t.dataset.act === 'open') { active = row.dataset.id; renderThread(); renderList(); stick = true; toBottom(); shell.classList.remove('open'); }
    else if (t.dataset.act === 'del') {
      convs = convs.filter(c => c.id !== row.dataset.id);
      if (active === row.dataset.id) { const next = convs.find(c => c.messages.length); if (next) active = next.id; else newConv(); }
      save(); renderThread(); renderList();
    }
  });

  function startNew() { if (streaming) return; newConv(); renderThread(); renderList(); shell.classList.remove('open'); input.focus(); }
  $('newBtn').addEventListener('click', startNew);
  $('newTop').addEventListener('click', startNew);
  $('openSide').addEventListener('click', () => shell.classList.add('open'));
  $('closeSide').addEventListener('click', () => shell.classList.remove('open'));
  $('scrim').addEventListener('click', () => shell.classList.remove('open'));
  document.addEventListener('keydown', e => { if (e.key === 'Escape') shell.classList.remove('open'); });

  scroller.addEventListener('scroll', () => {
    const near = scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight < 90;
    stick = near; jump.hidden = near;
  }, {passive: true});
  jump.addEventListener('click', () => { stick = true; toBottom(); });

  input.addEventListener('input', resize);
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey && !coarse && !e.isComposing) { e.preventDefault(); form.requestSubmit(); }
  });
  form.addEventListener('submit', e => {
    e.preventDefault();
    if (streaming) { if (controller) controller.abort(); return; }
    send(input.value);
  });

  /* --- Başlat --- */
  const badge = $('modeBadge');
  badge.classList.toggle('ai', !!MODE.ai);
  badge.title = MODE.hint;
  badge.querySelector('span').textContent = MODE.label;
  convs = load();
  const last = convs.filter(c => c.messages.length).sort((a, b) => b.updated - a.updated)[0];
  if (last) active = last.id; else newConv();
  setBusy(false); renderThread(); renderList(); toBottom();
  if (!coarse) input.focus();
})();
</script>
"""


# =========================================================
# SOHBET ROTALARINI AKTİF ET
# =========================================================

register_ai(app, globals())

# =========================================================
# START
# =========================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    print(f"[Vantorium] DB path : {DB_FILE}")
    print(f"[Vantorium] Code dir: {CODE_FILES_DIR}")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)

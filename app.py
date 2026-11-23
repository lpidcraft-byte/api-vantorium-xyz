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
import tempfile
import uuid
from datetime import datetime, timedelta
from functools import wraps
from contextlib import contextmanager
from collections import defaultdict, deque
from threading import Lock
from flask import Flask, request, jsonify, Response, redirect, make_response, render_template_string, session, send_from_directory, send_file, g

app = Flask(__name__)
app.secret_key = os.environ.get("AgHa3uhKwpLmnw!jduUs", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)

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

    # Railway / Docker volume için yaygın yol
    for candidate in ("/data/vantorium.db", "/app/data/vantorium.db"):
        parent = os.path.dirname(candidate)
        if os.path.isdir(parent) or os.access(os.path.dirname(parent) or "/", os.W_OK):
            try:
                os.makedirs(parent, exist_ok=True)
                return candidate
            except Exception:
                pass

    # Yerel / fallback
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
    """Tabloları oluşturur, gerekirse eksik kolonları ekler. Birden fazla çağrı güvenli."""
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
                # İndeksler
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


# Uygulama başlarken mutlaka çalıştır
init_db()


def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


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
            # 7 günden eski rate kayıtlarını sil
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
        )) or is_code_request(query),
        "is_code_request": is_code_request(query),
        "is_definition": bool(DEFINITION_RE.match(query or "")),
        "is_response_advice": bool(RESPONSE_RE.search(query or "")),
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
            timeout=7
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
        r = requests.get(url, params=params, headers=headers, timeout=7)

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
            timeout=7
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
            timeout=7
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
    """
    Kod 40 KB'dan büyükse dosya olarak saklar ve indirme linki verir.
    Küçükse normal markdown code block döner.
    """
    code = code or ""
    size = len(code.encode("utf-8"))
    FILE_THRESHOLD = 40 * 1024  # 40 KB

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
        # fallback: yine de kısaltılmış göster
        preview = code[:8000] + "\n\n# ... (dosya çok büyük, tamamı kaydedilemedi) ..."
        return (f"**{title}**\n\n```{language}\n{preview}\n```", source)

    return (
        f"**{title}**\n\n```{language}\n{code}\n```",
        source
    )


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
# GENERATIVE AI — REAL ANSWER SYNTHESIS
# =========================================================

def call_language_model(user_prompt, context="", mode="answer"):
    """Harici LLM bağlantısı kapalıdır; Vantorium yerel motorunu kullanır."""
    return None


def format_research_context(results):
    chunks = []
    for item in (results or [])[:7]:
        title = clean_snippet(item.get("title", ""), 180)
        snippet = clean_snippet(item.get("snippet", ""), 650)
        if title or snippet:
            chunks.append((title + ": " + snippet).strip())
    return "\n\n".join(chunks)


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
    """Ham arama metinlerini yerel kurallarla kısa, çok kaynaklı özete dönüştürür."""
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
            "Bu ifadeye verebileceğin kısa cevap: **“Anladım, biraz daha açar mısın?”**\\n\\n"
            "Daha samimi bir seçenek: **“Neden öyle düşünüyorsun?”**\\n\\n"
            f"Arama sonuçlarından ilgili bilgi: {snippets[0]}"
        )
    sentences = []
    for snippet in snippets:
        for sentence in re.split(r"(?<=[.!?])\\s+", snippet):
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
        f"**{query.strip()}** hakkında bulabildiğim bilgilerin özeti:\\n\\n"
        + "\\n\\n".join(sentences[:4])
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
# LOCAL GENERATION ENGINE — NO AI API REQUIRED
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
            "İşte yerel kelime üreticimin oluşturduğu özgün kelimeler:\n\n"
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
        "Bu soruya özel doğrulanmış bilgi yerel bilgi tabanımda bulunmuyor. "
        "Arama sonuçları da yeterince ilgili değil; yanlış bilgi uydurmak istemem. "
        "Soruyu biraz daha ayrıntılandırırsan yerel bilgilerim ve örneklerle yardımcı olabilirim."
    )


def recommendation_answer(query):
    q = normalize(query)
    if re.search(r"teknoloji|technology|teknolojik", q):
        return (
            "Bugün öğrenmeye değer 5 teknoloji konusu:\\n\\n"
            "1. **Yapay zekâ ajanları:** Araç kullanabilen ve çok adımlı işleri "
            "tamamlayabilen akıllı sistemler.\\n\\n"
            "2. **Siber güvenlik:** Kimlik avı, veri sızıntısı ve güvenli yazılım "
            "geliştirme yöntemleri.\\n\\n"
            "3. **Kuantum bilişim:** Kuantum bilgisayarların çalışma mantığı "
            "ve kullanım alanları.\\n\\n"
            "4. **Robotik ve otonom sistemler:** Sensörler, bilgisayarlı görü "
            "ve kendi kararlarını verebilen makineler.\\n\\n"
            "5. **Edge AI:** Yapay zekânın bulut yerine telefon ve diğer "
            "cihazların üzerinde çalıştırılması.\\n\\n"
            "**Başlangıç önerim:** Python temeliyle küçük bir yapay zekâ "
            "asistanı geliştirerek başla.",
            "öneri"
        )
    return None


def get_answer(query):
    query = (query or "").strip()
    if not query:
        return "Bir şeyler yaz, birlikte bakalım.", "sistem"

    parts = analyze_query(query)

    if parts["is_greeting"]:
        return random.choice([
            "Selam! 👋 Ben Vantorium. Ne yapmak istiyorsun?",
            "Merhaba! Hazırım. Sorunu yaz, birlikte çözelim.",
            "Selam kral 😎 Ne üzerinde çalışıyoruz?"
        ]), "selamlama"

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
        # user_id varsa dosya sahipliği için geçeriz
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

    # Search is used only as a source of facts; no third-party AI is called.
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
            cur.execute(
                "UPDATE users SET last_login = ? WHERE id = ?",
                (now.isoformat(), user_id)
            )
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
  display:block;
  object-fit:contain;
  background:transparent;
  box-shadow:none;
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

/* CODE BLOCKS IN CHAT */
.code-card{margin-top:14px;border:1px solid rgba(255,255,255,.09);border-radius:15px;overflow:hidden;background:#070a0f;box-shadow:0 14px 45px rgba(0,0,0,.25)}
.code-card-head{display:flex;align-items:center;justify-content:space-between;padding:9px 11px;background:#0d131b;border-bottom:1px solid rgba(255,255,255,.07)}
.code-lang{color:#7f8b9a;font-size:11px;font-weight:800;text-transform:uppercase}
.copy-code{border:0;border-radius:8px;padding:7px 10px;background:#17212b;color:#e8edf3;font-size:11px;font-weight:800;cursor:pointer}
.copy-code:hover{background:#20303d}
.code-card pre{margin:0;padding:15px;overflow:auto;white-space:pre;color:#e8edf3;font:12px/1.7 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
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

/* ========== GEMINI-STYLE CHAT UI ========== */
.chat-shell{
  height:100dvh;
  min-height:520px;
  display:grid;
  grid-template-columns:260px minmax(0,1fr);
  background:#0b0d10;
  overflow:hidden;
}
body:has(.chat-shell){margin:0;overflow:hidden}
.chat-sidebar{
  border-right:1px solid rgba(255,255,255,.07);
  background:#101216;
  padding:16px 12px;
  display:flex;flex-direction:column;gap:14px;
  overflow-y:auto;
}
.sidebar-new{
  display:flex;align-items:center;gap:10px;width:100%;
  padding:12px 14px;border:1px solid rgba(255,255,255,.09);
  border-radius:14px;background:#1a1d23;color:#f2f4f7;
  font-weight:650;cursor:pointer;text-align:left;font-size:14px;
  transition:.15s;
}
.sidebar-new:hover,.sidebar-link:hover{background:#22262d}
.sidebar-label{padding:4px 10px;color:#7e8794;font-size:11px;font-weight:800;letter-spacing:.8px;text-transform:uppercase}
.sidebar-link{
  display:flex;align-items:center;gap:11px;padding:10px 12px;
  border-radius:12px;color:#c4cad3;font-size:13px;font-weight:600;
  transition:.15s;
}
.sidebar-bottom{margin-top:auto;display:grid;gap:4px;padding-top:12px;border-top:1px solid rgba(255,255,255,.06)}
.chat-main{min-width:0;display:flex;flex-direction:column;position:relative;background:#0b0d10}
.chat-topbar{
  height:56px;flex-shrink:0;display:flex;align-items:center;
  justify-content:space-between;padding:0 22px;
  border-bottom:1px solid rgba(255,255,255,.055);
}
.chat-model{display:flex;align-items:center;gap:9px;font-size:14px;font-weight:700;color:#e8ebef}
.model-pill{
  font-size:11px;color:#9bbcf2;background:rgba(138,180,248,.12);
  padding:4px 10px;border-radius:20px;font-weight:700;
}
.chat-top-actions{display:flex;align-items:center;gap:6px}
.top-icon{
  width:36px;height:36px;border:0;border-radius:50%;
  background:transparent;color:#aeb7c4;cursor:pointer;font-size:17px;
  display:grid;place-items:center;transition:.15s;
}
.top-icon:hover{background:#20242b;color:#fff}
.chat-history{
  flex:1;min-height:0;overflow:auto;padding:28px 20px 160px;
  width:100%;max-width:860px;margin:0 auto;
  scrollbar-width:thin;scrollbar-color:#343943 transparent;
}
.chat-row{
  display:flex;align-items:flex-start;gap:12px;
  margin:0 auto 22px;max-width:760px;width:100%;
  animation:msgIn .28s ease;
}
@keyframes msgIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.chat-row.user{justify-content:flex-end}
.chat-row .avatar{
  width:32px;height:32px;flex:0 0 32px;border-radius:50%;
  display:grid;place-items:center;font-weight:800;font-size:12px;
  overflow:hidden;
}
.chat-row.ai .avatar{background:linear-gradient(145deg,#8ab4f8,#7c8df5);color:#101827}
.chat-row.user .avatar{background:#2b3038;color:#f4f6f8;order:2}
.bubble{max-width:min(100%,700px);font-size:15px;line-height:1.75;color:#e2e5e9;overflow-wrap:anywhere}
.chat-row.user .bubble{
  background:#20242b;border:1px solid rgba(255,255,255,.05);
  border-radius:20px 20px 6px 20px;padding:11px 16px;
  max-width:min(78%,560px);line-height:1.6;
}
.chat-row.ai .bubble{padding:2px 0}
.chat-welcome{max-width:760px;margin:8vh auto 32px;padding:0 8px;text-align:left}
.welcome-kicker{font-size:14px;color:#a9b5c7;margin-bottom:10px;font-weight:500}
.chat-welcome h1{
  font-size:clamp(28px,4.8vw,44px);line-height:1.15;
  letter-spacing:-1.4px;font-weight:650;color:#eef2f8;margin:0;
}
.chat-welcome h1 span{
  background:linear-gradient(90deg,#8ab4f8,#c4a7ff);
  -webkit-background-clip:text;background-clip:text;color:transparent;
}
.welcome-sub{margin-top:12px;color:#929ba8;font-size:15px;line-height:1.5}
.prompt-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-top:28px}
.prompt-chip{
  min-height:72px;text-align:left;padding:14px 15px;border-radius:16px;
  border:1px solid rgba(255,255,255,.07);background:#14171d;color:#d8dde5;
  cursor:pointer;font-size:13px;line-height:1.45;transition:.18s;
  display:flex;flex-direction:column;justify-content:center;
}
.prompt-chip:hover{
  background:#1b2028;border-color:rgba(138,180,248,.4);
  transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,0,0,.25);
}
.prompt-chip small{display:block;color:#7f8998;margin-top:5px;font-size:12px}
.composer-dock{
  position:absolute;left:0;right:0;bottom:0;padding:16px 20px 20px;
  background:linear-gradient(180deg,rgba(11,13,16,0) 0%,#0b0d10 28%);
}
.composer-wrap{max-width:760px;margin:0 auto}
.composer{
  display:flex;align-items:flex-end;gap:8px;padding:10px 12px 10px 16px;
  border:1px solid #343a45;border-radius:24px;background:#1b1f26;
  box-shadow:0 8px 32px rgba(0,0,0,.3);transition:.18s;
}
.composer:focus-within{
  border-color:#7189b6;
  box-shadow:0 0 0 3px rgba(138,180,248,.1),0 8px 32px rgba(0,0,0,.3);
}
.composer textarea{
  flex:1;min-width:0;max-height:160px;min-height:28px;resize:none;
  border:0;outline:0;background:transparent;color:#f1f3f7;
  font:15px/1.5 Inter,system-ui,sans-serif;padding:6px 0;
}
.composer textarea::placeholder{color:#8b929e}
.composer-tools{display:flex;align-items:center;gap:4px}
.send-btn{
  width:40px;height:40px;border:0;border-radius:50%;display:grid;place-items:center;
  background:#a8c7fa;color:#142238;cursor:pointer;transition:.18s;flex-shrink:0;
}
.send-btn:hover{background:#c0d7ff;transform:scale(1.05)}
.send-btn:disabled{opacity:.4;cursor:wait;transform:none}
.composer-hint{text-align:center;color:#707987;font-size:11px;margin-top:9px}
.thinking{display:flex;align-items:center;gap:9px;color:#dce5f5;font-weight:650}
.thinking-dot{
  width:8px;height:8px;border-radius:50%;background:#9bbcf2;
  box-shadow:0 0 0 5px rgba(155,188,242,.12);animation:vPulse 1s infinite;
}
.status-line{font-size:12px;color:#818b99;margin-top:4px}
@keyframes vPulse{50%{opacity:.35;transform:scale(.8)}}
.code-card{
  margin:14px 0;border:1px solid #343b47;border-radius:14px;
  overflow:hidden;background:#101319;
}
.code-card-head{
  display:flex;align-items:center;justify-content:space-between;
  padding:9px 12px;background:#191e26;border-bottom:1px solid #303641;
}
.code-lang{color:#aab8ce;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.7px}
.copy-code{
  border:0;border-radius:8px;padding:7px 11px;background:#d7e3f8;
  color:#182437;font-size:12px;font-weight:800;cursor:pointer;transition:.15s;
}
.copy-code:hover{filter:brightness(1.08)}
.code-card pre{
  margin:0;padding:14px;max-height:480px;overflow:auto;white-space:pre;
  color:#e7ebf2;font:12px/1.65 ui-monospace,SFMono-Regular,Consolas,monospace;
}
/* Dosya indirme kartı (uzun kodlar) */
.file-card{
  margin:14px 0;padding:16px 18px;border-radius:16px;
  border:1px solid rgba(138,180,248,.25);
  background:linear-gradient(135deg,rgba(138,180,248,.08),rgba(124,141,245,.04));
  display:flex;align-items:center;gap:14px;flex-wrap:wrap;
}
.file-card .file-icon{
  width:42px;height:42px;border-radius:12px;
  background:rgba(138,180,248,.18);display:grid;place-items:center;
  font-size:20px;flex-shrink:0;
}
.file-card .file-info{flex:1;min-width:140px}
.file-card .file-name{font-weight:700;font-size:14px;color:#e8eef8}
.file-card .file-meta{font-size:12px;color:#8b96a7;margin-top:3px}
.file-card a.file-dl{
  display:inline-flex;align-items:center;gap:6px;
  padding:10px 16px;border-radius:12px;background:#a8c7fa;color:#142238;
  font-weight:800;font-size:13px;text-decoration:none;transition:.15s;
}
.file-card a.file-dl:hover{background:#c0d7ff;transform:translateY(-1px)}
.chat-error{
  color:#ff9c9c;background:rgba(255,80,80,.08);
  border:1px solid rgba(255,80,80,.16);padding:12px 14px;border-radius:12px;
}
@media(max-width:900px){
  .chat-shell{grid-template-columns:1fr;height:100dvh}
  .chat-sidebar{display:none}
  .chat-topbar{height:52px;padding:0 14px}
  .chat-history{padding:20px 14px 150px}
  .composer-dock{padding:12px 12px calc(14px + env(safe-area-inset-bottom))}
  .chat-welcome{margin:7vh auto 24px}
}
@media(max-width:520px){
  .navbar{height:60px;padding:0 10px}
  .navbar .btn-nav{font-size:11px;padding:7px 5px}
  .navbar .logo{font-size:14px}
  .chat-history{padding:16px 12px 140px}
  .chat-row{gap:8px;margin-bottom:18px}
  .chat-row .avatar{width:28px;height:28px;flex-basis:28px}
  .bubble{font-size:14px}
  .chat-row.user .bubble{max-width:86%}
  .chat-welcome h1{font-size:30px}
  .prompt-grid{grid-template-columns:1fr 1fr;gap:8px;margin-top:20px}
  .prompt-chip{padding:12px;min-height:70px;font-size:12px}
  .composer{border-radius:20px;padding:8px 8px 8px 12px}
  .composer textarea{font-size:14px}
  .send-btn{width:38px;height:38px}
  .file-card{padding:12px 14px}
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
# SITE PROTECTION: HUMAN GATE + RATE LIMITING (Gelişmiş)
# =========================================================

_RATE_BUCKETS = defaultdict(deque)
_RATE_LOCK = Lock()
_FAIL_BUCKETS = defaultdict(deque)   # başarısız login / captcha denemeleri
_BLOCKED_IPS = {}                    # ip -> unblock_timestamp

def client_ip():
    # TRUST_PROXY=1 ise X-Forwarded-For kullanılır (Railway vb.)
    if os.environ.get("TRUST_PROXY", "").lower() == "1":
        forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if forwarded:
            return forwarded[:64]
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
                    # Aşırı istekte de kısa ban
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
    # API calls are intentionally never shown a browser CAPTCHA.
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
    expected = session.get("human_nonce")
    nonce = str(data.get("nonce", ""))
    elapsed = int(data.get("elapsed", 0) or 0)
    pointer_count = int(data.get("pointerCount", 0) or 0)
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
                        "SELECT id FROM users WHERE username = ?",
                        (username,)
                    ).fetchone()
                    if exists:
                        error = "Bu kullanıcı adı zaten alınmış."
                    else:
                        api_key = "vnt_" + secrets.token_hex(24)
                        cur.execute("""
                            INSERT INTO users
                            (username, password_hash, api_key, created_at, is_active)
                            VALUES (?, ?, ?, ?, 1)
                        """, (
                            username,
                            hash_password(password),
                            api_key,
                            datetime.now().isoformat()
                        ))
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
            pattern="[a-zA-Z0-9_.-]{{3,32}}"
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

            if user and user["password_hash"] == hash_password(password):
                token = create_session(user["id"])
                if token:
                    response = make_response(redirect("/chat"))
                    response.set_cookie(
                        "session_token",
                        token,
                        httponly=True,
                        samesite="Lax",
                        max_age=30 * 24 * 3600,
                        secure=request.is_secure
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
    destroy_session(token)
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
      <aside class="chat-sidebar">
        <button class="sidebar-new" type="button" onclick="newChat()">＋ <span>Yeni sohbet</span></button>
        <div class="sidebar-label">Vantorium</div>
        <a class="sidebar-link" href="/chat">✧ <span>Sohbet</span></a>
        <a class="sidebar-link" href="/search">⌕ <span>Web'de ara</span></a>
        <div class="sidebar-bottom">
          <a class="sidebar-link" href="/dashboard">⚙ <span>Dashboard</span></a>
          <a class="sidebar-link" href="/info">ⓘ <span>Kurallar ve bilgi</span></a>
          <a class="sidebar-link" href="/logout">↪ <span>Çıkış yap</span></a>
        </div>
      </aside>

      <section class="chat-main">
        <header class="chat-topbar">
          <div class="chat-model">Vantorium <span class="model-pill">AI Asistan</span></div>
          <div class="chat-top-actions">
            <button class="top-icon" type="button" title="Yeni sohbet" onclick="newChat()">＋</button>
          </div>
        </header>

        <div class="chat-history" id="chatHistory">
          <section class="chat-welcome" id="welcomePanel">
            <div class="welcome-kicker">Merhaba, """ + html.escape(user["username"]) + r""" 👋</div>
            <h1>Bugün neye <span>bakalım?</span></h1>
            <p class="welcome-sub">Sor, araştırayım. Kod iste, hazırlayayım. Birlikte çözelim.</p>
            <div class="prompt-grid">
              <button class="prompt-chip" onclick="usePrompt('Python ile gelişmiş bir Telegram botu kodu ver')">⌘ Kod oluştur<small>İhtiyacına uygun kod yaz</small></button>
              <button class="prompt-chip" onclick="usePrompt('Yapay zekâ nasıl çalışır?')">✧ Bir konuyu öğren<small>Açık ve anlaşılır şekilde araştır</small></button>
              <button class="prompt-chip" onclick="usePrompt('Bana modern bir web sitesi tasarla ve HTML kodunu ver')">▣ Web sitesi yap<small>HTML, CSS ve JavaScript</small></button>
              <button class="prompt-chip" onclick="usePrompt('Bugün öğrenmeye değer 5 teknoloji konusu öner')">⌕ Fikir keşfet<small>Yeni konular ve öneriler</small></button>
            </div>
          </section>
        </div>

        <div class="composer-dock">
          <div class="composer-wrap">
            <form class="composer" id="chatForm">
              <textarea id="chatInput" rows="1" placeholder="Vantorium'a bir şey sor..." autocomplete="off"></textarea>
              <div class="composer-tools">
                <button class="send-btn" id="sendBtn" type="submit" aria-label="Gönder">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V5"></path><path d="m5 12 7-7 7 7"></path></svg>
                </button>
              </div>
            </form>
            <div class="composer-hint">Vantorium hata yapabilir. Önemli bilgileri doğrulamayı unutma.</div>
          </div>
        </div>
      </section>
    </main>

    <script>
    (() => {
      const historyEl = document.getElementById("chatHistory");
      const input = document.getElementById("chatInput");
      const form = document.getElementById("chatForm");
      const sendBtn = document.getElementById("sendBtn");
      let sending = false;

      function escapeHTML(value) {
        return String(value).replace(/[&<>"']/g, ch => ({
          "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"
        }[ch]));
      }

      function scrollBottom() {
        requestAnimationFrame(() => { historyEl.scrollTop = historyEl.scrollHeight; });
      }

      function hideWelcome() {
        const welcome = document.getElementById("welcomePanel");
        if (welcome) welcome.remove();
      }

      window.newChat = function() {
        historyEl.innerHTML = document.getElementById("welcomeTemplate")?.innerHTML || "";
        if (!historyEl.querySelector(".chat-welcome")) {
          historyEl.innerHTML = `<section class="chat-welcome" id="welcomePanel">
            <div class="welcome-kicker">Yeniden merhaba 👋</div>
            <h1>Bugün neye <span>bakalım?</span></h1>
            <p class="welcome-sub">Sor, araştırayım. Kod iste, hazırlayayım. Birlikte çözelim.</p>
          </section>`;
        }
        input.value = "";
        input.focus();
      };

      window.usePrompt = function(value) {
        input.value = value;
        input.focus();
        autoResize();
      };

      function autoResize() {
        input.style.height = "auto";
        input.style.height = Math.min(input.scrollHeight, 170) + "px";
      }
      input.addEventListener("input", autoResize);
      input.addEventListener("keydown", event => {
        if (event.key === "Enter" && !event.shiftKey) {
          event.preventDefault();
          form.requestSubmit();
        }
      });

      function addMessage(text, type) {
        hideWelcome();
        const row = document.createElement("div");
        row.className = "chat-row " + type;
        const avatar = document.createElement("div");
        avatar.className = "avatar";
        if (type === "user") avatar.textContent = "K";
        else {
          const mark = document.createElement("img");
          mark.src = "/icon.png"; mark.alt = "Vantorium";
          mark.style.cssText = "width:100%;height:100%;object-fit:contain;border-radius:inherit";
          avatar.appendChild(mark);
        }
        const bubble = document.createElement("div");
        bubble.className = "bubble";
        bubble.textContent = text;
        row.append(avatar, bubble);
        historyEl.appendChild(row);
        scrollBottom();
        return bubble;
      }

      function addThinking() {
        hideWelcome();
        const row = document.createElement("div");
        row.className = "chat-row ai";
        row.id = "thinkingRow";
        row.innerHTML = `<div class="avatar"><img src="/icon.png" alt="Vantorium" style="width:100%;height:100%;object-fit:contain;border-radius:inherit"></div><div class="bubble">
          <div class="thinking"><span class="thinking-dot"></span><span id="thinkingText">Düşünüyor...</span></div>
          <div class="status-line" id="thinkingSub">Sorunu analiz ediyor</div>
        </div>`;
        historyEl.appendChild(row);
        scrollBottom();
      }

      function setThinking(main, sub) {
        const title = document.getElementById("thinkingText");
        const detail = document.getElementById("thinkingSub");
        if (title) title.textContent = main;
        if (detail) detail.textContent = sub;
      }

      function renderAnswer(text) {
        const codeBlocks = [];
        const token = "VANTORIUM_CODE_BLOCK_";
        let index = 0;
        let safeText = String(text || "").replace(/```([a-zA-Z0-9+#_.-]*)\s*\n?([\s\S]*?)```/g, (match, lang, code) => {
          const key = token + index++;
          codeBlocks.push({key, lang:lang || "code", code:code.replace(/^\n|\n$/g, "")});
          return key;
        });
        // Markdown indirme linklerini yakala: [dosya.ext](/download/code/ID)
        const fileCards = [];
        safeText = safeText.replace(
          /📥\s*\*\*İndir:\*\*\s*\[([^\]]+)\]\(\/download\/code\/([a-zA-Z0-9_-]+)\)/g,
          (match, fname, fid) => {
            const key = "VANTORIUM_FILE_" + fileCards.length;
            fileCards.push({key, fname, fid});
            return key;
          }
        );
        // Daha genel markdown link de yakala
        safeText = safeText.replace(
          /\[([^\]]+\.(?:py|html|js|css|php|sql|sh|java|ts|go|rs|rb|swift|txt|json))\]\(\/download\/code\/([a-zA-Z0-9_-]+)\)/gi,
          (match, fname, fid) => {
            const key = "VANTORIUM_FILE_" + fileCards.length;
            fileCards.push({key, fname, fid});
            return key;
          }
        );
        let output = escapeHTML(safeText)
          .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
          .replace(/`([^`]+)`/g, "<code>$1</code>")
          .replace(/\n/g, "<br>");
        for (const block of codeBlocks) {
          const codeHTML = `<div class="code-card">
            <div class="code-card-head"><span class="code-lang">${escapeHTML(block.lang)}</span>
            <button class="copy-code" type="button">Kopyala</button></div>
            <pre><code>${escapeHTML(block.code)}</code></pre></div>`;
          output = output.replace(block.key, codeHTML);
        }
        for (const f of fileCards) {
          const card = `<div class="file-card">
            <div class="file-icon">📄</div>
            <div class="file-info">
              <div class="file-name">${escapeHTML(f.fname)}</div>
              <div class="file-meta">Hazır dosya · 48 saat geçerli</div>
            </div>
            <a class="file-dl" href="/download/code/${escapeHTML(f.fid)}" download>
              İndir ↓
            </a>
          </div>`;
          output = output.replace(f.key, card);
        }
        return output;
      }

      async function sendChat() {
        const message = input.value.trim();
        if (!message || sending) return;
        sending = true;
        sendBtn.disabled = true;
        input.value = "";
        autoResize();
        addMessage(message, "user");
        addThinking();

        const codeIntent = /(kod|python|html|javascript|php|css|github)/i.test(message);
        const stages = codeIntent ? [
          ["Düşünüyor...","İsteğini ve programlama dilini belirliyor"],
          ["GitHub'da arıyor...","Uygun açık kaynak kodlarını kontrol ediyor"],
          ["Kodu inceliyor...","İhtiyaca en yakın örneği seçiyor"],
          ["Cevabı hazırlıyor...","Kod bloğunu ve kopyalama alanını hazırlıyor"]
        ] : [
          ["Düşünüyor...","Sorunun ne istediğini anlamaya çalışıyor"],
          ["Web'de arıyor...","İlgili bilgileri araştırıyor"],
          ["Bilgileri inceliyor...","Sonuçları karşılaştırıyor"],
          ["Cevabı hazırlıyor...","En uygun yanıtı oluşturuyor"]
        ];
        let stage = 0;
        setThinking(stages[0][0], stages[0][1]);
        const timer = setInterval(() => {
          stage = Math.min(stage + 1, stages.length - 1);
          setThinking(stages[stage][0], stages[stage][1]);
        }, 1300);

        try {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 90000);
          let response;
          try {
            response = await fetch("/api/chat", {
              method:"POST",
              credentials:"same-origin",
              headers:{"Content-Type":"application/json","Accept":"application/json"},
              body:JSON.stringify({message}),
              signal:controller.signal
            });
          } finally {
            clearTimeout(timeout);
          }

          const raw = await response.text();
          let data;
          try { data = JSON.parse(raw); }
          catch (_) { throw new Error("Sunucudan geçerli JSON yanıtı alınamadı: " + raw.slice(0,180)); }
          if (!response.ok) throw new Error(data.error || data.answer || ("HTTP " + response.status));
          if (!data || typeof data.answer !== "string" || !data.answer.trim()) {
            throw new Error("Sunucu boş yanıt döndürdü.");
          }

          clearInterval(timer);
          const thinking = document.getElementById("thinkingRow");
          if (thinking) thinking.remove();
          const bubble = addMessage("", "ai");
          bubble.innerHTML = renderAnswer(data.answer);

          bubble.querySelectorAll(".copy-code").forEach(button => {
            button.addEventListener("click", async () => {
              const code = button.closest(".code-card").querySelector("pre code").textContent;
              try {
                await navigator.clipboard.writeText(code);
                button.textContent = "Kopyalandı ✓";
              } catch (_) {
                const area = document.createElement("textarea");
                area.value = code; document.body.appendChild(area); area.select();
                document.execCommand("copy"); area.remove();
                button.textContent = "Kopyalandı ✓";
              }
              setTimeout(() => button.textContent = "Kopyala", 1600);
            });
          });
        } catch (error) {
          clearInterval(timer);
          const thinking = document.getElementById("thinkingRow");
          if (thinking) thinking.remove();
          const detail = error.name === "AbortError"
            ? "İstek zaman aşımına uğradı. Biraz daha kısa bir istekle tekrar dene."
            : (error.message || "Bilinmeyen bağlantı hatası.");
          const bubble = addMessage("Yanıt alınamadı. " + detail, "ai");
          bubble.classList.add("chat-error");
        } finally {
          sending = false;
          sendBtn.disabled = false;
          input.focus();
        }
      }

      form.addEventListener("submit", event => {
        event.preventDefault();
        sendChat();
      });
      input.focus();
    })();
    </script>
    """
    return render_page("Sohbet", content, user, show_nav=False)


@app.route("/api/chat", methods=["POST"])
@rate_limit(12, 60)
@login_required
def api_chat():
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip()

    if not message:
        return jsonify({"error": "Bir mesaj yazmalısın.", "answer": ""}), 400

    if len(message) > 6000:
        return jsonify({"error": "Mesaj çok uzun. En fazla 6000 karakter gönderebilirsin.", "answer": ""}), 413

    try:
        answer, source = get_answer(message)
        if not isinstance(answer, str) or not answer.strip():
            answer = "İsteğini işledim ancak boş yanıt oluştu. Bir kez daha dener misin?"
            source = "fallback"
        return jsonify({"answer": answer, "source": source})
    except requests.RequestException as exc:
        app.logger.exception("Chat request network error")
        return jsonify({
            "answer": "Araştırma servislerine şu anda ulaşılamıyor. Biraz sonra tekrar dene.",
            "source": "network_error"
        }), 200
    except Exception:
        app.logger.exception("Unhandled /api/chat error")
        return jsonify({
            "answer": "Yanıt hazırlanırken sunucu tarafında bir hata oluştu. Lütfen tekrar dene.",
            "source": "server_error"
        }), 200

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
@rate_limit(20, 60)
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
    try:
        with db_cursor() as cur:
            cur.execute(
                "UPDATE users SET api_key = ? WHERE id = ?",
                (new_key, user["id"])
            )
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
                "SELECT * FROM users WHERE api_key = ? AND is_active = 1",
                (apikey,)
            ).fetchone()
    except Exception:
        user = None

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
            "time_ms": round((time.time() - start) * 1000, 2),
            "engine": "Vantorium Local Engine 9.0",
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
    if not data:
        return "Dosya bulunamadı veya süresi dolmuş.", 404

    filename = data["filename"]
    content = data["content"]
    language = data.get("language") or "txt"

    mime_map = {
        "python": "text/x-python",
        "html": "text/html",
        "css": "text/css",
        "javascript": "application/javascript",
        "php": "application/x-httpd-php",
        "sql": "application/sql",
        "bash": "application/x-sh",
        "java": "text/x-java-source",
    }
    mimetype = mime_map.get(language, "text/plain")

    tmp = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8",
        suffix=os.path.splitext(filename)[1] or ".txt",
        delete=False
    )
    try:
        tmp.write(content)
        tmp.close()
        return send_file(
            tmp.name,
            mimetype=mimetype,
            as_attachment=True,
            download_name=filename
        )
    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass


@app.before_request
def maybe_cleanup():
    if random.random() < 0.015:
        cleanup_expired()


# =========================================================
# START
# =========================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    print(f"[Vantorium] DB path : {DB_FILE}")
    print(f"[Vantorium] Code dir: {CODE_FILES_DIR}")
    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )

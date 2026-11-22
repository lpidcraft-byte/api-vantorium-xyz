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
from datetime import datetime
from functools import wraps
from flask import (
    Flask, request, jsonify, Response,
    render_template_string, redirect,
    make_response
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ============================================================
# 1. AYARLAR
# ============================================================

DB_FILE = "vantorium.db"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",

    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",

    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
]

COMMON_HEADERS = {
    "User-Agent": random.choice(USER_AGENTS),
    "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7"
}


# ============================================================
# 2. VERİ TABANI
# ============================================================

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


# ============================================================
# 3. DATASET
# ============================================================

def normalize(text):
    text = str(text or "").lower().strip()
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"[?!.,;:]+$", "", text)
    return text.strip()


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
                current_q = None

                for line in file:
                    line = line.strip()

                    if not line or line.startswith("#"):
                        continue

                    if line.startswith("Input:"):
                        current_q = normalize(
                            line.replace("Input:", "", 1).strip()
                        )

                        if current_q not in data:
                            data[current_q] = []

                    elif line.startswith("Reply:") and current_q:
                        reply = line.replace(
                            "Reply:", "", 1
                        ).strip()

                        if reply:
                            data[current_q].append(reply)

            break

        except Exception:
            continue

    return data


DATASET = load_dataset()


# ============================================================
# 4. SORU ANALİZİ
# ============================================================

def analyze_query(query):
    q = normalize(query)

    is_greeting = bool(re.search(
        r"\b(merhaba|selam|hello|hi|hey|günaydın|"
        r"nasılsın|naber|nbr|sa|selamünaleyküm)\b",
        q
    ))

    is_math = bool(
        re.match(r"^[\d\s+\-*/().,^%]+$", query)
        and re.search(r"[\+\-\*\/\^%]", query)
    )

    is_code = bool(re.search(
        r"\b(kod|python|php|javascript|js|java|"
        r"html|css|flask|api|github|programlama|"
        r"fonksiyon|function|class|bug|hata|error|"
        r"debug|discord bot|telegram bot)\b",
        q
    ))

    # "X ne demek?"
    definition_patterns = [
        r"^(.+?)\s+ne demek$",
        r"^(.+?)\s+nedir$",
        r"^(.+?)\s+ne anlama geliyor$",
        r"^(.+?)\s+anlamı ne$",
        r"^(.+?)\s+anlamı nedir$"
    ]

    definition_word = None

    for pattern in definition_patterns:
        match = re.match(pattern, q)
        if match:
            definition_word = match.group(1).strip()
            break

    # "Bana X dedi, ne diyeyim?"
    reply_patterns = [
        r"(?:biri|birisi|arkadaşım|o) bana (.+?) dedi.*ne (?:diyeyim|demeliyim|denir|cevap vereyim)",
        r"(.+?) derse ne (?:diyeyim|demeliyim|denir|cevap vereyim)",
        r"(.+?) dedi.*ne (?:diyeyim|demeliyim|denir|cevap vereyim)",
        r"(.+?) diyene ne (?:diyeyim|demeliyim|denir)"
    ]

    reply_word = None

    for pattern in reply_patterns:
        match = re.search(pattern, q)
        if match:
            reply_word = match.group(1).strip()
            break

    image_request = bool(re.search(
        r"\b(resim|fotoğraf|foto|görsel|görüntü|"
        r"image|images|picture|fotoğrafları)\b",
        q
    ))

    return {
        "is_greeting": is_greeting,
        "is_math": is_math,
        "is_code": is_code,
        "definition_word": definition_word,
        "reply_word": reply_word,
        "image_request": image_request
    }


# ============================================================
# 5. MATEMATİK
# ============================================================

def calculate_math(query):
    try:
        expression = query.replace("^", "**")

        # Sadece güvenli matematik karakterleri
        expression = re.sub(
            r"[^0-9+\-*/().% ]",
            "",
            expression
        )

        result = eval(
            expression,
            {
                "__builtins__": {}
            },
            {}
        )

        return f"Sonuç: {result}"

    except Exception:
        return "Bu matematik işlemini çözemedim."


# ============================================================
# 6. DUCKDUCKGO WEB ARAMA
# ============================================================

def duckduckgo_search(query, limit=6):
    results = []

    try:
        encoded = urllib.parse.quote_plus(query)

        url = (
            "https://html.duckduckgo.com/html/"
            f"?q={encoded}"
        )

        headers = {
            **COMMON_HEADERS,
            "Accept": "text/html,application/xhtml+xml"
        }

        response = requests.get(
            url,
            headers=headers,
            timeout=8
        )

        if response.status_code != 200:
            return results

        page = response.text

        blocks = re.findall(
            r'<div class="result[^"]*".*?</div>\s*</div>',
            page,
            re.DOTALL
        )

        for block in blocks[:limit]:
            title_match = re.search(
                r'class="result__a"[^>]*>(.*?)</a>',
                block,
                re.DOTALL
            )

            snippet_match = re.search(
                r'class="result__snippet"[^>]*>(.*?)</a>|'
                r'class="result__snippet"[^>]*>(.*?)</div>',
                block,
                re.DOTALL
            )

            url_match = re.search(
                r'class="result__a"\s+href="([^"]+)"',
                block
            )

            if not title_match:
                continue

            title = re.sub(
                r"<[^>]+>",
                "",
                title_match.group(1)
            )

            title = html.unescape(title).strip()

            snippet = ""

            if snippet_match:
                snippet = (
                    snippet_match.group(1)
                    or snippet_match.group(2)
                    or ""
                )

                snippet = re.sub(
                    r"<[^>]+>",
                    "",
                    snippet
                )

                snippet = html.unescape(
                    snippet
                ).strip()

            result_url = ""

            if url_match:
                result_url = html.unescape(
                    url_match.group(1)
                )

                # DDG redirect linklerini çöz
                if "uddg=" in result_url:
                    parsed = urllib.parse.urlparse(result_url)
                    params = urllib.parse.parse_qs(
                        parsed.query
                    )

                    if "uddg" in params:
                        result_url = params["uddg"][0]

            if title:
                results.append({
                    "title": title,
                    "snippet": snippet,
                    "url": result_url,
                    "source": "web"
                })

    except Exception:
        pass

    return results


# ============================================================
# 7. WIKIPEDIA
# ============================================================

def wikipedia_search(query, limit=4):
    results = []

    try:
        url = "https://tr.wikipedia.org/w/api.php"

        params = {
            "action": "query",
            "list": "search",
            "srsearch": query,
            "utf8": 1,
            "format": "json",
            "srlimit": limit
        }

        response = requests.get(
            url,
            params=params,
            headers=COMMON_HEADERS,
            timeout=8
        )

        data = response.json()

        for item in data.get("query", {}).get("search", []):
            title = item.get("title", "")

            snippet = re.sub(
                r"<[^>]+>",
                "",
                item.get("snippet", "")
            )

            snippet = html.unescape(snippet)

            wiki_url = (
                "https://tr.wikipedia.org/wiki/"
                + urllib.parse.quote(
                    title.replace(" ", "_")
                )
            )

            results.append({
                "title": title,
                "snippet": snippet,
                "url": wiki_url,
                "source": "wikipedia"
            })

    except Exception:
        pass

    return results


# ============================================================
# 8. GITHUB ARAMA
# ============================================================

def github_search(query, limit=5):
    results = []

    try:
        url = "https://api.github.com/search/repositories"

        params = {
            "q": query,
            "sort": "stars",
            "order": "desc",
            "per_page": limit
        }

        headers = {
            **COMMON_HEADERS,
            "Accept": "application/vnd.github+json"
        }

        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=8
        )

        if response.status_code != 200:
            return results

        data = response.json()

        for item in data.get("items", []):
            results.append({
                "title": item.get("full_name", ""),
                "snippet": item.get("description")
                           or "Açıklama bulunamadı.",
                "url": item.get("html_url", ""),
                "source": "github",
                "stars": item.get("stargazers_count", 0),
                "language": item.get("language")
                            or ""
            })

    except Exception:
        pass

    return results


# ============================================================
# 9. WIKIMEDIA GÖRSEL ARAMA
# ============================================================

def image_search(query, limit=6):
    images = []

    try:
        url = "https://commons.wikimedia.org/w/api.php"

        params = {
            "action": "query",
            "generator": "search",
            "gsrsearch": query,
            "gsrnamespace": 6,
            "gsrlimit": limit,
            "prop": "imageinfo",
            "iiprop": "url|mime",
            "iiurlwidth": 900,
            "format": "json"
        }

        response = requests.get(
            url,
            params=params,
            headers=COMMON_HEADERS,
            timeout=8
        )

        data = response.json()

        pages = data.get(
            "query",
            {}
        ).get(
            "pages",
            {}
        )

        for page in pages.values():
            imageinfo = page.get(
                "imageinfo",
                []
            )

            if not imageinfo:
                continue

            info = imageinfo[0]

            image_url = (
                info.get("thumburl")
                or info.get("url")
            )

            if not image_url:
                continue

            mime = info.get("mime", "")

            if not mime.startswith("image/"):
                continue

            images.append({
                "title": page.get("title", ""),
                "url": image_url,
                "source": "Wikimedia Commons"
            })

    except Exception:
        pass

    return images


# ============================================================
# 10. TEMİZ METİN
# ============================================================

def clean_text(text):
    if not text:
        return ""

    text = html.unescape(text)

    text = re.sub(
        r"<script.*?</script>",
        "",
        text,
        flags=re.I | re.S
    )

    text = re.sub(
        r"<style.*?</style>",
        "",
        text,
        flags=re.I | re.S
    )

    text = re.sub(
        r"<[^>]+>",
        "",
        text
    )

    text = text.replace(
        "\u00a0",
        " "
    )

    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip()


# ============================================================
# 11. KISA CEVAP SEÇİCİ
# ============================================================

def best_snippet(results):
    if not results:
        return None

    valid = []

    for item in results:
        snippet = clean_text(
            item.get("snippet", "")
        )

        title = clean_text(
            item.get("title", "")
        )

        if snippet:
            valid.append({
                **item,
                "snippet": snippet,
                "title": title
            })

    if not valid:
        return None

    # Öncelik Wikipedia
    wiki = [
        x for x in valid
        if x.get("source") == "wikipedia"
    ]

    if wiki:
        return wiki[0]

    return valid[0]


# ============================================================
# 12. KELİME TANIMI
# ============================================================

def answer_definition(word):
    searches = [
        wikipedia_search(
            f"{word} nedir",
            4
        ),

        duckduckgo_search(
            f'"{word}" ne demek',
            5
        )
    ]

    results = []

    for group in searches:
        results.extend(group)

    selected = best_snippet(results)

    if not selected:
        return (
            f"“{word}” için güvenilir bir sonuç bulamadım.",
            "bulunamadi",
            []
        )

    snippet = clean_text(
        selected["snippet"]
    )

    # Aşırı uzun sonuçları kısalt
    if len(snippet) > 450:
        snippet = snippet[:447] + "..."

    answer = snippet

    return (
        answer,
        selected.get("source", "web"),
        []
    )


# ============================================================
# 13. "BANA X DEDİ, NE DİYİM?"
# ============================================================

def answer_reply(word):
    queries = [
        f'"{word}" dedi ne cevap verilir',
        f'"{word}" diyene ne denir',
        f'"{word}" dedi ne demeliyim',
        f'"{word}" cevabı ne'
    ]

    all_results = []

    for query in queries:
        all_results.extend(
            duckduckgo_search(
                query,
                3
            )
        )

    selected = best_snippet(
        all_results
    )

    if not selected:
        return (
            f"“{word}” denince şöyle cevap verebilirsin: "
            f"“Teşekkür ederim, sen de sağ ol.”",
            "cevap",
            []
        )

    snippet = clean_text(
        selected["snippet"]
    )

    if len(snippet) > 350:
        snippet = snippet[:347] + "..."

    return (
        snippet,
        "web",
        []
    )


# ============================================================
# 14. GENEL ARAMA
# ============================================================

def general_search(query):
    web_results = duckduckgo_search(
        query,
        6
    )

    wiki_results = wikipedia_search(
        query,
        3
    )

    combined = []

    # Wikipedia'yı biraz öne al
    combined.extend(wiki_results)
    combined.extend(web_results)

    selected = best_snippet(
        combined
    )

    if not selected:
        return (
            "Bu konuda güvenilir bir sonuç bulamadım.",
            "bulunamadi",
            []
        )

    answer = clean_text(
        selected["snippet"]
    )

    if len(answer) > 600:
        answer = answer[:597] + "..."

    source_url = selected.get(
        "url",
        ""
    )

    if source_url:
        answer += (
            f"\n\nKaynak: {source_url}"
        )

    return (
        answer,
        selected.get("source", "web"),
        []
    )


# ============================================================
# 15. ANA CEVAP MOTORU
# ============================================================

def get_answer(kelime):
    normalized = normalize(kelime)

    parts = analyze_query(
        kelime
    )

    # Selamlama
    if parts["is_greeting"]:
        return (
            random.choice([
                "Selam! Ben Vantorium. Ne hakkında konuşalım?",
                "Merhaba! Hazırım. Ne sormak istersin?",
                "Selam! Sorunu gönder, hemen bakalım."
            ]),
            "selamlama",
            []
        )

    # Matematik
    if parts["is_math"]:
        return (
            calculate_math(kelime),
            "matematik",
            []
        )

    # Dataset
    if (
        normalized in DATASET
        and DATASET[normalized]
    ):
        return (
            random.choice(
                DATASET[normalized]
            ),
            "veri_seti",
            []
        )

    # Hafıza
    cached = memory_get(
        normalized
    )

    if cached:
        return (
            cached,
            "hafiza",
            []
        )

    # "X ne demek?"
    if parts["definition_word"]:
        answer, source, images = answer_definition(
            parts["definition_word"]
        )

        memory_save(
            normalized,
            answer,
            0.88,
            source
        )

        return answer, source, images

    # "Bana X dedi, ne diyeyim?"
    if parts["reply_word"]:
        answer, source, images = answer_reply(
            parts["reply_word"]
        )

        memory_save(
            normalized,
            answer,
            0.85,
            source
        )

        return answer, source, images

    # Kod sorusu -> GitHub
    if parts["is_code"]:
        github_results = github_search(
            kelime,
            5
        )

        selected = best_snippet(
            github_results
        )

        if selected:
            answer = clean_text(
                selected["snippet"]
            )

            if len(answer) > 500:
                answer = answer[:497] + "..."

            answer += (
                "\n\nGitHub: "
                + selected.get(
                    "url",
                    ""
                )
            )

            memory_save(
                normalized,
                answer,
                0.90,
                "github"
            )

            return (
                answer,
                "github",
                []
            )

    # Normal arama
    answer, source, images = general_search(
        kelime
    )

    # Görsel istendiyse
    if parts["image_request"]:
        images = image_search(
            kelime,
            6
        )

    memory_save(
        normalized,
        answer,
        0.80,
        source
    )

    return (
        answer,
        source,
        images
    )


# ============================================================
# 16. KULLANICI
# ============================================================

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


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not get_current_user():
            return redirect("/login")

        return f(*args, **kwargs)

    return decorated


# ============================================================
# 17. TASARIM
# ============================================================

BASE_STYLE = """
<style>

* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

html {
    background: #07090b;
    color-scheme: dark;
}

body {
    font-family:
        Inter,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        Roboto,
        Arial,
        sans-serif;

    background:
        radial-gradient(
            circle at 50% -20%,
            rgba(16,163,127,.12),
            transparent 38%
        ),
        #07090b;

    color: #f4f4f5;
    min-height: 100vh;

    -webkit-font-smoothing: antialiased;
    text-rendering: optimizeLegibility;
}

a {
    color: #19d3a2;
    text-decoration: none;
}

button,
input {
    font-family: inherit;
}

/* NAVBAR */

.navbar {
    height: 68px;
    padding: 0 22px;

    display: flex;
    align-items: center;
    justify-content: space-between;

    position: sticky;
    top: 0;
    z-index: 1000;

    background:
        rgba(7,9,11,.78);

    backdrop-filter:
        blur(20px);

    -webkit-backdrop-filter:
        blur(20px);

    border-bottom:
        1px solid rgba(255,255,255,.07);
}

.logo {
    display: flex;
    align-items: center;
    gap: 11px;

    color: white;
    font-size: 18px;
    font-weight: 800;
    letter-spacing: -.5px;
}

.logo-icon {
    width: 34px;
    height: 34px;

    border-radius: 11px;

    display: flex;
    align-items: center;
    justify-content: center;

    background:
        linear-gradient(
            135deg,
            #20e3ad,
            #08a879
        );

    box-shadow:
        0 8px 30px
        rgba(16,163,127,.25);

    font-weight: 900;
}

.nav-actions {
    display: flex;
    align-items: center;
    gap: 5px;
}

.btn-nav {
    color: #a1a1aa;
    padding: 9px 12px;
    border-radius: 9px;

    font-size: 14px;
    font-weight: 600;

    transition:
        .2s ease;
}

.btn-nav:hover {
    color: white;
    background: rgba(255,255,255,.06);
}

.btn-nav.primary {
    color: white;
    background: #10a37f;
}

.btn-nav.primary:hover {
    background: #12b98e;
    transform: translateY(-1px);
}

/* AUTH */

.auth-wrapper {
    min-height:
        calc(100vh - 68px);

    display: flex;
    align-items: center;
    justify-content: center;

    padding: 28px 18px;
}

.container {
    width: 100%;
    max-width: 430px;

    padding: 34px;

    background:
        rgba(17,19,23,.82);

    border:
        1px solid rgba(255,255,255,.08);

    border-radius: 22px;

    box-shadow:
        0 30px 100px
        rgba(0,0,0,.35);

    backdrop-filter: blur(20px);
}

.container.wide {
    max-width: 1000px;
    margin: 35px auto;
}

h2 {
    font-size: 25px;
    letter-spacing: -.7px;
    margin-bottom: 7px;
}

.subtitle {
    color: #8f939b;
    font-size: 14px;
    line-height: 1.6;
    margin-bottom: 25px;
}

label {
    display: block;
    color: #cfd1d5;
    font-size: 13px;
    font-weight: 600;
    margin-bottom: 7px;
}

input[type=text],
input[type=password] {
    width: 100%;
    padding: 13px 14px;

    margin-bottom: 18px;

    color: white;
    background: #0b0e12;

    border:
        1px solid #252a31;

    border-radius: 11px;

    outline: none;

    transition: .2s ease;
}

input:focus {
    border-color: #10a37f;

    box-shadow:
        0 0 0 4px
        rgba(16,163,127,.11);
}

.btn {
    width: 100%;
    border: 0;

    padding: 13px;

    color: white;
    background: #10a37f;

    border-radius: 11px;

    font-weight: 700;
    cursor: pointer;

    transition: .2s ease;
}

.btn:hover {
    background: #12b98e;
    transform: translateY(-1px);
}

.link-row {
    margin-top: 22px;
    text-align: center;

    color: #777b83;
    font-size: 14px;
}

.error {
    padding: 12px 14px;
    margin-bottom: 18px;

    color: #ff8d8d;

    background:
        rgba(239,68,68,.09);

    border:
        1px solid
        rgba(239,68,68,.18);

    border-radius: 11px;

    font-size: 13px;
}

/* CARDS */

.card {
    padding: 25px;

    margin-bottom: 18px;

    background:
        rgba(17,19,23,.78);

    border:
        1px solid rgba(255,255,255,.07);

    border-radius: 17px;
}

.card h3 {
    margin-bottom: 14px;

    font-size: 16px;
}

.card p {
    color: #a4a7ad;
    font-size: 14px;
    line-height: 1.75;
}

.api-key-box {
    padding: 14px;

    margin-bottom: 13px;

    color: #1ce0ad;

    background: #090c0f;

    border:
        1px solid #22272d;

    border-radius: 10px;

    font-family:
        "SFMono-Regular",
        Consolas,
        monospace;

    word-break: break-all;
}

.code-block {
    padding: 15px;

    margin: 12px 0;

    overflow-x: auto;

    color: #ddd;

    background: #090c0f;

    border:
        1px solid #22272d;

    border-radius: 11px;

    font-family:
        "SFMono-Regular",
        Consolas,
        monospace;

    font-size: 13px;
    line-height: 1.6;
}

h1.page-title {
    font-size: 30px;
    letter-spacing: -.8px;
    margin-bottom: 7px;
}

h2.section-title {
    margin: 38px 0 15px;
    font-size: 18px;
}

.footer {
    text-align: center;
    padding: 35px;
    color: #555a62;
    font-size: 12px;
}

/* CHAT */

.chat-layout {
    height:
        calc(100vh - 68px);

    max-width: 980px;
    width: 100%;

    margin: 0 auto;

    display: flex;
    flex-direction: column;
}

.chat-history {
    flex: 1;

    overflow-y: auto;

    padding:
        30px 20px
        130px 20px;

    scroll-behavior: smooth;
}

.chat-history::-webkit-scrollbar {
    width: 5px;
}

.chat-history::-webkit-scrollbar-thumb {
    background: #24282e;
    border-radius: 10px;
}

.chat-msg {
    display: flex;
    gap: 13px;

    margin-bottom: 27px;

    animation:
        messageIn .25s ease;
}

@keyframes messageIn {
    from {
        opacity: 0;
        transform: translateY(5px);
    }

    to {
        opacity: 1;
        transform: translateY(0);
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

    font-weight: 800;
    font-size: 13px;
}

.chat-msg.ai .avatar {
    background:
        linear-gradient(
            135deg,
            #18d9a6,
            #079d77
        );

    box-shadow:
        0 7px 22px
        rgba(16,163,127,.2);
}

.chat-msg.user .avatar {
    background: #20252d;
}

.msg-content {
    max-width: min(760px, 82vw);

    color: #e9eaec;

    font-size: 15px;
    line-height: 1.75;

    padding-top: 3px;

    white-space: pre-wrap;

    overflow-wrap: anywhere;
}

.chat-msg.user .msg-content {
    padding: 11px 16px;

    background:
        #191e25;

    border-radius: 17px;
    border-top-right-radius: 5px;
}

/* THINKING */

.thinking {
    display: inline-flex;
    align-items: center;
    gap: 9px;

    color: #8e949d;

    font-size: 14px;
}

.thinking-dot {
    width: 7px;
    height: 7px;

    border-radius: 50%;

    background: #17d5a4;

    animation:
        pulseDot 1s infinite ease-in-out;
}

@keyframes pulseDot {
    0%,100% {
        opacity: .25;
        transform: scale(.7);
    }

    50% {
        opacity: 1;
        transform: scale(1);
    }
}

/* SOURCE */

.source {
    margin-top: 13px;

    color: #6f767f;

    font-size: 12px;
}

.source a {
    color: #18c99b;
}

/* IMAGES */

.image-grid {
    display: grid;

    grid-template-columns:
        repeat(3, minmax(0, 1fr));

    gap: 8px;

    margin-top: 15px;
}

.image-card {
    position: relative;
    overflow: hidden;

    border-radius: 12px;

    aspect-ratio: 1 / 1;

    background: #11151a;

    border:
        1px solid rgba(255,255,255,.07);
}

.image-card img {
    width: 100%;
    height: 100%;

    object-fit: cover;

    transition: .25s ease;
}

.image-card:hover img {
    transform: scale(1.04);
}

/* INPUT */

.chat-input-area {
    position: fixed;

    left: 50%;
    bottom: 14px;

    transform:
        translateX(-50%);

    width:
        min(940px, calc(100% - 24px));

    z-index: 500;
}

.chat-input-box {
    position: relative;

    padding: 6px;

    background:
        rgba(12,15,19,.88);

    border:
        1px solid rgba(255,255,255,.10);

    border-radius: 19px;

    box-shadow:
        0 20px 60px
        rgba(0,0,0,.45);

    backdrop-filter: blur(20px);
}

.chat-input-box input {
    width: 100%;

    padding:
        15px 60px 15px 17px;

    margin: 0;

    border: 0;

    color: white;

    background: transparent;

    outline: none;

    font-size: 15px;
}

.chat-input-box button {
    position: absolute;

    right: 8px;
    top: 50%;

    transform:
        translateY(-50%);

    width: 42px;
    height: 42px;

    border: 0;
    border-radius: 13px;

    display: flex;
    align-items: center;
    justify-content: center;

    color: white;

    background:
        linear-gradient(
            135deg,
            #19dca9,
            #0ab687
        );

    cursor: pointer;

    transition: .2s ease;
}

.chat-input-box button:hover {
    transform:
        translateY(-50%)
        scale(1.04);
}

.chat-input-box button:disabled {
    opacity: .45;
}

/* RESPONSIVE */

@media (max-width: 650px) {

    .navbar {
        padding: 0 14px;
    }

    .logo {
        font-size: 16px;
    }

    .nav-actions {
        gap: 1px;
    }

    .btn-nav {
        padding: 8px 7px;
        font-size: 12px;
    }

    .container {
        padding: 25px 20px;
    }

    .chat-history {
        padding-left: 13px;
        padding-right: 13px;
    }

    .msg-content {
        font-size: 14px;
    }

    .image-grid {
        grid-template-columns:
            repeat(2, minmax(0, 1fr));
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


# ============================================================
# 18. SAYFA RENDER
# ============================================================

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
                <a href="/dashboard"
                   class="btn-nav">
                    Dashboard
                </a>

                <a href="/chat"
                   class="btn-nav">
                    Sohbet
                </a>

                <a href="/info"
                   class="btn-nav">
                    Bilgi
                </a>

                <a href="/logout"
                   class="btn-nav">
                    Çıkış
                </a>
            """

        else:

            actions = """
                <a href="/info"
                   class="btn-nav">
                    Bilgi
                </a>

                <a href="/login"
                   class="btn-nav">
                    Giriş
                </a>

                <a href="/register"
                   class="btn-nav primary">
                    Kayıt Ol
                </a>
            """

        nav = f"""
        <div class="navbar">

            <a href="/" class="logo">
                <div class="logo-icon">
                    V
                </div>

                Vantorium
            </a>

            <div class="nav-actions">
                {actions}
            </div>

        </div>
        """

    return f"""
    <!DOCTYPE html>

    <html lang="tr">

    <head>

        <meta charset="UTF-8">

        <meta
            name="viewport"
            content="width=device-width,
            initial-scale=1.0,
            maximum-scale=1.0,
            user-scalable=no"
        >

        <meta
            name="theme-color"
            content="#07090b"
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


# ============================================================
# 19. ANA SAYFA
# ============================================================

@app.route("/")
def index():

    if get_current_user():
        return redirect("/chat")

    return redirect("/login")


# ============================================================
# 20. KAYIT
# ============================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if get_current_user():
        return redirect("/chat")

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

        if (
            len(username) < 3
            or len(password) < 6
        ):

            error = (
                "Kullanıcı adı en az 3, "
                "şifre en az 6 karakter olmalı."
            )

        else:

            conn = db()

            exists = conn.execute(
                "SELECT id FROM users "
                "WHERE username = ?",
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

    content = f"""

    <div class="auth-wrapper">

        <div class="container">

            <h2>
                Hesap Oluştur
            </h2>

            <p class="subtitle">
                Vantorium'a katıl ve
                kendi API anahtarını oluştur.
            </p>

            {f'<div class="error">{html.escape(error)}</div>' if error else ''}

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
                    placeholder="••••••••"
                >

                <button
                    type="submit"
                    class="btn"
                >
                    Kayıt Ol
                </button>

            </form>

            <div class="link-row">

                Hesabın var mı?
                <a href="/login">
                    Giriş Yap
                </a>

            </div>

        </div>

    </div>

    """

    return render_page(
        "Kayıt",
        content
    )


# ============================================================
# 21. GİRİŞ
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if get_current_user():
        return redirect("/chat")

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
            "SELECT * FROM users "
            "WHERE username = ?",
            (username,)
        ).fetchone()

        if (
            user
            and user["password_hash"]
            == hash_password(password)
        ):

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
                redirect("/chat")
            )

            response.set_cookie(
                "session_token",
                token,
                httponly=True,
                secure=True,
                samesite="Lax",
                max_age=30 * 24 * 3600
            )

            return response

        error = (
            "Kullanıcı adı veya şifre hatalı."
        )

        conn.close()

    content = f"""

    <div class="auth-wrapper">

        <div class="container">

            <h2>
                Tekrar Hoş Geldin
            </h2>

            <p class="subtitle">
                Vantorium hesabına giriş yap.
            </p>

            {f'<div class="error">{html.escape(error)}</div>' if error else ''}

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

            <div class="link-row">

                Hesabın yok mu?
                <a href="/register">
                    Kayıt Ol
                </a>

            </div>

        </div>

    </div>

    """

    return render_page(
        "Giriş",
        content
    )


# ============================================================
# 22. ÇIKIŞ
# ============================================================

@app.route("/logout")
def logout():

    token = request.cookies.get(
        "session_token"
    )

    if token:

        conn = db()

        conn.execute(
            "DELETE FROM sessions "
            "WHERE token = ?",
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


# ============================================================
# 23. DASHBOARD
# ============================================================

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

    <div class="container wide">

        <h1 class="page-title">
            Dashboard
        </h1>

        <p class="subtitle"
           style="font-size:15px">

            Hoş geldin,
            <strong style="color:white">
                {html.escape(user["username"])}
            </strong>.

            Vantorium API'ni buradan yönetebilirsin.

        </p>

        <div class="card">

            <h3>
                🔐 API Anahtarın
            </h3>

            <div class="api-key-box">
                {html.escape(user["api_key"])}
            </div>

            <p>
                API anahtarını kimseyle paylaşma.
            </p>

            <form
                method="POST"
                action="/regenerate-key"
                style="margin-top:15px"
            >

                <button
                    type="submit"
                    class="btn"
                    style="
                        background:#b52b35;
                        max-width:190px;
                    "
                >
                    Anahtarı Yenile
                </button>

            </form>

        </div>

        <div class="card">

            <h3>
                ⚡ API Kullanımı
            </h3>

            <p>
                HTTP GET isteği gönder:
            </p>

            <div class="code-block">
                {html.escape(example_url)}
            </div>

            <p>
                JSON olarak
                <code>"answer"</code>
                alanından cevabı alabilirsin.
            </p>

        </div>

    </div>

    """

    return render_page(
        "Dashboard",
        content,
        user
    )


# ============================================================
# 24. CHAT
# ============================================================

@app.route("/chat")
@login_required
def chat():

    user = get_current_user()

    content = """

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
                    Sorunu gönder; gerekiyorsa
                    web'de araştırıp en uygun
                    kısa cevabı hazırlayayım.

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
                        width="19"
                        height="19"
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
                        />

                        <polyline
                            points="5 12 12 5 19 12"
                        />

                    </svg>

                </button>

            </div>

        </div>

    </div>


<script>

const chatHistory =
    document.getElementById("chatHistory");

const chatInput =
    document.getElementById("chatInput");

const sendBtn =
    document.getElementById("sendBtn");


chatInput.addEventListener(
    "keydown",
    function(e) {

        if (
            e.key === "Enter"
            && !e.shiftKey
        ) {

            e.preventDefault();

            sendChat();
        }

    }
);


chatInput.focus();


function escapeHtml(text) {

    const div =
        document.createElement("div");

    div.textContent =
        text;

    return div.innerHTML;
}


function linkify(text) {

    return text.replace(
        /(https?:\\/\\/[^\\s]+)/g,
        function(url) {

            const safe =
                escapeHtml(url);

            return `
                <a
                    href="${safe}"
                    target="_blank"
                    rel="noopener noreferrer"
                >
                    ${safe}
                </a>
            `;
        }
    );

}


function formatAnswer(text) {

    let safe =
        escapeHtml(text);

    safe =
        safe.replace(
            /\\*\\*(.*?)\\*\\*/g,
            "<strong>$1</strong>"
        );

    safe =
        linkify(safe);

    return safe;
}


function scrollBottom() {

    chatHistory.scrollTop =
        chatHistory.scrollHeight;

}


function addMessage(
    text,
    sender
) {

    const div =
        document.createElement("div");

    div.className =
        "chat-msg " + sender;

    div.innerHTML = `

        <div class="avatar">
            ${sender === "user" ? "K" : "V"}
        </div>

        <div class="msg-content">
            ${formatAnswer(text)}
        </div>

    `;

    chatHistory.appendChild(
        div
    );

    scrollBottom();

    return div;
}


function addThinking() {

    const div =
        document.createElement("div");

    div.className =
        "chat-msg ai";

    div.innerHTML = `

        <div class="avatar">
            V
        </div>

        <div
            class="msg-content"
            id="thinkingText"
        >

            <span class="thinking">

                <span class="thinking-dot"></span>

                <span>
                    Düşünüyor...
                </span>

            </span>

        </div>

    `;

    chatHistory.appendChild(
        div
    );

    scrollBottom();

    return div;
}


function updateThinking(
    element,
    text
) {

    const target =
        element.querySelector(
            "#thinkingText"
        );

    if (!target)
        return;

    target.innerHTML = `

        <span class="thinking">

            <span class="thinking-dot"></span>

            <span>
                ${escapeHtml(text)}
            </span>

        </span>

    `;

    scrollBottom();
}


function showImages(
    parent,
    images
) {

    if (
        !images
        || !images.length
    ) {
        return;
    }

    const grid =
        document.createElement("div");

    grid.className =
        "image-grid";

    images.forEach(
        function(image) {

            const card =
                document.createElement("a");

            card.className =
                "image-card";

            card.href =
                image.url;

            card.target =
                "_blank";

            card.rel =
                "noopener noreferrer";

            const img =
                document.createElement("img");

            img.src =
                image.url;

            img.loading =
                "lazy";

            img.alt =
                image.title || "Görsel";

            card.appendChild(
                img
            );

            grid.appendChild(
                card
            );

        }
    );

    parent.appendChild(
        grid
    );

}


async function sendChat() {

    const text =
        chatInput.value.trim();

    if (!text)
        return;

    chatInput.value = "";

    sendBtn.disabled = true;

    addMessage(
        text,
        "user"
    );

    const thinking =
        addThinking();

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
                "Sunucu hatası"
            );
        }

        const reader =
            response.body.getReader();

        const decoder =
            new TextDecoder();

        let buffer = "";

        while (true) {

            const {
                done,
                value
            } = await reader.read();

            if (done)
                break;

            buffer +=
                decoder.decode(
                    value,
                    {
                        stream: true
                    }
                );

            const lines =
                buffer.split("\\n");

            buffer =
                lines.pop();

            for (
                const line
                of lines
            ) {

                if (!line.trim())
                    continue;

                try {

                    const data =
                        JSON.parse(line);

                    if (
                        data.type
                        === "status"
                    ) {

                        updateThinking(
                            thinking,
                            data.text
                        );

                    }

                    if (
                        data.type
                        === "result"
                    ) {

                        thinking.remove();

                        const answerBox =
                            addMessage(
                                data.answer,
                                "ai"
                            );

                        const content =
                            answerBox.querySelector(
                                ".msg-content"
                            );

                        if (
                            data.source
                            && data.source !==
                            "selamlama"
                        ) {

                            const source =
                                document.createElement(
                                    "div"
                                );

                            source.className =
                                "source";

                            source.textContent =
                                "Kaynak: "
                                + data.source;

                            content.appendChild(
                                source
                            );

                        }

                        showImages(
                            content,
                            data.images || []
                        );

                    }

                    if (
                        data.type
                        === "error"
                    ) {

                        thinking.remove();

                        addMessage(
                            data.message
                            || "Bir hata oluştu.",
                            "ai"
                        );

                    }

                } catch(e) {

                    console.error(
                        e
                    );

                }

            }

            scrollBottom();
        }

    } catch(error) {

        thinking.remove();

        addMessage(
            "Bağlantı sırasında bir hata oluştu. Lütfen tekrar dene.",
            "ai"
        );

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


# ============================================================
# 25. STREAM API
# ============================================================

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
        return jsonify({
            "error":
                "Mesaj boş olamaz."
        }), 400

    def generate():

        try:

            # 1
            yield json.dumps({
                "type": "status",
                "text": "Düşünüyor..."
            }, ensure_ascii=False) + "\n"

            time.sleep(.15)

            parts =
                analyze_query(kelime)

            # Basit cevaplarda gereksiz
            # bekletme yapma
            if (
                parts["is_greeting"]
                or parts["is_math"]
            ):

                yield json.dumps({
                    "type": "status",
                    "text": "Cevabı hazırlıyor..."
                }, ensure_ascii=False) + "\n"

            else:

                # 2
                yield json.dumps({
                    "type": "status",
                    "text": "Web'de arıyor..."
                }, ensure_ascii=False) + "\n"

                time.sleep(.2)

                # 3
                yield json.dumps({
                    "type": "status",
                    "text":
                        "Bulduğu bilgileri inceliyor..."
                }, ensure_ascii=False) + "\n"

                time.sleep(.2)

                # 4
                yield json.dumps({
                    "type": "status",
                    "text":
                        "En uygun cevabı hazırlıyor..."
                }, ensure_ascii=False) + "\n"

            answer, source, images = get_answer(
                kelime
            )

            yield json.dumps({
                "type": "result",
                "answer": answer,
                "source": source,
                "images": images
            }, ensure_ascii=False) + "\n"

        except Exception as e:

            yield json.dumps({
                "type": "error",
                "message":
                    "Cevap hazırlanırken hata oluştu."
            }, ensure_ascii=False) + "\n"

    return Response(
        generate(),
        mimetype="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no"
        }
    )


# ============================================================
# 26. API KEY YENİLE
# ============================================================

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
        "UPDATE users SET api_key = ? "
        "WHERE id = ?",
        (
            new_key,
            user["id"]
        )
    )

    conn.commit()
    conn.close()

    return redirect(
        "/dashboard"
    )


# ============================================================
# 27. BİLGİ / KURALLAR
# ============================================================

@app.route("/info")
def info():

    user = get_current_user()

    base_url = request.host_url.rstrip("/")

    content = f"""

    <div class="container wide">

        <h1 class="page-title">
            Vantorium Bilgi Merkezi
        </h1>

        <p class="subtitle"
           style="font-size:15px">

            Vantorium API, kullanım kuralları
            ve gizlilik bilgileri.

        </p>

        <div class="card">

            <h3>
                🤖 Vantorium Nedir?
            </h3>

            <p>
                Vantorium, kullanıcı sorularını
                analiz eden ve gerektiğinde web
                kaynaklarından bilgi araştırarak
                cevaplayan bir yapay zekâ
                asistanıdır.
            </p>

        </div>

        <h2 class="section-title">
            API Kullanımı
        </h2>

        <div class="card">

            <p>
                API anahtarınla istek gönderebilirsin:
            </p>

            <div class="code-block">
                {html.escape(base_url)}
                /api-key=SENIN_ANAHTARIN?word=merhaba
            </div>

            <p>
                API JSON formatında cevap verir.
            </p>

        </div>

        <h2 class="section-title">
            Kurallar
        </h2>

        <div class="card">

            <p>
                • API anahtarını paylaşma.<br><br>

                • Sistemi aşırı isteklerle
                zorlamaya çalışma.<br><br>

                • DDoS, SQL Injection,
                XSS ve benzeri saldırılar
                yasaktır.<br><br>

                • Yasa dışı faaliyetler için
                kullanma.<br><br>

                • Vantorium cevaplarının
                her zaman %100 doğru olduğu
                garanti edilmez.
            </p>

        </div>

        <h2 class="section-title">
            Gizlilik
        </h2>

        <div class="card">

            <p>
                Hesap işlemleri için kullanıcı adı,
                şifre özeti ve API anahtarı tutulur.
                Sistem performansı ve cevap kalitesi
                için bazı sorgular anonim şekilde
                hafızaya alınabilir.
            </p>

        </div>

        <h2 class="section-title">
            Sorumluluk Reddi
        </h2>

        <div class="card">

            <p>
                Vantorium tarafından oluşturulan
                cevaplar bilgilendirme amacıyla
                sunulur. Kritik tıbbi, hukuki veya
                finansal kararlar için bağımsız
                doğrulama yapılmalıdır.
            </p>

        </div>

        <div class="footer">
            © 2026 Vantorium AI
        </div>

    </div>

    """

    return render_page(
        "Bilgi",
        content,
        user
    )


# ============================================================
# 28. DIŞ API
# ============================================================

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
        "SELECT * FROM users "
        "WHERE api_key = ?",
        (apikey,)
    ).fetchone()

    conn.close()

    if not user:

        return jsonify({
            "error":
                "Geçersiz API anahtarı"
        }), 401

    start = time.time()

    answer, source, images = get_answer(
        word
    )

    return jsonify({
        "input": word,

        "answer": answer,

        "images": images,

        "meta": {

            "source": source,

            "time_ms":
                round(
                    (time.time() - start)
                    * 1000,
                    2
                ),

            "engine":
                "Vantorium Pro",

            "timestamp":
                datetime.now()
                .astimezone()
                .isoformat()
        }
    })


# ============================================================
# 29. ÇALIŞTIR
# ============================================================

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

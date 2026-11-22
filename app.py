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
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, Response, render_template_string, redirect, url_for, make_response

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# --- 1. VERİ TABANI ---
DB_FILE = 'vantorium.db'

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        api_key TEXT UNIQUE NOT NULL,
        created_at TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS memory (
        word TEXT PRIMARY KEY,
        answer TEXT,
        confidence REAL,
        source TEXT,
        created_at TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER,
        created_at TEXT
    )''')
    conn.commit()
    conn.close()

init_db()

def db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def memory_get(word):
    conn = db()
    row = conn.execute("SELECT answer FROM memory WHERE word = ?", (word,)).fetchone()
    conn.close()
    return row['answer'] if row else None

def memory_save(word, answer, confidence, source):
    conn = db()
    conn.execute("INSERT OR REPLACE INTO memory (word, answer, confidence, source, created_at) VALUES (?, ?, ?, ?, ?)",
              (word, answer, confidence, source, datetime.now().isoformat()))
    conn.commit()
    conn.close()

# --- 2. VERİ SETİ ---
def load_dataset():
    files = [
        'ultra_soru_cevap_30_cevapli.txt',
        'ultra_soru_cevap_30_cevapli.txt.txt',
        'storage/ultra_soru_cevap_30_cevapli.txt',
        'storage/ultra_soru_cevap_30_cevapli.txt.txt'
    ]
    data = {}
    for f in files:
        if os.path.exists(f):
            with open(f, 'r', encoding='utf-8') as file:
                current_q = None
                for line in file:
                    line = line.strip()
                    if not line or line.startswith('#'): continue
                    if line.startswith('Input:'):
                        current_q = normalize(line.replace('Input:', '').strip())
                        if current_q not in data: data[current_q] = []
                    elif line.startswith('Reply:') and current_q:
                        data[current_q].append(line.replace('Reply:', '').strip())
            break
    return data

def normalize(text):
    t = text.lower().strip()
    t = re.sub(r'\s+', ' ', t)
    t = re.sub(r'[?!.,;:]+$', '', t)
    return t.strip()

DATASET = load_dataset()

# --- 3. MOTOR & ARAMA ---
def analyze_query(query):
    q = query.lower()
    return {
        'is_greeting': bool(re.search(r'\b(merhaba|selam|hello|hi|hey|günaydın|nasılsın|naber|nbr)\b', q)),
        'is_math': bool(re.match(r'^[\d\s\+\-\*\/\(\)\.\,\^%]+$', query) and re.search(r'[\+\-\*\/\^%]', query)),
        'is_code': bool(re.search(r'\b(kod|function|class|php|javascript|python|api|hata|error|debug|yazılım|programlama)\b', q)),
    }

def web_search(query, parts):
    results = []
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    ]
    headers = {
        'User-Agent': random.choice(user_agents),
        'Accept': 'application/json, text/html, application/xhtml+xml, */*',
        'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
    }
    session = requests.Session()
    session.headers.update(headers)

    # 1. GOOGLE PROGRAMMABLE SEARCH (CSE)
    try:
        cse_url = f"https://cse.google.com/cse/element/v1?rsz=filtered_cse&num=3&hl=tr&source=gcsc&cselibv=8a5d5b6de8c9f12f&cx=f79f63e39ec7f4c78&q={urllib.parse.quote(query)}&safe=off&cse_tok=&exp=csqr,cc&callback=cb"
        r = session.get(cse_url, timeout=10)
        match = re.search(r'cb\((.*)\)', r.text, re.DOTALL)
        if match:
            g_data = json.loads(match.group(1))
            if 'results' in g_data:
                for item in g_data['results'][:3]:
                    results.append({
                        'title': item.get('titleNoFormatting', ''),
                        'url': item.get('unescapedUrl', ''),
                        'snippet': item.get('contentNoFormatting', ''),
                        'source': 'google'
                    })
    except Exception as e:
        pass

    # 2. WIKIPEDIA API
    try:
        wiki_url = f"https://tr.wikipedia.org/w/api.php?action=query&list=search&srsearch={urllib.parse.quote(query)}&utf8=&format=json&srlimit=2"
        r = session.get(wiki_url, timeout=10)
        w_data = r.json()
        if 'query' in w_data and 'search' in w_data['query']:
            for item in w_data['query']['search']:
                clean_snippet = re.sub(r'<[^>]+>', '', item.get('snippet', ''))
                results.append({
                    'title': item.get('title', ''),
                    'url': f"https://tr.wikipedia.org/wiki/{urllib.parse.quote(item.get('title', '').replace(' ', '_'))}",
                    'snippet': clean_snippet,
                    'source': 'wikipedia'
                })
    except Exception as e:
        pass

    # 3. GITHUB (Kod/Teknik sorularda)
    if parts['is_code']:
        try:
            gh_url = f"https://api.github.com/search/repositories?q={urllib.parse.quote(query)}&sort=stars&per_page=2"
            r = session.get(gh_url, timeout=10)
            if r.status_code == 200:
                for item in r.json().get('items', []):
                    results.append({
                        'title': item.get('full_name', ''),
                        'url': item.get('html_url', ''),
                        'snippet': item.get('description', '') or 'Açıklama yok.',
                        'source': 'github'
                    })
        except Exception as e:
            pass
            
    return results

def synthesize_results(query, results):
    if not results: return None
    lines = []
    seen = set()
    for r in results:
        if r['url'] in seen: continue
        seen.add(r['url'])
        snippet = r.get('snippet', '')
        if len(snippet) > 200: snippet = snippet[:197] + "..."
        line = f"• [{r['source'].upper()}] {r['title']}"
        if snippet: line += f"\n{snippet}"
        line += f"\n{r['url']}"
        lines.append(line)
        if len(lines) >= 4: break 
    
    header = f"'{query}' hakkında Google, Wikipedia ve diğer kaynaklardan bulduklarım:\n"
    return header + "\n\n".join(lines)

def get_answer(kelime):
    normalized = normalize(kelime)
    parts = analyze_query(kelime)
    if parts['is_greeting']:
        return random.choice(['Merhaba! Ben Vantorium. Sana nasıl yardımcı olabilirim?', 'Selam! Sistemler hazır, ne sormak istersin?']), "selamlama"
    elif parts['is_math']:
        try:
            return f"Sonuç: {eval(re.sub(r'[^\d\+\-\*\/\(\)\.\^% ]', '', kelime))}", "matematik"
        except: return "Matematik ifadesini çözemedim.", "hata"
    elif normalized in DATASET and DATASET[normalized]:
        return random.choice(DATASET[normalized]), "veri_seti"
    cached = memory_get(normalized)
    if cached: return cached, "hafiza"
    
    results = web_search(kelime, parts)
    if results:
        ans = synthesize_results(kelime, results)
        memory_save(normalized, ans, 0.8, "web")
        return ans, "web"
    return "Bunu bilmiyorum, internette de bulamadım.", "bulunamadi"

# --- 4. YARDIMCILAR ---
def get_current_user():
    token = request.cookies.get('session_token')
    if not token: return None
    conn = db()
    row = conn.execute("SELECT u.* FROM users u JOIN sessions s ON u.id = s.user_id WHERE s.token = ?", (token,)).fetchone()
    conn.close()
    return row

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not get_current_user():
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated

# --- 5. HTML & CSS (Gelişmiş Inter Tasarımı) ---
BASE_STYLE = """
<style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #09090b; color: #ededed; min-height: 100vh; -webkit-font-smoothing: antialiased; display: flex; flex-direction: column; }
    a { color: #10a37f; text-decoration: none; transition: color 0.15s ease; }
    a:hover { color: #34d399; text-decoration: none; }
    
    /* Navbar */
    .navbar { padding: 0 24px; height: 64px; border-bottom: 1px solid #1f1f1f; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; background: rgba(9, 9, 11, 0.85); backdrop-filter: blur(12px); z-index: 100; }
    .logo { display: flex; align-items: center; gap: 10px; color: #fff; font-weight: 700; font-size: 18px; letter-spacing: -0.5px; }
    .logo-icon { width: 28px; height: 28px; background: linear-gradient(135deg, #10a37f, #0d8c6c); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 15px; color: #fff; font-weight: 800; }
    .nav-actions { display: flex; gap: 12px; align-items: center; }
    .btn-nav { padding: 8px 16px; font-size: 14px; color: #a1a1a1; background: transparent; border: none; border-radius: 6px; cursor: pointer; text-decoration: none; font-weight: 500; transition: all 0.15s ease; }
    .btn-nav:hover { color: #fff; background: #1f1f1f; }
    .btn-nav.primary { background: #10a37f; color: #fff; }
    .btn-nav.primary:hover { background: #0d8c6c; }

    /* Auth Forms */
    .auth-wrapper { flex: 1; display: flex; align-items: center; justify-content: center; padding: 24px; }
    .container { width: 100%; max-width: 400px; padding: 40px; background: #111113; border: 1px solid #1f1f1f; border-radius: 16px; box-shadow: 0 8px 32px rgba(0,0,0,0.4); }
    .container.wide { max-width: 900px; margin: 40px auto; }
    
    h2 { font-size: 24px; font-weight: 600; margin-bottom: 6px; color: #fff; letter-spacing: -0.5px; }
    .subtitle { color: #888; font-size: 14px; margin-bottom: 28px; line-height: 1.5; }
    
    label { display: block; font-size: 13px; font-weight: 500; color: #ccc; margin-bottom: 6px; }
    input[type=text], input[type=password] { width: 100%; padding: 12px 14px; background: #09090b; border: 1px solid #27272a; border-radius: 8px; color: #fff; font-size: 14px; font-family: inherit; margin-bottom: 20px; outline: none; transition: border 0.15s ease, box-shadow 0.15s ease; }
    input:focus { border-color: #10a37f; box-shadow: 0 0 0 3px rgba(16,163,127,0.15); }
    
    .btn { width: 100%; padding: 12px; background: #10a37f; color: #fff; border: none; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; font-family: inherit; transition: background 0.15s ease; display: flex; justify-content: center; align-items: center; gap: 8px; }
    .btn:hover { background: #0d8c6c; }
    .btn.danger { background: #ef4444; }
    .btn.danger:hover { background: #dc2626; }
    .btn.secondary { background: #27272a; color: #fff; }
    .btn.secondary:hover { background: #3f3f46; }
    .btn-small { width: auto; padding: 8px 16px; font-size: 13px; }

    .link-row { text-align: center; margin-top: 24px; font-size: 14px; color: #888; }
    .error { background: rgba(239, 68, 68, 0.1); color: #f87171; padding: 12px; border-radius: 8px; margin-bottom: 20px; font-size: 14px; border: 1px solid rgba(239, 68, 68, 0.2); }

    /* Cards & Info */
    .card { background: #111113; border: 1px solid #1f1f1f; border-radius: 12px; padding: 28px; margin-bottom: 20px; }
    .card h3 { font-size: 16px; font-weight: 600; margin-bottom: 16px; color: #fff; display: flex; align-items: center; gap: 8px; }
    .card p { color: #a1a1a1; font-size: 14px; line-height: 1.7; margin-bottom: 12px; }
    .card ul { list-style: none; padding-left: 0; }
    .card ul li { padding: 10px 0; color: #a1a1a1; font-size: 14px; border-bottom: 1px solid #1f1f1f; display: flex; gap: 10px; line-height: 1.6; }
    .card ul li:last-child { border-bottom: none; }
    .card ul li::before { content: "•"; color: #10a37f; font-weight: bold; }

    .api-key-box { background: #09090b; border: 1px solid #27272a; padding: 16px; border-radius: 8px; font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 14px; word-break: break-all; color: #10a37f; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center; }
    .code-block { background: #09090b; border: 1px solid #27272a; padding: 16px; border-radius: 8px; font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 13px; color: #ededed; overflow-x: auto; margin: 12px 0; line-height: 1.6; }
    
    h1.page-title { font-size: 28px; margin-bottom: 8px; color: #fff; font-weight: 600; letter-spacing: -0.5px; }
    h2.section-title { font-size: 18px; margin-top: 40px; margin-bottom: 16px; color: #fff; font-weight: 600; padding-bottom: 8px; border-bottom: 1px solid #1f1f1f; }
    .footer { text-align: center; padding: 40px 20px; color: #555; font-size: 13px; border-top: 1px solid #1f1f1f; margin-top: auto; }

    /* Chat UI */
    .chat-layout { display: flex; flex-direction: column; flex: 1; max-width: 900px; margin: 0 auto; width: 100%; padding: 0 20px; height: calc(100vh - 64px); }
    .chat-history { flex: 1; overflow-y: auto; padding: 30px 0; display: flex; flex-direction: column; gap: 24px; scrollbar-width: thin; scrollbar-color: #27272a transparent; }
    .chat-history::-webkit-scrollbar { width: 6px; }
    .chat-history::-webkit-scrollbar-thumb { background-color: #27272a; border-radius: 10px; }
    
    .chat-msg { display: flex; gap: 16px; width: 100%; max-width: 800px; margin: 0 auto; }
    .chat-msg.user { flex-direction: row-reverse; }
    .chat-msg .avatar { width: 32px; height: 32px; border-radius: 6px; display: flex; align-items: center; justify-content: center; font-weight: 600; font-size: 13px; flex-shrink: 0; }
    .chat-msg.user .avatar { background: #27272a; color: #fff; }
    .chat-msg.ai .avatar { background: #10a37f; color: #fff; }
    .msg-content { color: #ededed; font-size: 15px; line-height: 1.7; white-space: pre-wrap; padding-top: 4px; }
    .chat-msg.user .msg-content { background: #1f1f1f; padding: 12px 18px; border-radius: 18px; border-top-right-radius: 4px; }
    
    .chat-input-area { padding: 20px 0 30px; background: #09090b; }
    .chat-input-box { position: relative; max-width: 800px; margin: 0 auto; }
    .chat-input-box input { width: 100%; padding: 16px 56px 16px 20px; background: #111113; border: 1px solid #27272a; border-radius: 12px; color: #fff; font-size: 15px; outline: none; font-family: inherit; margin: 0; transition: border 0.15s ease, box-shadow 0.15s ease; box-shadow: 0 4px 20px rgba(0,0,0,0.2); }
    .chat-input-box input:focus { border-color: #10a37f; box-shadow: 0 0 0 3px rgba(16,163,127,0.15); }
    .chat-input-box button { position: absolute; right: 8px; top: 50%; transform: translateY(-50%); width: 36px; height: 36px; border-radius: 8px; padding: 0; display: flex; align-items: center; justify-content: center; background: #10a37f; border: none; cursor: pointer; color: #fff; transition: background 0.15s ease; }
    .chat-input-box button:hover { background: #0d8c6c; }
</style>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
"""

def render_page(title, content, user=None, show_nav=True):
    nav = ""
    if show_nav:
        if user:
            actions = '<a href="/chat" class="btn-nav">Sohbet</a><a href="/dashboard" class="btn-nav">Dashboard</a><a href="/info" class="btn-nav">Kurallar</a><a href="/logout" class="btn-nav">Çıkış</a>'
        else:
            actions = '<a href="/info" class="btn-nav">Kurallar</a><a href="/login" class="btn-nav">Giriş</a><a href="/register" class="btn-nav primary">Kayıt Ol</a>'

        nav = f"""
        <div class="navbar">
            <a href="/" class="logo"><div class="logo-icon">V</div>Vantorium</a>
            <div class="nav-actions">
                {actions}
            </div>
        </div>
        """
    return f"""<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>{title} | Vantorium</title>{BASE_STYLE}</head><body>{nav}{content}</body></html>"""

# --- 6. ROUTES ---
@app.route('/')
def index():
    if get_current_user(): return redirect('/dashboard')
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if get_current_user(): return redirect('/dashboard')
    
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if len(username) < 3 or len(password) < 6:
            error = "Kullanıcı adı en az 3, şifre en az 6 karakter olmalı."
        else:
            conn = db()
            if conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
                error = "Bu kullanıcı adı zaten alınmış."
            else:
                api_key = "vnt_" + secrets.token_hex(24)
                conn.execute("INSERT INTO users (username, password_hash, api_key, created_at) VALUES (?, ?, ?, ?)",
                             (username, hash_password(password), api_key, datetime.now().isoformat()))
                conn.commit()
                conn.close()
                return redirect('/login')
            conn.close()
    
    content = f"""
    <div class="auth-wrapper">
        <div class="container">
            <h2>Hesap Oluştur</h2>
            <p class="subtitle">Vantorium'a katılarak kendi API anahtarını oluştur.</p>
            {f'<div class="error">{error}</div>' if error else ''}
            <form method="POST">
                <label>Kullanıcı Adı</label>
                <input type="text" name="username" required autocomplete="username" placeholder="kullanici_adi">
                <label>Şifre</label>
                <input type="password" name="password" required autocomplete="new-password" placeholder="••••••••">
                <button type="submit" class="btn">Kayıt Ol</button>
            </form>
            <div class="link-row">Hesabın var mı? <a href="/login">Giriş Yap</a></div>
        </div>
    </div>
    """
    return render_page("Kayıt", content)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if get_current_user(): return redirect('/dashboard')
    
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        conn = db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and user['password_hash'] == hash_password(password):
            token = secrets.token_hex(32)
            conn.execute("INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
                         (token, user['id'], datetime.now().isoformat()))
            conn.commit()
            conn.close()
            resp = make_response(redirect('/dashboard'))
            resp.set_cookie('session_token', token, httponly=True, max_age=30*24*3600)
            return resp
        error = "Kullanıcı adı veya şifre hatalı."
        conn.close()
    
    content = f"""
    <div class="auth-wrapper">
        <div class="container">
            <h2>Tekrar Hoş Geldin</h2>
            <p class="subtitle">Hesabına giriş yaparak dashboard'a eriş.</p>
            {f'<div class="error">{error}</div>' if error else ''}
            <form method="POST">
                <label>Kullanıcı Adı</label>
                <input type="text" name="username" required autocomplete="username" placeholder="kullanici_adi">
                <label>Şifre</label>
                <input type="password" name="password" required autocomplete="current-password" placeholder="••••••••">
                <button type="submit" class="btn">Giriş Yap</button>
            </form>
            <div class="link-row">Hesabın yok mu? <a href="/register">Kayıt Ol</a></div>
        </div>
    </div>
    """
    return render_page("Giriş", content)

@app.route('/logout')
def logout():
    token = request.cookies.get('session_token')
    if token:
        conn = db()
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()
    resp = make_response(redirect('/login'))
    resp.delete_cookie('session_token')
    return resp

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    base_url = request.host_url.rstrip('/')
    example_url = f"{base_url}/api-key={user['api_key']}?word=merhaba"
    
    content = f"""
    <div class="container wide">
        <h1 class="page-title">Dashboard</h1>
        <p class="subtitle" style="font-size:15px;">Hoş geldin, <strong style="color:#fff;">{user['username']}</strong>. API anahtarını aşağıdan yönetebilirsin.</p>
        
        <div class="card">
            <h3>API Anahtarın</h3>
            <div class="api-key-box">
                {user['api_key']}
            </div>
            <p style="color:#888;font-size:13px;">Bu anahtarı kimseyle paylaşma. Güvenliğin için düzenli olarak yenileyebilirsin.</p>
            <form method="POST" action="/regenerate-key" style="margin-top:16px;">
                <button type="submit" class="btn danger btn-small">Anahtarı Yenile</button>
            </form>
        </div>

        <div class="card">
            <h3>Kullanım Örneği</h3>
            <p>Aşağıdaki adrese HTTP GET isteği atarak API'yi kullanabilirsin:</p>
            <div class="code-block">{example_url}</div>
            <p style="color:#888;font-size:13px;margin-bottom:0;">Yanıt JSON formatında döner. <code style="color:#10a37f;">"answer"</code> alanı asistanın cevabıdır.</p>
        </div>
    </div>
    """
    return render_page("Dashboard", content, user)

@app.route('/chat')
@login_required
def chat():
    user = get_current_user()
    content = """
    <div class="chat-layout">
        <div class="chat-history" id="chatHistory">
            <div class="chat-msg ai">
                <div class="avatar">V</div>
                <div class="msg-content">Merhaba! Ben Vantorium. Geçmiş sohbetlerini hatırlarım, bilmediğim şeyleri Google, Wikipedia ve GitHub üzerinden araştırırım. Ne sormak istersin?</div>
            </div>
        </div>
        <div class="chat-input-area">
            <div class="chat-input-box">
                <input type="text" id="chatInput" placeholder="Vantorium'a bir şey sor..." autocomplete="off">
                <button onclick="sendChat()" id="sendBtn">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="19" x2="12" y2="5"></line><polyline points="5 12 12 5 19 12"></polyline></svg>
                </button>
            </div>
        </div>
    </div>
    <script>
        const chatHistory = document.getElementById('chatHistory');
        const chatInput = document.getElementById('chatInput');
        
        chatInput.addEventListener('keypress', e => { if (e.key === 'Enter') sendChat(); });
        chatInput.focus();

        function addMsg(text, sender) {
            const div = document.createElement('div');
            div.className = 'chat-msg ' + sender;
            div.innerHTML = `<div class="avatar">${sender === 'user' ? 'K' : 'V'}</div><div class="msg-content">${text}</div>`;
            chatHistory.appendChild(div);
            chatHistory.scrollTop = chatHistory.scrollHeight;
            return div;
        }

        async function sendChat() {
            const text = chatInput.value.trim();
            if (!text) return;
            chatInput.value = '';
            addMsg(text, 'user');
            const aiMsg = addMsg('Düşünüyor...', 'ai');
            const contentDiv = aiMsg.querySelector('.msg-content');
            
            try {
                const res = await fetch('/api/chat', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({message: text})
                });
                const reader = res.body.getReader();
                const decoder = new TextDecoder();
                contentDiv.innerHTML = '';
                while (true) {
                    const {done, value} = await reader.read();
                    if (done) break;
                    contentDiv.innerHTML += decoder.decode(value, {stream: true});
                    chatHistory.scrollTop = chatHistory.scrollHeight;
                }
            } catch(e) { contentDiv.innerHTML = 'Bağlantı hatası.'; }
        }
    </script>
    """
    return render_page("Sohbet", content, user)

@app.route('/api/chat', methods=['POST'])
@login_required
def api_chat():
    data = request.json
    kelime = data.get('message', '')
    answer, _ = get_answer(kelime)
    def generate():
        for char in answer:
            yield char
            time.sleep(0.01)
    return Response(generate(), mimetype='text/plain')

@app.route('/regenerate-key', methods=['POST'])
@login_required
def regenerate_key():
    user = get_current_user()
    new_key = "vnt_" + secrets.token_hex(24)
    conn = db()
    conn.execute("UPDATE users SET api_key = ? WHERE id = ?", (new_key, user['id']))
    conn.commit()
    conn.close()
    return redirect('/dashboard')

@app.route('/info')
def info():
    user = get_current_user()
    base_url = request.host_url.rstrip('/')
    content = f"""
    <div class="container wide">
        <h1 class="page-title">Bilgi Merkezi</h1>
        <p class="subtitle" style="font-size:15px;">Vantorium API'sini kullanmadan önce bilmen gereken her şey.</p>
        
        <div class="card">
            <h3>Vantorium Nedir?</h3>
            <p>Vantorium, doğal dildeki sorulara anlamlı ve hızlı yanıt üretebilen bir yapay zekâ asistanıdır. Kendi bilgi tabanı, Google, Wikipedia ve GitHub gibi devasa kaynaklardan gelen verilerle çalışır. Amacı, kullanıcılarına en doğru ve güncel cevapları sunmaktır.</p>
        </div>

        <h2 class="section-title">API Anahtarı Kullanımı</h2>
        <div class="card">
            <p>API anahtarın, hesabına bağlı olarak oluşturulur ve tüm isteklerinde kimlik doğrulaması için kullanılır. Anahtarın aşağıdaki formatta çalışır:</p>
            <div class="code-block">{base_url}/api-key=SENIN_ANAHTARIN?word=kelime</div>
            <p>Örnek bir istek:</p>
            <div class="code-block">{base_url}/api-key=vnt_ornekanahtar123?word=merhaba</div>
            <p style="color:#f87171;"><strong>Dikkat:</strong> API anahtarını kimseyle paylaşmamalısın. Anahtar sızıntısı durumunda hesabın geçici olarak askıya alınabilir. Yeni anahtar oluşturmak için Dashboard'u kullanabilirsin.</p>
        </div>

        <h2 class="section-title">Kurallar ve Koşullar</h2>
        <div class="card">
            <ul>
                <li>API anahtarını üçüncü taraflarla paylaşmak kesinlikle yasaktır.</li>
                <li>Sisteme zarar vermeye yönelik istekler (DDoS, SQL Injection, XSS vb.) yasaktır.</li>
                <li>Yasa dışı faaliyetler için kullanım tespit edilirse hesabın kalıcı olarak kapatılır.</li>
                <li>Otomatik botlarla saniyede 10'dan fazla istek atmak hizmet kalitesini düşürür ve hesap askıya alınabilir.</li>
                <li>Vantorium, sağladığı cevapların %100 doğruluğunu garanti etmez. Kritik kararlar için doğrulama yapmalısın.</li>
                <li>Sistem kaynaklarını tüketmeye yönelik aşırı yük bindiren istekler engellenir.</li>
            </ul>
        </div>

        <h2 class="section-title">Gizlilik ve Veri Politikası</h2>
        <div class="card">
            <p>Kullanıcı adı, şifre ve API anahtarı dışında hiçbir kişisel veri kaydedilmez. Yaptığın sohbetler, sistemin öğrenmesi amacıyla anonim olarak saklanabilir. Kişisel verilerin üçüncü taraflarla kesinlikle paylaşılmaz. Verilerin güvenliği için endüstri standartlarında şifreleme kullanılır.</p>
        </div>

        <h2 class="section-title">Hizmet Kullanımı</h2>
        <div class="card">
            <p>Vantorium, kişisel kullanım için tamamen ücretsizdir. Ticari kullanım için önceden iletişime geçmen gerekir. Hizmet, önceden bildirim yapılmaksızın güncellenebilir veya bakım için geçici olarak durdurulabilir. Planlı bakımlar önceden duyurulur.</p>
        </div>
        
        <h2 class="section-title">Yasal Uyarı ve Sorumluluk Reddi</h2>
        <div class="card">
            <p>Vantorium tarafından üretilen cevaplar yalnızca bilgilendirme amaçlıdır. Tıbbi, hukuki veya finansal tavsiye niteliği taşımaz. Bu cevaplara dayanarak alınan kararlardan doğacak sonuçlardan kullanıcı sorumludur. Vantorium, hizmetin kesintisiz veya hatasız olacağını garanti etmez.</p>
        </div>

        <h2 class="section-title">Destek ve İletişim</h2>
        <div class="card">
            <p>Kurallar, hizmet veya hesabınla ilgili soruların için Dashboard üzerinden iletişime geçebilirsin. Teknik destek ekibimiz en kısa sürede geri dönüş yapacaktır.</p>
        </div>

        <div class="footer">
            &copy; 2026 Vantorium AI. Tüm hakları saklıdır.
        </div>
    </div>
    """
    return render_page("Bilgi", content, user)

# --- 7. DIŞ API (Key Doğrulamalı) ---
@app.route('/api-key=<apikey>', methods=['GET'])
def api_word(apikey):
    word = request.args.get('word')
    if not word:
        return jsonify({'error': 'word parametresi gerekli', 'usage': '/api-key=...?word=kelime'}), 400
    
    conn = db()
    user = conn.execute("SELECT * FROM users WHERE api_key = ?", (apikey,)).fetchone()
    conn.close()
    if not user:
        return jsonify({'error': 'Geçersiz API anahtarı'}), 401
    
    start = time.time()
    answer, source = get_answer(word)
    
    return jsonify({
        'input': word,
        'answer': answer,
        'meta': {
            'source': source,
            'time_ms': round((time.time() - start) * 1000, 2),
            'engine': 'Vantorium v4.1',
            'timestamp': datetime.now().astimezone().isoformat()
        }
    })

# --- 8. ÇALIŞTIR ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

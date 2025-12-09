# mitm_to_flask.py
from mitmproxy import http
import re, json, base64, threading, requests, os, time, socket
from datetime import datetime
from collections import deque
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------- 配置 (可通过环境变量覆盖) ----------
def get_local_ip():
    """自动获取本机在当前网络下的局域网 IP"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # 这里并不会真的发请求，只是用来判断本机出口 IP
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

# 优先使用环境变量 FLASK_API_URL，否则动态获取 IP
API_URL = os.getenv("FLASK_API_URL", f"http://{get_local_ip()}:5000/api/sessions")
POST_INTERVAL = float(os.getenv("MITM_POST_INTERVAL", "0.12"))  # worker 每条之间的间隔 (秒)
MAX_RETRIES = int(os.getenv("MITM_MAX_RETRIES", "3"))
REQUEST_TIMEOUT = float(os.getenv("MITM_REQUEST_TIMEOUT", "5.0"))
API_TOKEN = os.getenv("FLASK_API_TOKEN") or os.getenv("ADMIN_TOKEN") or os.getenv("MITM_API_TOKEN")
if not API_TOKEN:
    raise RuntimeError("???? FLASK_API_TOKEN/ADMIN_TOKEN???????? /api/sessions ??")
AUTH_HEADERS = {"X-ADMIN-TOKEN": API_TOKEN}


# ---------- 内部队列与 worker 管理 ----------
_queue = deque()
_queue_lock = threading.Lock()
_worker_started = False
_stop_event = threading.Event()

# requests session with some retries for transient network issues
_session = requests.Session()
_retry_strategy = Retry(total=2, backoff_factor=0.3, status_forcelist=(500,502,503,504))
_adapter = HTTPAdapter(max_retries=_retry_strategy)
_session.mount("http://", _adapter)
_session.mount("https://", _adapter)

# ---------- 帮助函数 ----------
def looks_like_base64(s: str):
    if not s: return False
    s = s.strip()
    if len(s) % 4 != 0 or len(s) < 8:
        return False
    try:
        return base64.b64encode(base64.b64decode(s)) == s.encode()
    except Exception:
        return False

def detect_sensitive_from_text(text: str):
    """
    返回 list[str]，例如 ["phone", "email", "base64:abcd..."]
    保证所有元素都是字符串，避免返回复杂结构导致后端错误。
    """
    hits = []
    if not text:
        return hits
    # 中国手机号样式（简单检测）
    if re.search(r"\b1[3-9]\d{9}\b", text):
        hits.append("phone")
    # 简单邮箱检测
    if re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text):
        hits.append("email")
    # 可能的 base64 token
    tokens = re.findall(r"[A-Za-z0-9+/=]{8,}", text)
    for t in tokens:
        if looks_like_base64(t):
            short = t if len(t) <= 32 else (t[:29] + "...")
            hits.append(f"base64:{short}")
    # 去重并保持顺序
    seen = set(); out = []
    for h in hits:
        if h not in seen:
            seen.add(h); out.append(h)
    return out

def _enqueue(payload):
    with _queue_lock:
        _queue.append(payload)

def _dequeue():
    with _queue_lock:
        if _queue:
            return _queue.popleft()
    return None

def _worker():
    """
    后台 worker：从队列取出项并 POST 到后端，失败则按 MAX_RETRIES 重试，
    若仍失败则打印错误并丢弃（避免无限重试导致内存占用）
    """
    while not _stop_event.is_set():
        item = _dequeue()
        if item is None:
            time.sleep(POST_INTERVAL)
            continue
        attempt = 0
        success = False
        while attempt < MAX_RETRIES and not success and not _stop_event.is_set():
            attempt += 1
            try:
                resp = _session.post(API_URL, json=item, timeout=REQUEST_TIMEOUT, headers=AUTH_HEADERS)
                if resp.status_code in (200, 201):
                    print(f"[mitm->flask] post ok (attempt {attempt}) {item.get('method')} {item.get('url')}")
                    success = True
                    break
                else:
                    print(f"[mitm->flask] post failed {resp.status_code} (attempt {attempt}) resp={resp.text}")
            except Exception as e:
                print(f"[mitm->flask] post exception (attempt {attempt}): {e}")
            # 指数/线性退避
            time.sleep(0.5 * attempt)
        if not success:
            print(f"[mitm->flask] giving up after {attempt} attempts for {item.get('url')}")
        # 控制发送速率，避免短时间内大量请求压垮后端
        time.sleep(POST_INTERVAL)

def ensure_worker_started():
    global _worker_started
    if not _worker_started:
        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        _worker_started = True

# ---------- mitmproxy hook: request ----------
def request(flow: http.HTTPFlow) -> None:
    """
    mitmproxy 收到 HTTP 请求时调用，将会话放入队列异步上报
    """
    try:
        try:
            body = flow.request.get_text(strict=False)
        except Exception:
            body = ""
        url = getattr(flow.request, "pretty_url", flow.request.url)
        headers = dict(flow.request.headers)
        method = flow.request.method
        time_str = datetime.utcnow().isoformat() + "Z"

        suspicious = detect_sensitive_from_text((body or "") + " " + json.dumps(headers, ensure_ascii=False))

        payload = {
            "time": time_str,
            "client": str(flow.client_conn.address),
            "method": method,
            "url": url,
            "headers": headers,
            "body": body,
            "suspicious": suspicious
        }

        _enqueue(payload)
        ensure_worker_started()

        if suspicious:
            print("[SUSP] ", method, url, suspicious)
        else:
            print("[OK] ", method, url)
    except Exception as e:
        # 防止插件异常导致 mitmproxy 崩溃
        print("[mitm plugin error]", e)

# ---------- mitmproxy done (clean shutdown) ----------
def done():
    _stop_event.set()
    # 给 worker 短暂时间退出
    time.sleep(0.2)

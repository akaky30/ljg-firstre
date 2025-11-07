# app.py
# MITM 会话可视化：Flask + Flask-SocketIO + Frida helpers
from flask import Flask, request, jsonify, send_file
from flask_socketio import SocketIO
import sqlite3, os, uuid, json, subprocess, re, time, csv, traceback, logging, threading
from io import StringIO
from functools import wraps

# ---------- frida python optional import ----------
try:
    import frida
    FRIDA_PY_AVAILABLE = True
except Exception:
    FRIDA_PY_AVAILABLE = False

# ---------- 配置 ----------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB = os.path.join(BASE_DIR, "sessions.db")
FRIDA_DIR = os.path.join(BASE_DIR, "frida_out")
os.makedirs(FRIDA_DIR, exist_ok=True)
LOGFILE = os.path.join(BASE_DIR, "server_debug.log")

# 日志配置
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s",
                    handlers=[logging.FileHandler(LOGFILE, encoding="utf-8"),
                              logging.StreamHandler()])

# 强制使用线程模式，避免不同 async driver 的跨线程 emit 问题
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ADMIN_TOKEN 可选保护
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")

# ------------------ 工具函数 ------------------
def safe_load_json(s, default=None):
    if s is None:
        return default
    if isinstance(s, (list, dict)):
        return s
    try:
        return json.loads(s)
    except Exception:
        return default

def db_conn():
    return sqlite3.connect(DB, timeout=10)

def init_db():
    conn = db_conn()
    conn.execute("""CREATE TABLE IF NOT EXISTS sessions(
        id TEXT PRIMARY KEY, time TEXT, url TEXT, method TEXT, headers TEXT, body TEXT, suspicious TEXT
    )""")
    conn.commit()
    conn.close()
    logging.info("DB initialized at: %s", DB)

init_db()

# ------------------ 简单敏感检测 ------------------
SENSITIVE_PATTERNS = {
    "手机号": re.compile(r"\b1\d{10}\b"),
    "邮箱": re.compile(r"\b[\w\.-]+@[\w\.-]+\.\w+\b"),
    "身份证": re.compile(r"\b(\d{15}|\d{17}[\dXx])\b"),
    "token": re.compile(r"(?i)(?:token|access_token|auth)[\"'=:\s]*([A-Za-z0-9\-_\.]+)"),
    "password": re.compile(r"(?i)password[\"'=:\s]*([^&\s]+)")
}

def pick_exact_pid_from_ps(ps_output: str, target_app: str):
    """
    从 frida-ps -Uai 的输出里，尽量选主进程 PID：
    - 优先匹配整行末尾恰好是 target_app 的行（避免 :push / :remote）
    - 再退而求其次匹配“最后一列等于 target_app”的行
    返回 int 或 None
    """
    best = None
    for ln in (ps_output or "").splitlines():
        s = ln.strip()
        if not s:
            continue
        parts = s.split()
        # 先判定是否匹配“恰好就是包名（无冒号后缀）”
        if s.endswith(" " + target_app) or s.endswith("\t" + target_app) or (len(parts) >= 2 and parts[-1] == target_app):
            # 抓第一个纯数字 token 当 PID
            for tok in parts:
                if tok.isdigit():
                    return int(tok)

        # 记录一个退路：包含 target_app 但不是严格等于（比如 :remote），仅在完全找不到时用
        if target_app in s and best is None:
            for tok in parts:
                if tok.isdigit():
                    best = int(tok)
                    break
    return best


def detect_sensitive(text: str) -> list:
    if not text:
        return []
    found = []
    for name, pat in SENSITIVE_PATTERNS.items():
        if pat.search(text):
            found.append(name)
    return found

# ------------------ 权限装饰器 ------------------
def require_token(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not ADMIN_TOKEN:
            return fn(*args, **kwargs)
        token = request.headers.get("X-ADMIN-TOKEN") or request.args.get("token")
        if token != ADMIN_TOKEN:
            return jsonify({"error":"unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper

# === External Frida template loader （新增）===
from dataclasses import dataclass
import glob

SCRIPTS_DIR = os.path.join(BASE_DIR, "frida_scripts")

@dataclass
class TemplateSpec:
    name: str
    path: str
    code: str
    meta: dict
    mtime: float

TEMPLATE_CACHE = {}  # name -> TemplateSpec

def _load_meta(js_path: str) -> dict:
    meta_path = js_path.replace(".js", ".meta.json")
    if os.path.exists(meta_path):
        with open(meta_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"display_name": os.path.basename(js_path),
            "required_params": [], "targets": [], "risks": [], "defaults": {}}

def load_templates():
    os.makedirs(SCRIPTS_DIR, exist_ok=True)
    for js_path in glob.glob(os.path.join(SCRIPTS_DIR, "*.js")):
        name = os.path.splitext(os.path.basename(js_path))[0]
        mtime = os.path.getmtime(js_path)
        if name in TEMPLATE_CACHE and TEMPLATE_CACHE[name].mtime == mtime:
            continue
        with open(js_path, "r", encoding="utf-8") as f:
            code = f.read()
        TEMPLATE_CACHE[name] = TemplateSpec(
            name=name, path=js_path, code=code, meta=_load_meta(js_path), mtime=mtime
        )

# safe_format 与参数渲染（保留 + 新增对外置模板的渲染）
class SafeDict(dict):
    def __missing__(self, key):
        return "{%s}" % key

def safe_format(tpl: str, **params):
    try:
        return tpl.format_map(SafeDict(**params))
    except Exception:
        out = tpl
        for k, v in params.items():
            out = out.replace("{" + k + "}", str(v))
        return out

def render_template_external(name: str, params: dict) -> str:
    """从外置模板缓存中渲染脚本（带 defaults / required 校验）"""
    load_templates()
    spec = TEMPLATE_CACHE.get(name)
    if not spec:
        raise ValueError(f"template not found: {name}")
    merged = dict(spec.meta.get("defaults", {}))
    merged.update(params or {})
    missing = [k for k in spec.meta.get("required_params", [])
               if merged.get(k) in (None, "", [])]
    if missing:
        raise ValueError(f"missing required params: {missing}")
    return safe_format(spec.code, **merged)

# ------------------ Sessions API ------------------
@app.route("/api/sessions", methods=["POST"])
def add_session():
    try:
        j = request.get_json(force=True, silent=True) or {}
        logging.info("Received POST /api/sessions payload keys: %s", list(j.keys()))
        sid = str(uuid.uuid4())
        time_str = j.get("time") or time.strftime("%Y-%m-%d %H:%M:%S")
        url = j.get("url") or j.get("request_url") or j.get("uri") or ""
        method = j.get("method") or j.get("http_method") or ""
        headers = j.get("headers") or {}
        body = j.get("body") or ""

        if isinstance(headers, str):
            parsed = safe_load_json(headers, default={})
            headers_parsed = parsed or {}
        else:
            headers_parsed = headers

        provided = j.get("suspicious") or []
        normalized_provided = []
        if isinstance(provided, str):
            parsed = safe_load_json(provided, default=None)
            if isinstance(parsed, list):
                provided = parsed
            else:
                provided = [provided]
        for it in provided:
            if it is None:
                continue
            if isinstance(it, str):
                normalized_provided.append(it)
            elif isinstance(it, (list, tuple)) and len(it) >= 1:
                try:
                    k = str(it[0]); v = str(it[1]) if len(it) > 1 else ""
                    normalized_provided.append(f"{k}:{v}" if v else k)
                except:
                    normalized_provided.append(str(it))
            elif isinstance(it, dict):
                t = it.get("type") or it.get("name")
                v = it.get("value") or it.get("val") or ""
                if t:
                    normalized_provided.append(f"{t}:{v}" if v else t)
                else:
                    normalized_provided.append(json.dumps(it, ensure_ascii=False))
            else:
                normalized_provided.append(str(it))

        headers_text = json.dumps(headers_parsed, ensure_ascii=False)
        body_text = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)
        combined = headers_text + "\n" + body_text
        detected = detect_sensitive(combined)

        merged = normalized_provided + detected
        seen = set(); suspicious_final = []
        for x in merged:
            if x not in seen:
                seen.add(x); suspicious_final.append(x)

        conn = db_conn()
        conn.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?,?)",
                     (sid, time_str, url, method,
                      json.dumps(headers_parsed, ensure_ascii=False), body_text, json.dumps(suspicious_final, ensure_ascii=False)))
        conn.commit()
        conn.close()

        logging.info("Stored session %s url=%s method=%s suspicious=%s", sid, url, method, suspicious_final)
        socketio.emit("session_new", {"id": sid, "time": time_str, "url": url, "method": method, "suspicious": suspicious_final})
        return jsonify({"id": sid}), 201
    except Exception as e:
        logging.error("add_session error: %s\n%s", e, traceback.format_exc())
        return jsonify({"error":"server error", "detail": str(e)}), 500

@app.route("/api/sessions", methods=["GET"])
def list_sessions():
    q = request.args.get("q", "").strip()
    try:
        limit = int(request.args.get("limit", 200))
    except:
        limit = 200
    try:
        offset = int(request.args.get("offset", 0))
    except:
        offset = 0
    conn = db_conn(); cur = conn.cursor()
    if q:
        q_like = f"%{q}%"
        rows = cur.execute("SELECT id,time,url,method,suspicious FROM sessions WHERE url LIKE ? OR method LIKE ? OR body LIKE ? ORDER BY time DESC LIMIT ? OFFSET ?",
                           (q_like,q_like,q_like,limit,offset)).fetchall()
    else:
        rows = cur.execute("SELECT id,time,url,method,suspicious FROM sessions ORDER BY time DESC LIMIT ? OFFSET ?",
                           (limit, offset)).fetchall()
    conn.close()
    out=[]
    for r in rows:
        susp = safe_load_json(r[4], default=[])
        out.append({"id": r[0], "time": r[1], "url": r[2], "method": r[3], "suspicious": susp})
    return jsonify(out)

@app.route("/api/sessions/<sid>", methods=["GET"])
def get_session(sid):
    try:
        conn = db_conn()
        row = conn.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        conn.close()
        if not row:
            return jsonify({"error":"not found"}), 404
        headers = safe_load_json(row[4], default={})
        suspicious = safe_load_json(row[6], default=[])
        return jsonify({"id":row[0],"time":row[1],"url":row[2],"method":row[3],"headers":headers,"body":row[5],"suspicious":suspicious})
    except Exception as e:
        logging.error("get_session error: %s\n%s", e, traceback.format_exc())
        return jsonify({"error":"server error"}), 500

@app.route("/api/clear_sessions", methods=["POST"])
@require_token
def clear_sessions():
    try:
        conn = db_conn()
        conn.execute("DELETE FROM sessions")
        conn.commit()
        conn.close()
        logging.info("All sessions cleared by API")
        socketio.emit("sessions_cleared", {})
        return jsonify({"status":"ok", "msg":"all sessions cleared"})
    except Exception as e:
        logging.error("clear_sessions error: %s\n%s", e, traceback.format_exc())
        return jsonify({"error":"server error"}), 500

@app.route("/api/sessions/export", methods=["GET"])
def export_sessions():
    fmt = request.args.get("format", "json")
    conn = db_conn()
    rows = conn.execute("SELECT id,time,url,method,headers,body,suspicious FROM sessions ORDER BY time DESC").fetchall()
    conn.close()
    data=[]
    for r in rows:
        data.append({"id":r[0],"time":r[1],"url":r[2],"method":r[3],
                     "headers": safe_load_json(r[4],{}),"body":r[5],"suspicious":safe_load_json(r[6],[]) } )
    if fmt=="csv":
        si=StringIO(); cw=csv.writer(si)
        cw.writerow(["id","time","url","method","headers","body","suspicious"])
        for it in data:
            cw.writerow([it["id"],it["time"],it["url"],it["method"], json.dumps(it["headers"],ensure_ascii=False),
                         (it["body"] or "").replace("\n","\\n"), json.dumps(it["suspicious"],ensure_ascii=False)])
        return si.getvalue(), 200, {'Content-Type':'text/csv; charset=utf-8','Content-Disposition':'attachment; filename="sessions.csv"'}
    return jsonify(data)

# === 模板接口：获取某个模板源码（改为外置） ===
@app.route('/api/frida_template/<name>', methods=['GET'])
def get_frida_template(name):
    try:
        load_templates()
        spec = TEMPLATE_CACHE.get(name)
        if not spec:
            return jsonify({"error":"template not found"}), 404
        return spec.code, 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# === 模板接口：列出全部模板（新增） ===
@app.route("/api/frida/templates", methods=["GET"])
def list_frida_templates():
    load_templates()
    out = []
    for name, spec in TEMPLATE_CACHE.items():
        out.append({
            "name": name,
            "display_name": spec.meta.get("display_name", name),
            "required_params": spec.meta.get("required_params", []),
            "targets": spec.meta.get("targets", []),
            "risks": spec.meta.get("risks", []),
            "defaults": spec.meta.get("defaults", {}),
        })
    return jsonify(out)

# ------------------ probe endpoint ------------------
@app.route('/api/probe', methods=['POST'])
def probe_process():
    data = request.get_json() or {}
    app_name = data.get("app") or data.get("app_name") or data.get("pkg") or data.get("package")
    if not app_name:
        return jsonify({"error":"missing app"}), 400
    try:
        p = subprocess.run(["frida-ps", "-Uai"], capture_output=True, text=True, timeout=10)
        if p.returncode != 0:
            return jsonify({"error":"frida-ps failed", "detail": p.stderr or p.stdout}), 500
        lines = (p.stdout or "").splitlines()
        matches = []
        for ln in lines:
            if app_name in ln:
                matches.append(ln.strip())
        found = len(matches) > 0
        return jsonify({"found": found, "matches": matches, "raw_count": len(lines), "stdout": p.stdout, "stderr": p.stderr}), 200
    except Exception as e:
        logging.error("probe error: %s", traceback.format_exc())
        return jsonify({"error":"probe failed", "detail": str(e)}), 500

# ------------------ FRIDA helpers ------------------
FRIDA_SESSIONS = {}  # pid -> {session, script, device, target}
FRIDA_SESSIONS_LOCK = threading.Lock()
FRIDA_CLI_PROCS = {}  # pid -> {"proc": Popen, "script": path}
FRIDA_CLI_PROCS_LOCK = threading.Lock()

# wrapper to forward console.log/error -> send()
CONSOLE_WRAPPER = r"""
(function(){
    try {
        // Send immediate marker so backend knows wrapper executed
        try { send({__frida_console: true, args: ["[WRAP] console wrapper loaded"]}); } catch(e){}

        var __orig_console_log = (typeof console !== 'undefined' && console.log) ? console.log : function(){};
        var __orig_console_error = (typeof console !== 'undefined' && console.error) ? console.error : function(){};

        function __safe_send(payload){
            try { send(payload); } catch(e) { /* ignore */ }
        }

        // override console.log
        try {
            console.log = function() {
                try {
                    __safe_send({__frida_console: true, args: Array.prototype.slice.call(arguments), level: 'log'});
                } catch(e) {}
                try { __orig_console_log.apply(console, arguments); } catch(e) {}
            };
        } catch(e){}

        // override console.error
        try {
            console.error = function() {
                try {
                    __safe_send({__frida_console: true, args: Array.prototype.slice.call(arguments), level: 'error'});
                } catch(e) {}
                try { __orig_console_error.apply(console, arguments); } catch(e) {}
            };
        } catch(e){}

        // provide a fallback if user calls send directly (no-op)
    } catch(e) {}
})();
"""

def _format_payload_to_line(payload):
    try:
        if isinstance(payload, str):
            return payload
        if isinstance(payload, (int, float, bool)):
            return str(payload)
        if isinstance(payload, dict):
            if payload.get("__frida_console"):
                args = payload.get("args", [])
                lvl = payload.get("level", "log")
                try:
                    return "[" + lvl.upper() + "] " + " ".join(str(a) for a in args)
                except:
                    return "[" + lvl.upper() + "] " + str(args)
            return json.dumps(payload, ensure_ascii=False)
        if isinstance(payload, list):
            return " ".join(str(x) for x in payload)
        return str(payload)
    except Exception:
        return str(payload)

def _start_frida_via_subprocess(cmd, script_path):
    """
    Spawn frida CLI and stream stdout/stderr lines to socketio.
    This implementation does NOT modify the cmd; it streams the CLI output
    as-is so the frontend sees the same output you see when running the CLI locally.
    """
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        pid = p.pid
        logging.info("Started frida subprocess pid=%s cmd=%s", pid, " ".join(cmd))
        socketio.emit("frida_started", {"pid": pid, "script": script_path, "spawn": ("-f" in cmd or "-F" in cmd)})

        with FRIDA_CLI_PROCS_LOCK:
            FRIDA_CLI_PROCS[pid] = {"proc": p, "script": script_path}

        def reader_thread(stream, prefix=""):
            try:
                for raw in iter(stream.readline, b""):
                    if not raw:
                        break
                    try:
                        line = raw.decode(errors="ignore").rstrip("\r\n")
                    except Exception:
                        line = str(raw)
                    socketio.emit("frida_log", {"pid": pid, "line": prefix + line})
            except Exception as e:
                socketio.emit("frida_log", {"pid": pid, "line": f"[reader error] {e}"})

        socketio.start_background_task(reader_thread, p.stdout, "")
        socketio.start_background_task(reader_thread, p.stderr, "[ERR] ")

        def wait_thread():
            try:
                code = p.wait()
            except Exception:
                code = None
            finally:
                with FRIDA_CLI_PROCS_LOCK:
                    FRIDA_CLI_PROCS.pop(pid, None)
            socketio.emit("frida_stopped", {"pid": pid, "exit_code": code})

        socketio.start_background_task(wait_thread)

        return {"status": "ok", "pid": pid, "script": script_path, "spawn": ("-f" in cmd or "-F" in cmd)}
    except Exception as e:
        logging.error("subprocess frida spawn error: %s\n%s", e, traceback.format_exc())
        return {"error": "frida spawn error", "detail": str(e)}

def _start_frida_via_api_sync(target_app, script_text, use_spawn, attach_pid=None, attach_name=None):
    """
    通过 frida-python 同步 attach/spawn + load script。
    """
    if not FRIDA_PY_AVAILABLE:
        return {"error": "frida python module not available"}

    def _pick_android_device():
        try:
            mgr = frida.get_device_manager()
            devs = mgr.enumerate_devices()
            cands = [d for d in devs if d.type in ("usb", "remote")]
            for d in cands:
                if "127.0.0.1" in (d.id or "") or ":5555" in (d.id or "") or str(d.id or "").startswith("tcp@"):
                    return d
            if cands:
                return cands[0]
            return None
        except Exception:
            return None

    def _proc_exists_on_device(dev, pid=None, name=None, package=None):
        try:
            plist = dev.enumerate_processes()
        except Exception:
            return (False, None)
        if pid is not None:
            for p in plist:
                if int(getattr(p, "pid", -1)) == int(pid):
                    return (True, p)
        if name:
            for p in plist:
                if getattr(p, "name", "") == name:
                    return (True, p)
        if package:
            for p in plist:
                pname = getattr(p, "name", "")
                if pname == package or pname.endswith(package):
                    return (True, p)
        return (False, None)

    device = _pick_android_device()
    if device is None:
        msg = "[api] no usb/remote device found; ensure frida-server is running and -U device is visible"
        logging.error(msg)
        socketio.emit("frida_log", {"pid": -1, "line": msg})
        return {"error": "no-device", "detail": msg}

    socketio.emit("frida_log", {"pid": -1, "line": f"[api] using device id={device.id} type={device.type} name={getattr(device, 'name', '')}"})

    final_script = CONSOLE_WRAPPER + "\n" + script_text

    try:
        session = None
        pid = None

        if use_spawn:
            socketio.emit("frida_log", {"pid": -1, "line": f"[api] spawn {target_app} ..."})
            spawned_pid = device.spawn([target_app])
            pid = spawned_pid
            session = device.attach(pid)
            try:
                device.resume(pid)
            except Exception:
                pass
            time.sleep(1.5)
            socketio.emit("frida_log", {"pid": pid, "line": f"[api] spawn attached pid={pid}, resumed, sleeping before load ..."})

        else:
            ok, proc = (False, None)
            if attach_pid is not None:
                ok, proc = _proc_exists_on_device(device, pid=attach_pid)
                if not ok:
                    socketio.emit("frida_log", {"pid": -1, "line": f"[api] WARN: pid {attach_pid} not on device {device.id}, will try by name"})
            if not ok and attach_name:
                ok, proc = _proc_exists_on_device(device, name=attach_name)
            if not ok:
                ok, proc = _proc_exists_on_device(device, package=target_app)

            if not ok:
                detail = f"process '{target_app}' not found on device {device.id}"
                socketio.emit("frida_log", {"pid": -1, "line": "[api] " + detail})
                return {"error": "frida api error", "detail": detail}

            if attach_pid is not None and _proc_exists_on_device(device, pid=attach_pid)[0]:
                socketio.emit("frida_log", {"pid": -1, "line": f"[api] attach by PID {attach_pid} ({target_app})"})
                session = device.attach(attach_pid)
                pid = attach_pid
            elif attach_name and _proc_exists_on_device(device, name=attach_name)[0]:
                socketio.emit("frida_log", {"pid": -1, "line": f"[api] attach by NAME {attach_name}"})
                session = device.attach(attach_name)
                ok2, proc2 = _proc_exists_on_device(device, name=attach_name)
                pid = getattr(proc2, "pid", None) if ok2 else None
            else:
                pname = getattr(proc, "name", None)
                if pname:
                    socketio.emit("frida_log", {"pid": -1, "line": f"[api] attach by NAME {pname} (fallback)"})
                    session = device.attach(pname)
                    pid = getattr(proc, "pid", None)
                else:
                    socketio.emit("frida_log", {"pid": -1, "line": f"[api] attach by PACKAGE {target_app} (fallback)"})
                    session = device.attach(target_app)
                    try:
                        pid = session.pid
                    except Exception:
                        pid = None

        try:
            script = session.create_script(final_script, runtime='v8')
        except TypeError:
            script = session.create_script(final_script)

        def on_message(message, data):
            try:
                if not message:
                    return
                t = message.get("type")
                if t == "send":
                    payload = message.get("payload")
                    line = _format_payload_to_line(payload)
                    socketio.emit("frida_log", {"pid": pid or -1, "line": line})
                elif t == "error":
                    stack = message.get("stack") or message.get("description") or str(message)
                    socketio.emit("frida_log", {"pid": pid or -1, "line": "[JS ERROR]\n" + str(stack)})
                else:
                    socketio.emit("frida_log", {"pid": pid or -1, "line": "[JS MSG] " + json.dumps(message, ensure_ascii=False)})
            except Exception as e:
                socketio.emit("frida_log", {"pid": pid or -1, "line": "[on_message error] " + str(e)})

        script.on("message", on_message)
        script.load()

        with FRIDA_SESSIONS_LOCK:
            FRIDA_SESSIONS[pid or -1] = {"session": session, "script": script, "device": device, "target": target_app}

        socketio.emit("frida_started", {"pid": pid or -1, "script": f"(in-memory script for {target_app})", "spawn": use_spawn})
        logging.info("Started frida (api) pid=%s spawn=%s target=%s device=%s", pid, use_spawn, target_app, getattr(device, "id", "?"))
        return {"status": "ok", "pid": pid or -1, "script": f"(in-memory script for {target_app})", "spawn": use_spawn}

    except frida.TransportError as te:
        logging.error("frida transport error: %s", te)
        socketio.emit("frida_log", {"pid": -1, "line": f"[frida transport error] {te}"})
        return {"error": "frida api error", "detail": str(te)}
    except Exception as e:
        logging.error("frida api error: %s\n%s", e, traceback.format_exc())
        return {"error": "frida api error", "detail": str(e)}


# ------------------ Consolidated wait-wrapper with improved diagnostics ------------------
def wrap_user_script_wait_java(user_js: str, max_attempts: int = 50, delay_ms: int = 100):
    if user_js is None:
        user_js = """"""
    indented = "\n".join("        " + line for line in user_js.splitlines())
    tpl = f"""
(function(){{
  try {{ send({{'__frida_console':true, 'args':['[WRAP] wrapper loaded']}}); }} catch(e){{}}

  function __user_fn() {{
{indented}
  }}

  var attempt = 0; var max = {int(max_attempts)}; var delay = {int(delay_ms)};

  function _tryRun() {{
    try {{
      var java_ok = false;
      try {{
        if (typeof Java !== 'undefined' && ('available' in Java)) java_ok = !!Java.available;
        else if (typeof Java !== 'undefined' && typeof Java.perform === 'function') java_ok = true;
      }} catch(e) {{}}

      if (java_ok) {{
        try {{
          Java.perform(function(){{
            try {{ send({{'__frida_console':true,'args':['[WRAP] java available -> running user script']}}); }} catch(e){{}}
            try {{ __user_fn(); }} catch(err) {{ try{{ send({{'__frida_console':true,'args':['[USER ERR]', ''+err], 'level':'error'}}); }}catch(e2){{}} }}
          }});
          return true;
        }} catch(e) {{}}
      }}
    }} catch(e) {{}}
    return false;
  }}

  if (!_tryRun()) {{
    var iv = setInterval(function(){{
      attempt++;
      try {{ if (_tryRun()) {{ try{{ clearInterval(iv); }}catch(e){{}}; return; }} }} catch(e){{}}
      try {{ send({{'__frida_console':true,'args':['[WRAP] java not available yet (attempt ' + attempt + ')']}}); }} catch(e){{}}
      if (attempt >= max) {{
        try {{ send({{'__frida_console':true,'args':['[WRAP] timed out waiting for Java after ' + max + ' attempts'], 'level':'error'}}); }} catch(e){{}}
        try {{
          var mods = Process.enumerateModulesSync().slice(0,60).map(function(m){{return m.name}});
          send({{'__frida_console':true,'args':['[WRAP] modules (top 60): ' + mods.join(', ')]}});
        }} catch(e){{ try{{ send({{'__frida_console':true,'args':['[WRAP] modules enumerate failed: ' + e]}}); }}catch(e2){{}} }}
        try {{
          var ranges = [];
          if (typeof Process.enumerateRangesSync === 'function') {{ ranges = Process.enumerateRangesSync('r--') || []; }}
          send({{'__frida_console':true,'args':['[WRAP] ranges_count:' + (ranges.length || 0)]}});
        }} catch(e){{}}

        try {{
          send({{'__frida_console':true,'args':['[WRAP] attempting final fallback (non-Java)']}});
          try {{ __user_fn(); }} catch(err) {{ try{{ send({{'__frida_console':true,'args':['[auto-wrap] final exec err:', ''+err], 'level':'error'}}); }}catch(e2){{}} }}
        }} catch(e){{}}

        try{{ clearInterval(iv); }}catch(e){{}}
      }}
    }}, delay);
  }}

}})();
"""
    return tpl

@app.route('/api/run_frida', methods=['POST'])
@require_token
def run_frida():
    data = request.get_json() or {}
    target_app = data.get('app') or data.get('app_name') or data.get('package')
    spawn = bool(data.get('spawn', False))
    template_name = data.get("template")
    params = data.get("template_params") or {}
    script_override = data.get("script")
    force_cli = bool(data.get("force_cli", False))

    if not target_app:
        return jsonify({"error": "Missing target app"}), 400
    if not script_override and not template_name:
        return jsonify({"error": "Missing template or script"}), 400

    # 1) 生成 “用户脚本” （改：从外置模板渲染）
    try:
        if script_override:
            user_js = script_override
        else:
            user_js = render_template_external(template_name, params)
    except Exception as e:
        logging.error("prepare script failed: %s", traceback.format_exc())
        return jsonify({"error":"prepare script failed", "detail": str(e)}), 400

    # 2) 和命令行一致：用 setImmediate + Java.perform 包裹
    wrapped_no_console = (
        "setImmediate(function(){\n"
        "  try {\n"
        "    Java.perform(function(){\n"
        "      try {\n"
        f"{user_js}\n"
        "      } catch(e) {\n"
        "        try { send({__frida_console:true, args:['[USER ERR]', ''+e], level:'error'}); } catch(_) {}\n"
        "      }\n"
        "    });\n"
        "  } catch(e) {\n"
        "    try { send({__frida_console:true, args:['[RUN ERR]', ''+e], level:'error'}); } catch(_) {}\n"
        "  }\n"
        "});\n"
    )

    # 3) 将脚本写入磁盘（CLI fallback 用）
    script_name = f"frida_{template_name or 'manual'}_{int(time.time())}.js"
    script_path = os.path.join(FRIDA_DIR, script_name)
    try:
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(CONSOLE_WRAPPER + "\n" + wrapped_no_console)
    except Exception as e:
        return jsonify({"error":"write script failed", "detail": str(e)}), 500

    # ---- helpers（仅本函数内部用）----
    def _pidof_exact(package: str):
        try:
            p = subprocess.run(["adb", "shell", "pidof", "-s", package],
                               capture_output=True, text=True, timeout=4)
            out = (p.stdout or "").strip()
            if out and out.split()[0].isdigit():
                return int(out.split()[0])
        except Exception:
            pass
        return None

    def _find_by_ps(package: str):
        try:
            ps = subprocess.run(["frida-ps", "-Uai"], capture_output=True, text=True, timeout=6)
            if ps.returncode != 0:
                return (None, None, ps.stderr or ps.stdout)
            for ln in (ps.stdout or "").splitlines():
                s = ln.strip()
                if not s:
                    continue
                parts = s.split()
                if len(parts) < 2:
                    continue
                if package == parts[-1]:
                    pid = None
                    for tok in parts:
                        if tok.isdigit():
                            pid = int(tok); break
                    pretty_name = parts[1] if len(parts) >= 2 else None
                    return (pid, pretty_name, None)
            return (None, None, None)
        except Exception as e:
            return (None, None, str(e))

    # 4) 判定是否需要 Java（保持原逻辑）
    need_java = ("Java" in user_js) or ("java." in user_js.lower())
    prefer_cli = force_cli or need_java

    # 5) 优先 frida-python
    if FRIDA_PY_AVAILABLE and not prefer_cli:
        try:
            exact_pid = _pidof_exact(target_app)
            pid_ps, pretty_name, ps_err = _find_by_ps(target_app)
            if exact_pid is None and pid_ps is not None:
                exact_pid = pid_ps

            use_spawn = bool(spawn) or (exact_pid is None)
            if use_spawn:
                socketio.emit("frida_log", {"pid": -1, "line": f"[run] spawning {target_app} (no exact pid)"} )
            else:
                socketio.emit("frida_log", {"pid": -1, "line": f"[run] attaching: PID={exact_pid}, Name='{pretty_name or '?'}'"} )

            res = _start_frida_via_api_sync(
                target_app=target_app,
                script_text=wrapped_no_console,
                use_spawn=use_spawn,
                attach_pid=exact_pid,
                attach_name=pretty_name
            )
            status_code = 200 if res.get("status") == "ok" else 500
            return jsonify(res), status_code

        except Exception:
            logging.error("frida api path failed: %s", traceback.format_exc())
            # 继续走 CLI fallback

    # 6) CLI fallback
    try:
        check = subprocess.run(["frida", "--version"], capture_output=True, text=True, timeout=5)
        if check.returncode != 0:
            return jsonify({"error":"frida cli not available", "detail": check.stderr or check.stdout}), 500
    except Exception as e:
        return jsonify({"error":"frida cli check failed", "detail": str(e)}), 500

    exact_pid = _pidof_exact(target_app)
    pid_ps, pretty_name, ps_err = _find_by_ps(target_app)
    if exact_pid is None and pid_ps is not None:
        exact_pid = pid_ps

    cmd = ["frida", "-U"]
    if not spawn:
        if pretty_name:
            socketio.emit("frida_log", {"pid": -1, "line": f"[cli] attach -n {pretty_name} -l {os.path.basename(script_path)}"})
            cmd += ["-n", pretty_name, "-l", script_path]
        elif exact_pid is not None:
            socketio.emit("frida_log", {"pid": -1, "line": f"[cli] attach -p {exact_pid} -l {os.path.basename(script_path)}"})
            cmd += ["-p", str(exact_pid), "-l", script_path]
        else:
            socketio.emit("frida_log", {"pid": -1, "line": f"[cli] spawn -f {target_app} -l {os.path.basename(script_path)} (pid/name unresolved)"} )
            cmd += ["-f", target_app, "-l", script_path]
    else:
        socketio.emit("frida_log", {"pid": -1, "line": f"[cli] spawn -f {target_app} -l {os.path.basename(script_path)}"})
        cmd += ["-f", target_app, "-l", script_path]

    res = _start_frida_via_subprocess(cmd, script_path)
    return (jsonify(res), 200) if res.get("status") == "ok" else (jsonify(res), 500)


@app.route('/api/run_frida_custom', methods=['POST'])
@require_token
def run_frida_custom():
    data = request.get_json(silent=True) or {}
    target_app = data.get('app') or data.get('app_name') or data.get('package')
    script_text = data.get('script') or ""
    spawn = bool(data.get('spawn', False))

    if not target_app:
        return jsonify({"error":"Missing target app"}), 400
    if not script_text or not isinstance(script_text, str):
        return jsonify({"error":"Missing script"}), 400
    if len(script_text) > 200_000:
        return jsonify({"error":"script too large"}), 400

    script_name = f"frida_custom_{int(time.time())}_{uuid.uuid4().hex[:8]}.js"
    script_path = os.path.join(FRIDA_DIR, script_name)
    try:
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script_text)
    except Exception as e:
        logging.error("write custom script failed: %s\n%s", e, traceback.format_exc())
        return jsonify({"error":"write script failed", "detail": str(e)}), 500

    try:
        check = subprocess.run(["frida", "--version"], capture_output=True, text=True, timeout=5)
        if check.returncode != 0:
            return jsonify({"error":"frida cli not available", "detail": check.stderr or check.stdout}), 500
    except Exception as e:
        return jsonify({"error":"frida cli check failed", "detail": str(e)}), 500

    try:
        ps = subprocess.run(["frida-ps", "-Uai"], capture_output=True, text=True, timeout=8)
        p_stdout = ps.stdout or ""
        proc_found = any((target_app in ln) for ln in p_stdout.splitlines())
    except Exception:
        proc_found = False

    if spawn:
        use_spawn = True
    else:
        use_spawn = not proc_found

    cmd = ["frida", "-U"]
    if use_spawn:
        cmd += ["-f", target_app, "-l", script_path]
    else:
        cmd += ["-n", target_app, "-l", script_path]

    res = _start_frida_via_subprocess(cmd, script_path)
    return jsonify(res), 200 if res.get("status") == "ok" else 500


@app.route('/api/exit_frida_cli', methods=['POST'])
@require_token
def exit_frida_cli():
    data = request.get_json(silent=True) or {}
    pid = data.get("pid")
    if pid is None:
        return jsonify({"error": "missing pid"}), 400
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return jsonify({"error": "invalid pid"}), 400

    with FRIDA_CLI_PROCS_LOCK:
        info = FRIDA_CLI_PROCS.get(pid)
    if not info:
        return jsonify({"error": "pid not tracked"}), 404

    proc = info.get("proc")
    if proc is None:
        with FRIDA_CLI_PROCS_LOCK:
            FRIDA_CLI_PROCS.pop(pid, None)
        return jsonify({"error": "process handle missing"}), 410

    if proc.poll() is not None:
        with FRIDA_CLI_PROCS_LOCK:
            FRIDA_CLI_PROCS.pop(pid, None)
        return jsonify({"error": "process already exited"}), 410

    try:
        proc.stdin.write(b"exit\n")
        proc.stdin.flush()
    except Exception as e:
        logging.error("failed to send exit to pid %s: %s", pid, e)
        return jsonify({"error": "write failed", "detail": str(e)}), 500

    logging.info("Sent exit command to frida subprocess pid=%s", pid)
    return jsonify({"status": "ok"}), 200

# ------------------ inject_frida API ------------------
@app.route('/api/inject_frida', methods=['POST'])
@require_token
def inject_frida():
    data = request.get_json(silent=True) or {}
    target_app = data.get('app') or data.get('package')
    template_name = data.get('template')
    params = data.get('template_params') or {}
    spawn = bool(data.get('spawn', False))
    if not target_app or not template_name:
        return jsonify({"error": "Missing app or template"}), 400

    # 渲染模板（改：外置）
    try:
        user_script = render_template_external(template_name, params)
    except Exception as e:
        return jsonify({"error": "template render failed", "detail": str(e)}), 400

    # wrapper: 等待 Java + console 重定向
    wrapped = wrap_user_script_wait_java(user_script)
    final_script = CONSOLE_WRAPPER + "\n" + wrapped

    script_path = os.path.join(FRIDA_DIR, f"inject_{template_name}_{int(time.time())}.js")
    with open(script_path, "w", encoding="utf-8") as f:
        f.write(final_script)

    if FRIDA_PY_AVAILABLE:
        result = _start_frida_via_api_sync(target_app, wrapped, spawn)
        return jsonify(result), 200 if result.get('status') == 'ok' else 500

    cmd = ["frida", "-U"]
    if spawn:
        cmd += ["-f", target_app, "-l", script_path]
    else:
        cmd += ["-n", target_app, "-l", script_path]
    result = _start_frida_via_subprocess(cmd, script_path)
    return jsonify(result), 200 if result.get('status') == 'ok' else 500


# ------------------ stop/unload frida session ------------------
@app.route('/api/stop_frida', methods=['POST'])
@require_token
def stop_frida():
    data = request.get_json() or {}
    pid = data.get("pid")
    if not pid:
        return jsonify({"error": "missing pid"}), 400
    try:
        with FRIDA_SESSIONS_LOCK:
            if pid not in FRIDA_SESSIONS:
                return jsonify({"error": "pid not found in sessions"}), 404
            info = FRIDA_SESSIONS[pid]
            try:
                info["script"].unload()
            except Exception:
                pass
            try:
                info["session"].detach()
            except Exception:
                pass
            try:
                pass
            except Exception:
                pass
            del FRIDA_SESSIONS[pid]
        socketio.emit("frida_stopped", {"pid": pid})
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        logging.error("stop_frida error: %s\n%s", e, traceback.format_exc())
        return jsonify({"error": "stop failed", "detail": str(e)}), 500


# ------------------ index route ------------------
@app.route("/")
def index():
    index_path = os.path.join(BASE_DIR, "index.html")
    if not os.path.exists(index_path):
        return "index.html not found. Please place the UI file next to app.py.", 500
    return send_file(index_path)


# ------------------ 启动 ------------------
if __name__ == "__main__":
    logging.info("Starting Flask-SocketIO app; DB=%s LOG=%s FRIDA_PY=%s", DB, LOGFILE, FRIDA_PY_AVAILABLE)
    load_templates()  # 启动时扫描一次（仍支持运行中热加载）
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)

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

# ------------------ FRIDA templates & helpers ------------------
FRIDA_TEMPLATES = {
    "okhttp_log_url": """
Java.perform(function(){
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var Buffer = Java.use('okio.Buffer');
        var RequestBody = Java.use('okhttp3.RequestBody');
        var newCall_over = OkHttpClient.newCall.overload('okhttp3.Request');

        newCall_over.implementation = function(request){
            try {
                var url = "(unknown)";
                try { url = request.url().toString(); } catch(e){}
                console.log("[okhttp hook] url=" + url);
                try {
                    var body = request.body();
                    if (body) {
                        var buf = Buffer.$new();
                        body.writeTo(buf);
                        var bytes = buf.readByteArray();
                        var Base64 = Java.use('android.util.Base64');
                        console.log("[okhttp hook][body][base64] " + Base64.encodeToString(bytes, 0));
                    }
                } catch(e){}
                return newCall_over.call(this, request);
            } catch(inner){
                try { return newCall_over.call(this, request); } catch(e){ return this.newCall(request); }
            }
        };
        console.log("[okhttp hook] installed");
    } catch(e){
        console.log("[okhttp hook] install failed: " + e);
    }
});
""",
    "requestbody_dump": """
Java.perform(function() {
  try {
    var RequestBody = Java.use("okhttp3.RequestBody");
    var Buffer = Java.use("okio.Buffer");
    RequestBody.writeTo.overload("okio.BufferedSink").implementation = function(sink) {
      try {
        var buf = Buffer.$new();
        this.writeTo(buf);
        var bytes = buf.readByteArray();
        var Base64 = Java.use("android.util.Base64");
        var b64 = Base64.encodeToString(bytes, 0);
        console.log("[RequestBody] base64: " + b64);
      } catch(e) { console.log("RB err:", e); }
      return this.writeTo(sink);
    };
  } catch(e) { console.log("RequestBody hook fail", e); }
});
""",
    "ssl_pinning_bypass": """
Java.perform(function() {
    try {
        var CertPinner = Java.use('okhttp3.CertificatePinner');
        CertPinner.check.overload('java.lang.String','java.util.List').implementation = function() {
            console.log("[bypass] CertificatePinner.check called - bypassed");
            return;
        };
    } catch(e){ console.log("[bypass] CertificatePinner hook failed: " + e); }

    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');

        var TrustManager = Java.registerClass({
            name: "org.frida.TrustAllManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });

        var initOverload = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;','[Ljavax.net.ssl.TrustManager;','java.security.SecureRandom');
        initOverload.implementation = function(km, tm, sr){
            console.log("[bypass] SSLContext.init called - replacing TrustManager");
            initOverload.call(this, km, [TrustManager.$new()], sr);
        };
    } catch(e){ console.log("[bypass] X509TrustManager hook failed: " + e); }
});
""",
    "sharedprefs_dump": """
Java.perform(function() {
    try {
        var SharedPreferences = Java.use("android.app.SharedPreferencesImpl");
        SharedPreferences.getString.overload('java.lang.String', 'java.lang.String')
            .implementation = function(key, def) {
                var value = this.getString(key, def);
                console.log("[SharedPreferences] " + key + " = " + value);
                return value;
            };
    } catch(e) { console.log("sharedprefs_dump err:", e); }
});
""",
    "dump_class_string_fields": """
Java.perform(function() {
    try {
        var clsName = "{class_name}";
        console.log("[dump] attempting to enumerate instances of: " + clsName);
        Java.choose(clsName, {
            onMatch: function(instance) {
                try {
                    var fields = instance.getClass().getDeclaredFields();
                    for (var i=0;i<fields.length;i++){
                        try{
                            fields[i].setAccessible(true);
                            var t = fields[i].getType().getName();
                            if (t === 'java.lang.String') {
                                var v = fields[i].get(instance);
                                console.log("[DUMP] " + clsName + "#" + fields[i].getName() + " = " + v);
                            }
                        } catch(e2){}
                    }
                } catch(e1){}
            },
            onComplete: function() { console.log("[dump] choose complete for " + clsName); }
        });
    } catch(e) { console.log("dump_class_string_fields err:", e); }
});
""",
    "search_jwt_in_static_strings": r"""
Java.perform(function() {
    try {
        var JWT_RE = /^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$/;
        var Modifier = Java.use('java.lang.reflect.Modifier');
        var classes = Java.enumerateLoadedClassesSync();
        console.log("[search_jwt] total loaded classes: " + classes.length);
        for (var i=0;i<classes.length;i++){
            var name = classes[i];
            try {
                var cls = Java.use(name);
                var fields = cls.class.getDeclaredFields();
                for (var j=0;j<fields.length;j++){
                    try {
                        var f = fields[j];
                        var isStatic = Modifier.isStatic(f.getModifiers());
                        var tname = f.getType().getName();
                        if (isStatic && tname === "java.lang.String") {
                            f.setAccessible(true);
                            var val = f.get(null);
                            if (val && typeof val === "string" && JWT_RE.test(val)) {
                                console.log("[JWT static] class=" + name + " field=" + f.getName() + " value=" + val);
                            }
                        }
                    } catch(ef) {}
                }
            } catch(ec) {}
        }
        console.log("[search_jwt] done.");
    } catch(e) { console.log("search_jwt_in_static_strings err:", e); }
});
""",
    # runtime_probe template
    "runtime_probe": """
(function(){
    try {
        var info = {java_type: typeof Java};
        try { info.java_available = (typeof Java !== 'undefined') && (('available' in Java) ? Java.available : true); } catch(e) { info.java_available = false; }
        send({__frida_console:true, args:['[probe]', JSON.stringify(info)]});
    } catch(e) { send({__frida_console:true, args:['[probe] err', ''+e]}); }

    try {
        var mods = Process.enumerateModulesSync().slice(0,80).map(function(m){return m.name});
        send({__frida_console:true, args:['[probe-modules]', mods.join(', ')]});
    } catch(e) { }

    try {
        var maps = Process.enumerateRangesSync ? Process.enumerateRangesSync('r--') : [];
        send({__frida_console':true, args:['[probe-ranges-count]', maps.length || 0]});
    } catch(e) { }
})();
"""
}

# safe_format: missing keys remain as {key}
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

@app.route('/api/frida_template/<name>', methods=['GET'])
def get_frida_template(name):
    tpl = FRIDA_TEMPLATES.get(name)
    if not tpl:
        return jsonify({"error":"template not found"}), 404
    return tpl, 200

# ------------------ generate_frida ------------------
@app.route('/api/generate_frida', methods=['POST'])
def generate_frida():
    data = request.get_json() or {}
    template_name = data.get("template")
    params = data.get("template_params") or {}
    if template_name:
        tpl = FRIDA_TEMPLATES.get(template_name)
        if not tpl:
            return jsonify({"error":"template not found"}), 404
        try:
            script = safe_format(tpl, **params)
            return script, 200
        except Exception as e:
            logging.error("generate_frida template render failed: %s", traceback.format_exc())
            return jsonify({"error":"template render failed", "detail": str(e)}), 500

    session_id = data.get('id')
    if not session_id:
        return jsonify({"error":"missing id"}), 400
    conn = db_conn()
    row = conn.execute("SELECT url, headers, body, suspicious FROM sessions WHERE id=?", (session_id,)).fetchone()
    conn.close()
    if not row:
        return "Session not found", 404
    url, headers_json, body, suspicious_json = row[0], row[1], row[2], row[3]
    template = FRIDA_TEMPLATES.get("requestbody_dump") if (body and len(body.strip())>0) else FRIDA_TEMPLATES.get("okhttp_log_url")
    try:
        frida_script = safe_format(template, url=url)
        return frida_script, 200
    except Exception as e:
        logging.error("generate_frida session render failed: %s", traceback.format_exc())
        return jsonify({"error":"template render failed", "detail": str(e)}), 500

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

# ------------------ run_frida helpers ------------------
FRIDA_SESSIONS = {}  # pid -> {session, script, device, target}
FRIDA_SESSIONS_LOCK = threading.Lock()

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
        # Use the exact cmd provided by the caller (do not inject flags here).
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        pid = p.pid
        logging.info("Started frida subprocess pid=%s cmd=%s", pid, " ".join(cmd))
        socketio.emit("frida_started", {"pid": pid, "script": script_path, "spawn": ("-f" in cmd or "-F" in cmd)})

        def reader_thread(stream, prefix=""):
            try:
                # Read until EOF. We decode per-line and forward to frontend.
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

        # Start background tasks for stdout and stderr
        socketio.start_background_task(reader_thread, p.stdout, "")
        socketio.start_background_task(reader_thread, p.stderr, "[ERR] ")

        return {"status": "ok", "pid": pid, "script": script_path, "spawn": ("-f" in cmd or "-F" in cmd)}
    except Exception as e:
        logging.error("subprocess frida spawn error: %s\n%s", e, traceback.format_exc())
        return {"error": "frida spawn error", "detail": str(e)}

def _start_frida_via_api_sync(target_app, script_text, use_spawn):
    """
    Synchronous attach/spawn + create/load script using frida-python.
    Returns dict {status/pid/script/...} - pid is real number when ok.
    This enhanced version will automatically load a fallback "wait-for-Java" wrapper
    if the first script throws a ReferenceError about Java being undefined.
    """
    if not FRIDA_PY_AVAILABLE:
        return {"error":"frida python module not available"}

    # ensure console wrapper is present for API path too
    final_script = CONSOLE_WRAPPER + "\n" + script_text

    try:
        try:
            device = frida.get_usb_device(timeout=4)
        except Exception:
            device = frida.get_local_device()

        session = None
        pid = None

        if use_spawn:
            spawned_pid = device.spawn([target_app])
            pid = spawned_pid
            # Resume first so process finishes startup; then attach so script executes after normal init
            try:
                device.resume(pid)
            except Exception:
                pass
            # small delay to let resumed process proceed
            time.sleep(0.05)
            session = device.attach(pid)
        else:
            try:
                # allow attaching by name or pid (frida API accepts pid int)
                session = device.attach(target_app)
                pid = session.pid
            except Exception as e_attach:
                # try to attach by pid parsed from frida-ps output
                try:
                    p = subprocess.run(["frida-ps", "-Uai"], capture_output=True, text=True, timeout=5)
                    if p.returncode == 0:
                        for ln in (p.stdout or "").splitlines():
                            if target_app in ln:
                                for tok in ln.split():
                                    if tok.isdigit():
                                        possible_pid = int(tok)
                                        session = device.attach(possible_pid)
                                        pid = possible_pid
                                        break
                                if session:
                                    break
                except Exception:
                    pass
                if session is None:
                    raise RuntimeError(f"attach failed: {e_attach}")

        # create script + message handler
        script = session.create_script(final_script)

        # context to allow on_message to inject fallback only once
        ctx = {"fallback_injected": False}

        def on_message(message, data):
            try:
                if message is None:
                    return
                mtype = message.get("type")
                if mtype == "send":
                    payload = message.get("payload")
                    line = _format_payload_to_line(payload)
                    socketio.emit("frida_log", {"pid": pid, "line": line})
                elif mtype == "error":
                    stack = message.get("stack") or message.get("description") or str(message)
                    socketio.emit("frida_log", {"pid": pid, "line": "[JS ERROR]\n" + str(stack)})
                    # detect ReferenceError about Java and inject fallback wrapper once
                    try:
                        s = str(stack)
                        if ("Java" in s or "java" in s) and ("not defined" in s or "ReferenceError" in s) and not ctx["fallback_injected"]:
                            ctx["fallback_injected"] = True
                            try:
                                fallback = CONSOLE_WRAPPER + "\n" + wrap_user_script_wait_java(script_text, max_attempts=600, delay_ms=200)
                                fb_script = session.create_script(fallback)
                                fb_script.on("message", on_message)
                                fb_script.load()
                                socketio.emit("frida_log", {"pid": pid, "line": "[FRIDA FALLBACK] loaded wait-for-Java wrapper"})
                            except Exception as e_f:
                                socketio.emit("frida_log", {"pid": pid, "line": "[FRIDA FALLBACK ERR] " + str(e_f)})
                    except Exception:
                        pass
                else:
                    socketio.emit("frida_log", {"pid": pid, "line": "[JS MSG] " + json.dumps(message, ensure_ascii=False)})
            except Exception as e:
                socketio.emit("frida_log", {"pid": pid or -1, "line": "[on_message error] " + str(e)})

        script.on("message", on_message)

        # load script (synchronous)
        try:
            script.load()
        except Exception as e_load:
            socketio.emit("frida_log", {"pid": pid or -1, "line": "[script.load error] " + str(e_load)})
            raise

        # store references to avoid GC
        with FRIDA_SESSIONS_LOCK:
            FRIDA_SESSIONS[pid] = {"session": session, "script": script, "device": device, "target": target_app}

        socketio.emit("frida_started", {"pid": pid, "script": f"(in-memory script for {target_app})", "spawn": use_spawn})
        logging.info("Started frida (api) pid=%s spawn=%s target=%s", pid, use_spawn, target_app)
        return {"status":"ok", "pid": pid, "script": f"(in-memory script for {target_app})", "spawn": use_spawn}
    except frida.TransportError as te:
        logging.error("frida transport error: %s", te)
        socketio.emit("frida_log", {"pid": pid or -1, "line": f"[frida transport error] {te}"})
        return {"error":"frida api error", "detail": str(te)}
    except Exception as e:
        logging.error("frida api error: %s\n%s", e, traceback.format_exc())
        return {"error":"frida api error", "detail": str(e)}


# ------------------ Consolidated wait-wrapper with improved diagnostics ------------------
def wrap_user_script_wait_java(user_js: str, max_attempts: int = 150, delay_ms: int = 100):
    """
    Robust wrapper: waits for Java (using Java.available when possible). On timeout it
    emits detailed diagnostics (modules list, ranges count) and attempts a final
    non-Java invocation of the user code as a fallback.
    Returns wrapper JS string (to be prepended with CONSOLE_WRAPPER by the caller).
    """
    if user_js is None:
        user_js = """"""

    # indent user code
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
    session_id = data.get('id')
    target_app = data.get('app') or data.get('app_name') or data.get('package')
    spawn = bool(data.get('spawn', False))
    template_name = data.get("template")
    params = data.get("template_params") or {}
    script_override = data.get("script")

    if not target_app:
        return jsonify({"error":"Missing target app"}), 400

    try:
        if script_override:
            frida_script = script_override
        elif template_name:
            tpl = FRIDA_TEMPLATES.get(template_name)
            if not tpl:
                return jsonify({"error":"template not found"}), 404
            frida_script = safe_format(tpl, **params)
        elif session_id:
            conn = db_conn()
            row = conn.execute("SELECT url, headers, body FROM sessions WHERE id=?", (session_id,)).fetchone()
            conn.close()
            if not row:
                return jsonify({"error":"Session not found"}), 404
            url = row[0]; body = row[2]
            base_tpl = FRIDA_TEMPLATES.get("requestbody_dump") if (body and len(body.strip())>0) else FRIDA_TEMPLATES.get("okhttp_log_url")
            frida_script = safe_format(base_tpl, url=url)
        else:
            frida_script = FRIDA_TEMPLATES.get("okhttp_log_url")
    except Exception as e:
        logging.error("prepare script failed: %s", traceback.format_exc())
        return jsonify({"error":"prepare script failed", "detail": str(e)}), 500

    # wrap the script to wait for Java (do NOT include console wrapper here; API path will prepend it)
    wrapped_no_console = wrap_user_script_wait_java(frida_script)

    # persist script to file (for subprocess fallback) -- for CLI we must include CONSOLE_WRAPPER so stdout sends will be visible
    script_name = f"frida_{session_id or 'manual'}_{int(time.time())}.js"
    script_path = os.path.join(FRIDA_DIR, script_name)
    try:
        with open(script_path, "w", encoding="utf-8") as f:
            # CLI expects console wrapper + wrapped script
            f.write(CONSOLE_WRAPPER + "\n" + wrapped_no_console)
    except Exception as e:
        return jsonify({"error":"write script failed", "detail": str(e)}), 500

    # Preferred path: frida python API (synchronous)
    if FRIDA_PY_AVAILABLE:
        try:
            # check running processes via frida-ps
            try:
                ps = subprocess.run(["frida-ps", "-Uai"], capture_output=True, text=True, timeout=6)
                p_stdout = ps.stdout or ""
                proc_found = any((target_app in ln) for ln in p_stdout.splitlines())
            except Exception:
                proc_found = False

            use_spawn = bool(spawn)
            if not spawn and proc_found:
                use_spawn = False
            elif not spawn and not proc_found:
                use_spawn = True

            # _start_frida_via_api_sync expects script_text WITHOUT console wrapper (it prepends it), so pass wrapped_no_console
            res = _start_frida_via_api_sync(target_app, wrapped_no_console, use_spawn)
            status_code = 200 if res.get("status") == "ok" else 500
            return jsonify(res), status_code
        except Exception as e:
            logging.error("frida api path failed: %s", traceback.format_exc())
            # fallthrough to CLI fallback

    # fallback to CLI subprocess
    try:
        check = subprocess.run(["frida","--version"], capture_output=True, text=True, timeout=5)
        if check.returncode != 0:
            return jsonify({"error":"frida cli not available", "detail": check.stderr or check.stdout}), 500
    except Exception as e:
        return jsonify({"error":"frida cli check failed", "detail": str(e)}), 500

    # detect running process
    try:
        ps = subprocess.run(["frida-ps", "-Uai"], capture_output=True, text=True, timeout=8)
        p_stdout = ps.stdout or ""
        proc_found = any((target_app in ln) for ln in p_stdout.splitlines())
    except Exception:
        proc_found = False

    use_spawn = bool(spawn)
    if not spawn and proc_found:
        use_spawn = False
    elif not spawn and not proc_found:
        use_spawn = True

    cmd = ["frida", "-U"]
    if use_spawn:
        # do not add --no-pause universally because some frida versions error on it
        cmd += ["-f", target_app, "-l", script_path]
    else:
        cmd += ["-n", target_app, "-l", script_path]

    res = _start_frida_via_subprocess(cmd, script_path)
    if res.get("status") == "ok":
        return jsonify(res), 200
    else:
        return jsonify(res), 500
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

    # IMPORTANT: write the user's original script exactly as-is to file for CLI.
    # Do NOT prepend the CONSOLE_WRAPPER here, because the CLI output (console.log,
    # Java.perform logs, etc.) is what we want forwarded verbatim.
    script_name = f"frida_custom_{int(time.time())}_{uuid.uuid4().hex[:8]}.js"
    script_path = os.path.join(FRIDA_DIR, script_name)
    try:
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script_text)
    except Exception as e:
        logging.error("write custom script failed: %s\n%s", e, traceback.format_exc())
        return jsonify({"error":"write script failed", "detail": str(e)}), 500

    # Ensure frida CLI exists
    try:
        check = subprocess.run(["frida", "--version"], capture_output=True, text=True, timeout=5)
        if check.returncode != 0:
            return jsonify({"error":"frida cli not available", "detail": check.stderr or check.stdout}), 500
    except Exception as e:
        return jsonify({"error":"frida cli check failed", "detail": str(e)}), 500

    # Detect whether target process is already running
    try:
        ps = subprocess.run(["frida-ps", "-Uai"], capture_output=True, text=True, timeout=8)
        p_stdout = ps.stdout or ""
        proc_found = any((target_app in ln) for ln in p_stdout.splitlines())
    except Exception:
        proc_found = False

    # Decide: spawn if user requested spawn OR process not found; otherwise attach by name.
    if spawn:
        use_spawn = True
    else:
        use_spawn = not proc_found

    # Build CLI command to match the command you run locally.
    cmd = ["frida", "-U"]
    if use_spawn:
        # spawn like: frida -U -f com.example.re -l script.js
        cmd += ["-f", target_app, "-l", script_path]
    else:
        # attach by name (non-spawn). Use -n (attach by name) if supported.
        cmd += ["-n", target_app, "-l", script_path]

    # Start the process and forward CLI stdout/stderr to frontend.
    res = _start_frida_via_subprocess(cmd, script_path)
    return jsonify(res), 200 if res.get("status") == "ok" else 500



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
                # optionally kill spawned process? Not doing that by default.
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
    # run with threading async mode
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)
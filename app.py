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

# ------------------ FRIDA templates & helpers (safe for .format) ------------------
FRIDA_TEMPLATES = {
    # 0) 运行环境探针：确认 Java 可用 & 打点
    "runtime_probe": r"""
(function(){{
  function log(){{ try{{ send({{__frida_console:true, args:[].map.call(arguments, function(x){{return ''+x;}})}}); }}catch(e){{}} }}
  try {{ log('[probe] Java.available =', (typeof Java!=='undefined')? Java.available:false); }} catch(e){{ log('[probe] err', e); }}
  try {{
    var mods = Process.enumerateModulesSync().slice(0,50).map(function(m){{return m.name;}});
    log('[probe-modules]', mods.join(', '));
  }} catch(e){{}}
}})();
""",

    # 1) OkHttp：打印请求 URL + 请求体（base64）
    "okhttp_log_url": r"""
Java.perform(function(){{
  function log(){{ try{{ send({{__frida_console:true, args:[].map.call(arguments, function(x){{return ''+x;}})}}); }}catch(e){{}} }}
  try {{
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    var Buffer = Java.use('okio.Buffer');
    var Base64 = Java.use('android.util.Base64');
    var newCall_over = OkHttpClient.newCall.overload('okhttp3.Request');

    newCall_over.implementation = function(request){{
      try {{
        var url = "(unknown)"; try {{ url = request.url().toString(); }} catch(e){{}}
        log('[okhttp hook] url=', url);
        try {{
          var body = request.body();
          if (body) {{
            var buf = Buffer.$new();
            body.writeTo(buf);
            var bytes = buf.readByteArray();
            log('[okhttp hook][body][base64]', Base64.encodeToString(bytes, 0));
          }} else {{
            log('[okhttp hook] no body');
          }}
        }} catch(e){{ log('[okhttp hook] read body err:', e); }}
        return newCall_over.call(this, request);
      }} catch(inner){{
        try {{ return newCall_over.call(this, request); }} catch(e){{ return this.newCall(request); }}
      }}
    }};
    log('[okhttp hook] installed');
  }} catch(e){{
    log('[okhttp hook] install failed:', e);
  }}
}});
""",

    # 2) OkHttp：在 RequestBody.writeTo 处抓包（base64）
    "requestbody_dump": r"""
Java.perform(function() {{
  function log(){{ try{{ send({{__frida_console:true, args:[].map.call(arguments, function(x){{return ''+x;}})}}); }}catch(e){{}} }}
  try {{
    var RequestBody = Java.use("okhttp3.RequestBody");
    var Buffer = Java.use("okio.Buffer");
    var Base64 = Java.use("android.util.Base64");
    var writeToOver = RequestBody.writeTo.overload("okio.BufferedSink");

    writeToOver.implementation = function(sink) {{
      try {{
        var buf = Buffer.$new();
        writeToOver.call(this, buf);           // 先写到内存
        var bytes = buf.readByteArray();
        log("[RequestBody] base64:", Base64.encodeToString(bytes, 0));
      }} catch(e) {{ log("RB err:", e); }}
      return writeToOver.call(this, sink);     // 再写回真实 sink
    }};
    log("[RequestBody] hook installed");
  }} catch(e) {{ log("RequestBody hook fail", e); }}
}});
""",

    # 3) SSL Pinning Bypass（OkHttp + Hostname + TrustManager + HttpsURLConnection 兜底）
    "ssl_pinning_bypass": r"""
Java.perform(function() {{
  function log(){{ try{{ send({{__frida_console:true, args:[].map.call(arguments, function(x){{return ''+x;}})}}); }}catch(e){{}} }}

  // 3.1 OkHttp CertificatePinner.check 全覆盖
  try {{
    var CertPinner = Java.use('okhttp3.CertificatePinner');
    if (CertPinner.check) {{
      CertPinner.check.overloads.forEach(function(ov, idx){{
        ov.implementation = function(){{ log('[bypass] CertificatePinner.check #'+idx+' -> bypass'); return; }};
      }});
    }}
    if (CertPinner['check$okhttp']) {{
      CertPinner['check$okhttp'].overloads.forEach(function(ov, idx){{
        ov.implementation = function(){{ log('[bypass] CertificatePinner.check$okhttp #'+idx+' -> bypass'); return; }};
      }});
    }}
  }} catch(e){{ log('[bypass] CertPinner hook failed:', e); }}

  // 3.2 Hostname 验证兜底
  try {{
    var OkHostnameVerifier = Java.use('okhttp3.internal.tls.OkHostnameVerifier');
    if (OkHostnameVerifier && OkHostnameVerifier.verify) {{
      OkHostnameVerifier.verify.overloads.forEach(function(ov){{
        ov.implementation = function(host, session){{ log('[bypass] OkHostnameVerifier.verify host='+host+' -> true'); return true; }};
      }});
    }}
  }} catch(e){{ log('[bypass] OkHostnameVerifier hook failed:', e); }}

  // 3.3 全局 TrustManager（替换 SSLContext.init）
  try {{
    var X509TM = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    var TrustAll = Java.registerClass({{
      name: 'org.frida.TrustAllManager',
      implements: [X509TM],
      methods: {{
        checkClientTrusted: function(chain, authType) {{}},
        checkServerTrusted: function(chain, authType) {{}},
        getAcceptedIssuers: function() {{ return []; }}
      }}
    }});

    var initOver = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;','[Ljavax.net.ssl.TrustManager;','java.security.SecureRandom');
    initOver.implementation = function(km, tm, sr){{
      log('[bypass] SSLContext.init -> replace TrustManager');
      return initOver.call(this, km, [TrustAll.$new()], sr);
    }};
  }} catch(e){{ log('[bypass] SSLContext hook failed:', e); }}

  // 3.4 HttpsURLConnection 兜底
  try {{
    var HUC = Java.use('javax.net.ssl.HttpsURLConnection');
    HUC.setDefaultHostnameVerifier.implementation = function(verifier){{
      log('[bypass] HttpsURLConnection.setDefaultHostnameVerifier ignored');
      return; // 丢弃外部设置
    }};
  }} catch(e){{}}
}});
""",

    # 4) SharedPreferences Dump（读全打印 + Editor 写路径打印）
    "sharedprefs_dump": r"""
Java.perform(function() {{
  function log(){{ try{{ send({{__frida_console:true, args:[].map.call(arguments, function(x){{return ''+x;}})}}); }}catch(e){{}} }}
  try {{
    var SPImpl = Java.use('android.app.SharedPreferencesImpl');
    var EditorImpl = Java.use('android.app.SharedPreferencesImpl$EditorImpl');

    function whichFile(sp) {{
      try {{
        var f = sp.getClass().getDeclaredField('mFile');
        f.setAccessible(true);
        var file = f.get(sp);
        return file ? file.getAbsolutePath() : '(unknown-file)';
      }} catch(e) {{ return '(unknown-file)'; }}
    }}

    if (SPImpl.getAll) {{
      var getAll = SPImpl.getAll.overload();
      getAll.implementation = function() {{
        var ret = getAll.call(this);
        try {{ log('[SharedPreferences][getAll] file=', whichFile(this), ' -> ', ret.toString()); }} catch(e){{}}
        return ret;
      }};
    }}
    if (SPImpl.getString) {{
      var getStr = SPImpl.getString.overload('java.lang.String','java.lang.String');
      getStr.implementation = function(key, def) {{
        var v = getStr.call(this, key, def);
        try {{ log('[SharedPreferences][getString] file=', whichFile(this), ' ', key, ' = ', v); }} catch(e){{}}
        return v;
      }};
    }}

    function hookEditor(name, sig) {{
      try {{
        var ov = EditorImpl[name].overload.apply(EditorImpl[name], sig);
        ov.implementation = function() {{
          try {{
            if (name.startsWith('put')) {{
              log('[SharedPreferences][Editor.'+name+']', arguments[0], '=', arguments[1]);
            }} else if (name === 'remove') {{
              log('[SharedPreferences][Editor.remove] key=', arguments[0]);
            }} else if (name === 'clear') {{
              log('[SharedPreferences][Editor.clear]');
            }} else if (name === 'apply' || name === 'commit') {{
              log('[SharedPreferences][Editor.'+name+']');
            }}
          }} catch(e){{}}
          return ov.apply(this, arguments);
        }};
      }} catch(e){{}}
    }}

    hookEditor('putString', ['java.lang.String','java.lang.String']);
    hookEditor('putInt', ['java.lang.String','int']);
    hookEditor('putLong', ['java.lang.String','long']);
    hookEditor('putFloat', ['java.lang.String','float']);
    hookEditor('putBoolean', ['java.lang.String','boolean']);
    hookEditor('remove', ['java.lang.String']);
    hookEditor('clear', []);
    hookEditor('apply', []);
    hookEditor('commit', []);

    log('[SharedPreferences] hooks installed');
  }} catch(e) {{ log('sharedprefs_dump err:', e); }}
}});
""",

    # 5) Dump class string fields（静态 + 实例；自动挑 Loader）。需要传入 class_name
    "dump_class_string_fields": r"""
Java.perform(function () {{
  function log(){{ try{{ send({{__frida_console:true, args:[].map.call(arguments, function(x){{return ''+x;}})}}); }}catch(e){{}} }}

  var clsName = "{class_name}";
  log("[dump] target class:", clsName);

  // 5.1 选择能加载该类的 ClassLoader
  try {{
    var loaders = Java.enumerateClassLoadersSync();
    var picked = null;
    for (var i = 0; i < loaders.length; i++) {{
      var L = loaders[i];
      try {{ if (L.findClass && L.findClass(clsName)) {{ picked = L; break; }} }} catch(_){{
      }}
      try {{ if (L.loadClass && L.loadClass(clsName, false)) {{ picked = L; break; }} }} catch(_){{
      }}
    }}
    if (picked) {{ Java.classFactory.loader = picked; log("[dump] picked loader:", picked.$className || picked.toString()); }}
  }} catch(e){{}}

  // 5.2 打印静态 String 字段
  var staticOK = false;
  try {{
    var Clz = Java.use(clsName);
    var Modifier = Java.use("java.lang.reflect.Modifier");
    var fields = Clz.class.getDeclaredFields();
    for (var i = 0; i < fields.length; i++) {{
      try {{
        var f = fields[i]; f.setAccessible(true);
        if (Modifier.isStatic(f.getModifiers()) && f.getType().getName() === "java.lang.String") {{
          var val = f.get(null);
          log("[DUMP][static]", clsName + "." + f.getName(), "=", val);
          staticOK = true;
        }}
      }} catch (eF) {{}}
    }}
  }} catch (eClz) {{
    log("[dump] ERROR: cannot use class:", eClz);
  }}
  if (!staticOK) log("[dump] no static String fields or not accessible");

  // 5.3 枚举实例并打印实例字段
  var found = false;
  Java.choose(clsName, {{
    onMatch: function (inst) {{
      found = true;
      try {{
        var flds = inst.getClass().getDeclaredFields();
        var Modifier = Java.use('java.lang.reflect.Modifier');
        for (var i = 0; i < flds.length; i++) {{
          try {{
            flds[i].setAccessible(true);
            if (flds[i].getType().getName() === "java.lang.String"
                && !Modifier.isStatic(flds[i].getModifiers())) {{
              var v = flds[i].get(inst);
              log("[DUMP][instance]", clsName + "#" + flds[i].getName(), "=", v);
            }}
          }} catch (e1) {{}}
        }}
      }} catch (e2) {{}}
    }},
    onComplete: function () {{ if (!found) log("[dump] no instance found for", clsName); log("[dump] choose complete for", clsName); }}
  }});
}});
""",

    # 6) 搜索所有类的静态 String 中的 JWT（含 Base64 解码尝试）
    "search_jwt_in_static_strings": r"""
Java.perform(function() {{
  function log(){{ try{{ send({{__frida_console:true, args:[].map.call(arguments, function(x){{return ''+x;}})}}); }}catch(e){{}} }}

  // 尝试锁定 App 的 ClassLoader（通过 BuildConfig）
  try {{
    var app = Java.use('android.app.ActivityThread').currentApplication();
    if (app) {{
      var pkg = app.getApplicationContext().getPackageName();
      var buildCfg = pkg + ".BuildConfig";
      var loaders = Java.enumerateClassLoadersSync();
      for (var i=0;i<loaders.length;i++){{ 
        try {{ if (loaders[i].loadClass(buildCfg)) {{ Java.classFactory.loader = loaders[i]; log('[search_jwt] set loader by BuildConfig'); break; }} }} catch(e){{}} 
      }}
    }}
  }} catch(e){{}}

  var JWT_RE_GLOBAL = /[A-Za-z0-9\-_]+?\.[A-Za-z0-9\-_]+?\.[A-Za-z0-9\-_]+/g;
  var JWT_RE_STRICT = /^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$/;

  function toJsString(v){{ try {{ return (v===null||v===undefined) ? "" : (""+v); }} catch(e){{ return ""; }} }}
  function tryBase64Decode(s){{
    try {{
      var Base64 = Java.use('android.util.Base64');
      var bytes = Base64.decode(s, 0);
      var JStr = Java.use('java.lang.String');
      return JStr.$new(bytes).toString();
    }} catch(e){{ return ""; }}
  }}

  var Modifier = Java.use('java.lang.reflect.Modifier');
  var classes = Java.enumerateLoadedClassesSync();
  log("[search_jwt] loaded classes:", classes.length);

  for (var i=0;i<classes.length;i++){{ 
    var name = classes[i];
    try {{
      var C = Java.use(name);
      var fields = C.class.getDeclaredFields();
      for (var j=0;j<fields.length;j++){{ 
        try {{
          var f = fields[j]; f.setAccessible(true);
          if (!Modifier.isStatic(f.getModifiers())) continue;
          if (f.getType().getName() !== "java.lang.String") continue;

          var val = toJsString(f.get(null));
          if (!val) continue;

          if (JWT_RE_STRICT.test(val)) {{
            log("[JWT static] class=", name, " field=", f.getName(), " value=", val);
            continue;
          }}
          var m = val.match(JWT_RE_GLOBAL);
          if (m && m.length) {{
            m.forEach(function(tok){{ log("[JWT static(sub)] class=", name, " field=", f.getName(), " value=", tok); }});
            continue;
          }}
          var dec = tryBase64Decode(val);
          if (dec) {{
            if (JWT_RE_STRICT.test(dec)) {{
              log("[JWT static][b64] class=", name, " field=", f.getName(), " value=", dec);
              continue;
            }}
            var m2 = dec.match(JWT_RE_GLOBAL);
            if (m2 && m2.length) {{
              m2.forEach(function(tok){{ log("[JWT static(sub)][b64] class=", name, " field=", f.getName(), " value=", tok); }});
            }}
          }}
        }} catch(ef) {{}}
      }}
    }} catch(ec) {{}}
  }}
  log("[search_jwt] done.");
}});
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
    Attach/spawn + create/load script using frida-python.
    增强版：增加延迟等待 ART 初始化，避免 Java.perform 不可用。
    """
    if not FRIDA_PY_AVAILABLE:
        return {"error": "frida python module not available"}

    # 拼接 console wrapper
    final_script = CONSOLE_WRAPPER + "\n" + script_text

    # 辅助函数：精确获取 PID
    def _pidof_exact(package: str):
        try:
            p = subprocess.run(
                ["adb", "shell", "pidof", "-s", package],
                capture_output=True, text=True, timeout=4
            )
            out = (p.stdout or "").strip()
            if out and out.split()[0].isdigit():
                return int(out.split()[0])
        except Exception:
            pass
        return None

    def _pick_exact_pid_from_ps(ps_out: str, package: str):
        for ln in (ps_out or "").splitlines():
            if not ln.strip():
                continue
            if not ln.endswith(package):
                continue
            for tok in ln.split():
                if tok.isdigit():
                    return int(tok)
        return None

    try:
        try:
            device = frida.get_usb_device(timeout=4)
        except Exception:
            device = frida.get_local_device()

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
            # ⭐ 增加等待时间，保证 ART 初始化完成
            time.sleep(3.0)
            socketio.emit("frida_log", {"pid": pid, "line": f"[api] spawn attached pid={pid}, resumed, waiting-for-Java..."} )
        else:
            exact_pid = _pidof_exact(target_app)
            if exact_pid is None:
                try:
                    p = subprocess.run(["frida-ps", "-Uai"], capture_output=True, text=True, timeout=5)
                    if p.returncode == 0:
                        exact_pid = _pick_exact_pid_from_ps(p.stdout, target_app)
                except Exception:
                    exact_pid = None

            if exact_pid is not None:
                socketio.emit("frida_log", {"pid": -1, "line": f"[api] attach by PID {exact_pid} ({target_app})"})
                session = device.attach(exact_pid)
                pid = exact_pid
            else:
                socketio.emit("frida_log", {"pid": -1, "line": f"[api] attach by NAME {target_app} (pid 未找到)"} )
                session = device.attach(target_app)
                pid = session._impl.pid if hasattr(session, "_impl") else -1

            # ⭐ 附加后也等一等，避免 ART 未初始化
            time.sleep(1.5)

        # 创建脚本
        script = session.create_script(final_script)
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
                    # fallback wrapper
                    if ("Java" in stack or "java" in stack) and ("not defined" in stack or "ReferenceError" in stack) and not ctx["fallback_injected"]:
                        ctx["fallback_injected"] = True
                        try:
                            fb_code = CONSOLE_WRAPPER + "\n" + wrap_user_script_wait_java(script_text, max_attempts=600, delay_ms=200)
                            fb_script = session.create_script(fb_code)
                            fb_script.on("message", on_message)
                            fb_script.load()
                            socketio.emit("frida_log", {"pid": pid, "line": "[FRIDA FALLBACK] loaded wait-for-Java wrapper"})
                        except Exception as e_f:
                            socketio.emit("frida_log", {"pid": pid, "line": "[FRIDA FALLBACK ERR] " + str(e_f)})
                else:
                    socketio.emit("frida_log", {"pid": pid, "line": "[JS MSG] " + json.dumps(message, ensure_ascii=False)})
            except Exception as e:
                socketio.emit("frida_log", {"pid": pid, "line": "[on_message error] " + str(e)})

        script.on("message", on_message)
        script.load()

        with FRIDA_SESSIONS_LOCK:
            FRIDA_SESSIONS[pid] = {"session": session, "script": script, "device": device, "target": target_app}

        socketio.emit("frida_started", {"pid": pid, "script": f"(in-memory script for {target_app})", "spawn": use_spawn})
        logging.info("Started frida (api) pid=%s spawn=%s target=%s", pid, use_spawn, target_app)
        return {"status": "ok", "pid": pid, "script": f"(in-memory script for {target_app})", "spawn": use_spawn}

    except frida.TransportError as te:
        logging.error("frida transport error: %s", te)
        socketio.emit("frida_log", {"pid": pid or -1, "line": f"[frida transport error] {te}"} )
        return {"error": "frida api error", "detail": str(te)}
    except Exception as e:
        logging.error("frida api error: %s\n%s", e, traceback.format_exc())
        return {"error": "frida api error", "detail": str(e)}



# ------------------ Consolidated wait-wrapper with improved diagnostics ------------------
def wrap_user_script_wait_java(user_js: str, max_attempts: int = 50, delay_ms: int = 100):

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
        return jsonify({"error": "Missing target app"}), 400

    # 1) 生成脚本（渲染模板 + 等待 Java 的包裹）
    try:
        if script_override:
            frida_script = script_override
        elif template_name:
            tpl = FRIDA_TEMPLATES.get(template_name)
            if not tpl:
                return jsonify({"error": "template not found"}), 404
            frida_script = safe_format(tpl, **params)
        elif session_id:
            conn = db_conn()
            row = conn.execute("SELECT url, headers, body FROM sessions WHERE id=?", (session_id,)).fetchone()
            conn.close()
            if not row:
                return jsonify({"error": "Session not found"}), 404
            url = row[0]; body = row[2]
            base_tpl = FRIDA_TEMPLATES.get("requestbody_dump") if (body and len(body.strip()) > 0) else FRIDA_TEMPLATES.get("okhttp_log_url")
            frida_script = safe_format(base_tpl, url=url)
        else:
            frida_script = FRIDA_TEMPLATES.get("okhttp_log_url")
    except Exception as e:
        logging.error("prepare script failed: %s", traceback.format_exc())
        return jsonify({"error": "prepare script failed", "detail": str(e)}), 500

    wrapped_no_console = wrap_user_script_wait_java(frida_script)

    # 2) 写一份到磁盘（CLI 回退用，带 console wrapper）
    script_name = f"frida_{session_id or 'manual'}_{int(time.time())}.js"
    script_path = os.path.join(FRIDA_DIR, script_name)
    try:
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(CONSOLE_WRAPPER + "\n" + wrapped_no_console)
    except Exception as e:
        return jsonify({"error": "write script failed", "detail": str(e)}), 500

    # ---- helpers（仅本函数内使用）----
    def _pidof_exact(package: str):
        """优先用 adb pidof 精确拿主进程 PID。"""
        try:
            p = subprocess.run(["adb", "shell", "pidof", "-s", package],
                               capture_output=True, text=True, timeout=4)
            out = (p.stdout or "").strip()
            if out and out.split()[0].isdigit():
                return int(out.split()[0])
        except Exception:
            pass
        return None

    def _pick_from_frida_ps(package: str):
        """
        从 `frida-ps -Uai` 输出中，找到 Identifier==package 那一行，
        返回 (pid, name)；其中 name 是你 CLI 用的 -n 名称（如 “Demo”）。
        """
        try:
            ps = subprocess.run(["frida-ps", "-Uai"], capture_output=True, text=True, timeout=6)
            if ps.returncode != 0:
                return (None, None, ps.stdout or "", ps.stderr or "")
            for ln in (ps.stdout or "").splitlines():
                # 行样例: "8608  Demo            com.example.demo"
                s = ln.strip()
                if not s:
                    continue
                if not s.endswith(f" {package}"):
                    continue
                toks = s.split()
                # 最后一个是 Identifier（包名），第一个数字是 PID，Name 介于中间（可能包含空格）
                pid = None
                for tok in toks:
                    if tok.isdigit():
                        pid = int(tok); break
                # Name 列：从 PID 后到最后一个 token(包名) 之间的内容合并
                try:
                    last = s.rfind(package)
                    after_pid = s.find(str(pid)) + len(str(pid))
                    name = s[after_pid:last].strip()
                except Exception:
                    name = None
                return (pid, name, ps.stdout or "", "")
        except Exception:
            return (None, None, "", "")
        return (None, None, ps.stdout or "", "")

    # 3) 首选 frida-python API
    if FRIDA_PY_AVAILABLE:
        try:
            exact_pid = _pidof_exact(target_app)
            pid_from_ps, name_from_ps, ps_out, ps_err = (None, None, "", "")
            if exact_pid is None:
                pid_from_ps, name_from_ps, ps_out, ps_err = _pick_from_frida_ps(target_app)

            proc_found = exact_pid is not None or pid_from_ps is not None

            # 强约束：用户显式要求 spawn 则尊重；否则“进程存在就 attach，不存在再 spawn”
            use_spawn = bool(spawn) or (not proc_found)

            if use_spawn:
                socketio.emit("frida_log", {"pid": -1, "line": f"[run] spawning {target_app} (no exact PID found)"} )
            else:
                msg = f"[run] attaching: "
                if exact_pid is not None:
                    msg += f"PID={exact_pid}"
                elif pid_from_ps is not None:
                    msg += f"PID={pid_from_ps}, Name={name_from_ps!r}"
                socketio.emit("frida_log", {"pid": -1, "line": msg})

            res = _start_frida_via_api_sync(
                target_app=target_app,
                script_text=wrapped_no_console,
                use_spawn=use_spawn
            )
            status_code = 200 if res.get("status") == "ok" else 500
            return jsonify(res), status_code
        except Exception as e:
            logging.error("frida api path failed: %s", traceback.format_exc())
            # 回退到 CLI

    # 4) CLI 回退
    try:
        check = subprocess.run(["frida", "--version"], capture_output=True, text=True, timeout=5)
        if check.returncode != 0:
            return jsonify({"error": "frida cli not available", "detail": check.stderr or check.stdout}), 500
    except Exception as e:
        return jsonify({"error": "frida cli check failed", "detail": str(e)}), 500

    # 再做一次解析，决定 attach/spawn 与附加目标
    exact_pid = _pidof_exact(target_app)
    pid_from_ps, name_from_ps, ps_out, ps_err = _pick_from_frida_ps(target_app)

    use_spawn = bool(spawn) or (exact_pid is None and pid_from_ps is None)

    cmd = ["frida", "-U"]
    if use_spawn:
        socketio.emit("frida_log", {"pid": -1, "line": f"[cli] spawn -f {target_app} -l {os.path.basename(script_path)}"})
        cmd += ["-f", target_app, "-l", script_path]
    else:
        if exact_pid is not None:
            socketio.emit("frida_log", {"pid": -1, "line": f"[cli] attach -p {exact_pid} -l {os.path.basename(script_path)}"})
            cmd += ["-p", str(exact_pid), "-l", script_path]
        elif pid_from_ps is not None and name_from_ps:
            # 复现你 CLI 成功路径：按 Name 附加
            socketio.emit("frida_log", {"pid": -1, "line": f"[cli] attach -n {name_from_ps!r} -l {os.path.basename(script_path)}"})
            cmd += ["-n", name_from_ps, "-l", script_path]
        else:
            # 兜底才用包名按名字附加
            socketio.emit("frida_log", {"pid": -1, "line": f"[cli] attach -n {target_app} -l {os.path.basename(script_path)} (pid/name not resolved)"} )
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

    # 渲染模板
    tpl = FRIDA_TEMPLATES.get(template_name)
    if not tpl:
        return jsonify({"error":"template not found"}), 404
    user_script = safe_format(tpl, **params)

    # 拼接 wrapper: 等待 Java + console 重定向
    wrapped = wrap_user_script_wait_java(user_script)
    final_script = CONSOLE_WRAPPER + "\n" + wrapped

    # 保存脚本以便 CLI fallback
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
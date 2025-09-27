// search_jwt_in_static_strings.js (improved, parametric)
//
// Params (safe_format 占位符):
//   {package_prefix}  // e.g. "com.example.demo"；为空表示不限制包名
//   {scan_limit}      // e.g. 3000；0 表示不限制（不建议）
//   {batch_size}      // e.g. 200；批量聚合输出
//   {include_sub}     // true/false；是否打印“子串命中(sub)”
//
// 若后端未传参，下面会设本地默认。

Java.perform(function() {
  // -------------- 参数归一化 --------------
  function _normStr(s, d) { try { return (s && s !== "{package_prefix}") ? ("" + s) : d; } catch(_) { return d; } }
  function _normInt(s, d) {
    try {
      if (s === "{scan_limit}" || s === "{batch_size}") return d;
      var n = parseInt(s, 10);
      return isNaN(n) ? d : n;
    } catch(_) { return d; }
  }
  function _normBool(s, d) {
    try {
      if (s === "{include_sub}") return d;
      if (typeof s === "boolean") return s;
      var t = ("" + s).toLowerCase().trim();
      return t === "1" || t === "true" || t === "yes";
    } catch(_) { return d; }
  }

  var PARAM_PACKAGE_PREFIX = _normStr("{package_prefix}", "");     // 建议: 你的包名
  var PARAM_SCAN_LIMIT     = _normInt("{scan_limit}", 3000);       // 0 = 不限制
  var PARAM_BATCH_SIZE     = _normInt("{batch_size}", 200);
  var PARAM_INCLUDE_SUB    = _normBool("{include_sub}", false);    // 默认不打印子串命中

  // -------------- 基础工具 --------------
  function log() {
    try { send({ __frida_console: true, args: Array.prototype.slice.call(arguments) }); } catch(e) {}
  }

  // 批量缓冲，减少 send 次数，避免 JNI 全局引用暴涨
  var _BUF = [];
  function _push(line) {
    _BUF.push(line);
    if (_BUF.length >= PARAM_BATCH_SIZE) _flush();
  }
  function _flush() {
    if (_BUF.length === 0) return;
    try { send({ __frida_console: true, args: ["[search_jwt][batch]", _BUF.join("\n")] }); } catch(_) {}
    _BUF.length = 0;
  }

  // Base64URL/DEFAULT 双模式解码尝试
  var Base64 = Java.use('android.util.Base64');
  var JStr   = Java.use('java.lang.String');
  function _b64decodeToString(s) {
    if (!s) return "";
    try {
      // URL_SAFE
      var b1 = Base64.decode(s, 8 /* URL_SAFE */);
      return JStr.$new(b1).toString();
    } catch(e1) {
      try {
        var b2 = Base64.decode(s, 0 /* DEFAULT */);
        return JStr.$new(b2).toString();
      } catch(e2) {
        return "";
      }
    }
  }

  // 预筛：三段式 & base64url 字符，且每段长度 >= 10（减少系统常量误报）
  function looksLikeJwtLiteralFast(s) {
    if (!s || typeof s !== 'string') return false;
    var parts = s.split('.');
    if (parts.length !== 3) return false;
    for (var i = 0; i < 3; i++) {
      if (!/^[A-Za-z0-9\-_]{10,}$/.test(parts[i])) return false;
    }
    return true;
  }

  // 严格校验：header/payload 可解码 + header.typ == JWT（大小写不敏感）
  function isRealJwt(s) {
    if (!looksLikeJwtLiteralFast(s)) return false;
    try {
      var parts = s.split('.');
      var headerJson = _b64decodeToString(parts[0]);
      var payloadJson = _b64decodeToString(parts[1]);
      if (!headerJson || !payloadJson) return false;
      var header = JSON.parse(headerJson);
      // 允许 typ 为 "JWT" 或 "jwt"
      var typ = (header && header.typ) ? ("" + header.typ).toUpperCase() : "";
      if (typ !== "JWT") return false;
      // alg 存在即更可信
      if (!header.alg) return false;
      return true;
    } catch(_) {
      return false;
    }
  }

  // 子串搜索（可关）
  var JWT_RE_GLOBAL = /[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}/g;

  // -------------- 可选：定位 App ClassLoader（用 BuildConfig） --------------
  try {
    var app = Java.use('android.app.ActivityThread').currentApplication();
    if (app) {
      var pkg = app.getApplicationContext().getPackageName();
      var buildCfg = pkg + ".BuildConfig";
      var loaders = Java.enumerateClassLoadersSync();
      for (var i=0; i<loaders.length; i++) {
        try { if (loaders[i].loadClass(buildCfg)) { Java.classFactory.loader = loaders[i]; log("[search_jwt] set loader by BuildConfig ->", buildCfg); break; } } catch(e){}
      }
      if (!PARAM_PACKAGE_PREFIX) PARAM_PACKAGE_PREFIX = pkg; // 若未指定包前缀，则默认用 app 包名
    }
  } catch(e){}

  var Modifier = Java.use('java.lang.reflect.Modifier');
  var classes = Java.enumerateLoadedClassesSync();
  log("[search_jwt] loaded classes:", classes.length, "prefix:", PARAM_PACKAGE_PREFIX || "(none)", "limit:", PARAM_SCAN_LIMIT);

  var scanned = 0, realHits = 0, subHits = 0;

  outer:
  for (var ci = 0; ci < classes.length; ci++) {
    var name = classes[ci];

    // 包名前缀过滤（强烈建议启用；否则会扫到大量 android/java/okhttp 的系统常量）
    if (PARAM_PACKAGE_PREFIX && name.indexOf(PARAM_PACKAGE_PREFIX) !== 0) continue;

    scanned++;
    if (PARAM_SCAN_LIMIT > 0 && scanned > PARAM_SCAN_LIMIT) break outer;

    var C = null;
    try { C = Java.use(name); } catch(eC) { continue; }
    if (!C || !C.class || !C.class.getDeclaredFields) { continue; }

    var fields = null;
    try { fields = C.class.getDeclaredFields(); } catch(eF) { continue; }
    if (!fields) continue;

    for (var fi = 0; fi < fields.length; fi++) {
      var f = fields[fi];
      try {
        f.setAccessible(true);
        if (!Modifier.isStatic(f.getModifiers())) continue;
        if (f.getType().getName() !== "java.lang.String") continue;

        // —— 轻量预筛（字段名/类名可加关键字白/黑名单，这里仅长度&字符集）——
        // 不先取值，防止无谓 JNI 引用创建；先做必要性判断
        // 这里我们还是需要取值再严格判断
        var v = f.get(null);
        var sval = (v === null || v === undefined) ? "" : ("" + v);
        v = null; // 立刻释放 Java 引用

        if (!sval) continue;

        // 真 JWT：严格校验
        if (isRealJwt(sval)) {
          realHits++;
          _push("[JWT static] class=" + name + " field=" + f.getName() + " value=" + sval);
          continue;
        }

        // 子串命中：仅在 include_sub=true 时输出，且只输出少量
        if (PARAM_INCLUDE_SUB) {
          var m = sval.match(JWT_RE_GLOBAL);
          if (m && m.length) {
            for (var mi = 0; mi < m.length; mi++) {
              var tok = m[mi];
              if (isRealJwt(tok)) { // 子串也要再过一次严格校验，减少噪音
                subHits++;
                _push("[JWT static(sub)] class=" + name + " field=" + f.getName() + " value=" + tok);
              }
            }
          }
        }

      } catch(eField) {
        // ignore this field
      }
    } // end fields loop
  } // end classes loop

  _flush();
  log("[search_jwt] done. scanned_classes=", scanned, "real_hits=", realHits, "sub_hits=", subHits, "prefix=", PARAM_PACKAGE_PREFIX || "(none)");
});

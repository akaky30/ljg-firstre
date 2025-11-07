// Enhanced SSL Pinning Bypass (Java + Native/Cronet) - ASCII logs, idempotent, safer return types
// Optional CA re-pinning support: point CUSTOM_CA_PATH to your mitmproxy/burp certificate in DER form.
var CUSTOM_CA_PATH = "/data/local/tmp/cert-der.crt";
var ENABLE_CUSTOM_CA = true;

setImmediate(function () {
  if (globalThis.__frida_bypass_pinning_installed) {
    try { send({ __frida_console: true, args: ["[BYPASS] ALREADY INSTALLED - Script already running"] }); } catch (_) {}
    return;
  }
  globalThis.__frida_bypass_pinning_installed = true;

  // keep native callbacks from GC
  var __native_keep = { callbacks: [] };

  function log() {
    try { send({ __frida_console: true, args: Array.prototype.slice.call(arguments) }); } catch (e) {}
  }

  // --------------------------- Java Layer ---------------------------
  Java.perform(function () {

    var STATUS = {
      SUCCESS: "SUCCESS",
      FAILED: "FAILED",
      WARNING: "WARNING",
      INFO: "INFO"
    };

    var state = {
      pinnerBypassed: false,
      hostBypassed: false,
      handshakeError: false,
      hosts: new Set(),
      hookedModules: new Set(),
      failedHooks: new Set(),
      startTime: Date.now()
    };

    var repinState = {
      enabled: !!ENABLE_CUSTOM_CA,
      path: CUSTOM_CA_PATH,
      loaded: false,
      error: null,
      subject: null,
      trustManagers: null,
      socketFactory: null,
      buildingSocket: false
    };

    var CertificateFactory = null;
    var FileInputStream = null;
    var BufferedInputStream = null;
    var X509Certificate = null;
    var KeyStore = null;
    var TrustManagerFactory = null;

    try { CertificateFactory = Java.use("java.security.cert.CertificateFactory"); } catch (_) {}
    try { FileInputStream = Java.use("java.io.FileInputStream"); } catch (_) {}
    try { BufferedInputStream = Java.use("java.io.BufferedInputStream"); } catch (_) {}
    try { X509Certificate = Java.use("java.security.cert.X509Certificate"); } catch (_) {}
    try { KeyStore = Java.use("java.security.KeyStore"); } catch (_) {}
    try { TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory"); } catch (_) {}

    function ensureCustomTrustManagers() {
      if (!repinState.enabled) return null;
      if (repinState.trustManagers) return repinState.trustManagers;
      if (!CertificateFactory || !FileInputStream || !BufferedInputStream || !KeyStore || !TrustManagerFactory) {
        log("[WARN] [REPIN] Required Java classes unavailable; skipping custom CA loading");
        repinState.error = "Required Java classes unavailable";
        return null;
      }
      try {
        log("[INFO] [REPIN] Loading custom CA from " + repinState.path);
        var cf = CertificateFactory.getInstance("X.509");
        var fileInputStream = FileInputStream.$new(repinState.path);
        var bufferedInputStream = BufferedInputStream.$new(fileInputStream);
        var ca = cf.generateCertificate(bufferedInputStream);
        try { bufferedInputStream.close(); } catch (_) {}
        try { fileInputStream.close(); } catch (_) {}

        var certInfo = X509Certificate ? Java.cast(ca, X509Certificate) : null;
        if (certInfo) {
          repinState.subject = "" + certInfo.getSubjectDN();
          log("[INFO] [REPIN] Custom CA subject: " + repinState.subject);
        }

        var keyStoreType = KeyStore.getDefaultType();
        var keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);
        keyStore.setCertificateEntry("frida-custom-ca", ca);

        var tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        var tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
        tmf.init(keyStore);
        repinState.trustManagers = tmf.getTrustManagers();
        repinState.loaded = true;
        log("[OK] [REPIN] TrustManager initialized with custom CA");
        return repinState.trustManagers;
      } catch (err) {
        repinState.error = "" + err;
        log("[WARN] [REPIN] Failed to load custom CA (" + repinState.path + "): " + err);
        return null;
      }
    }

    function ensureCustomSocketFactory(SSLContext) {
      if (repinState.socketFactory) return repinState.socketFactory;
      var tmArray = ensureCustomTrustManagers();
      if (!tmArray) return null;
      try {
        var ctx = SSLContext.getInstance("TLS");
        repinState.buildingSocket = true;
        try {
          ctx.init(null, tmArray, null);
        } finally {
          repinState.buildingSocket = false;
        }
        repinState.socketFactory = ctx.getSocketFactory();
        log("[OK] [REPIN] Custom SSLSocketFactory constructed");
        return repinState.socketFactory;
      } catch (err) {
        log("[WARN] [REPIN] Unable to build SSLSocketFactory: " + err);
        return null;
      }
    }

    if (repinState.enabled) {
      ensureCustomTrustManagers();
    }

    function printBanner() {
      log("================================================");
      log("=== SSL PINNING BYPASS SCRIPT INITIALIZED ===");
      log("================================================");
      log("[STATUS] Script loaded successfully");
      log("[INFO] Monitoring SSL/TLS operations...");
    }
    printBanner();

    // 0) Monitor SSLHandshakeException
    try {
      var HEx = Java.use('javax.net.ssl.SSLHandshakeException');
      HEx.$init.overloads.forEach(function (ov) {
        if (ov.__frida_hooked) return;
        ov.__frida_hooked = true;
        ov.implementation = function () {
          try {
            state.handshakeError = true;
            var msg = arguments.length ? ("" + arguments[0]) : "";
            log("[WARN] SSL_HANDSHAKE_EXCEPTION Message:", msg);
          } catch (_) {}
          return ov.apply(this, arguments);
        };
      });
      log("[HOOK_STATUS: " + STATUS.SUCCESS + "] SSLHandshakeException monitoring active");
    } catch (e) {
      state.failedHooks.add('SSLHandshakeException');
      log("[HOOK_STATUS: " + STATUS.FAILED + "] SSLHandshakeException hook failed");
    }

    // 1) OkHttp CertificatePinner.check -> bypass
    try {
      var CertPinner = Java.use('okhttp3.CertificatePinner');
      var pinnerMethods = ['check', 'check$okhttp'];
      var pinnedHooks = 0;

      pinnerMethods.forEach(function (methodName) {
        if (CertPinner[methodName]) {
          CertPinner[methodName].overloads.forEach(function (ov, idx) {
            if (ov.__frida_hooked) return;
            ov.__frida_hooked = true;
            ov.implementation = function () {
              state.pinnerBypassed = true;
              state.hookedModules.add('OkHttp.CertificatePinner');
              log("[OK] [CERTIFICATE_PINNER_BYPASS] Method " + methodName + " #" + idx + " -> BYPASSED");
              return; // swallow
            };
            pinnedHooks++;
          });
        }
      });
      if (pinnedHooks > 0) {
        log("[HOOK_STATUS: " + STATUS.SUCCESS + "] OkHttp CertificatePinner hooks installed: " + pinnedHooks);
      }
    } catch (e) {
      state.failedHooks.add('OkHttp.CertificatePinner');
      log("[HOOK_STATUS: " + STATUS.FAILED + "] OkHttp CertificatePinner hook failed");
    }

    // 2) OkHttp Hostname verification -> always true
    try {
      var OkHostnameVerifier = Java.use('okhttp3.internal.tls.OkHostnameVerifier');
      if (OkHostnameVerifier && OkHostnameVerifier.verify) {
        OkHostnameVerifier.verify.overloads.forEach(function (ov) {
          if (ov.__frida_hooked) return;
          ov.__frida_hooked = true;
          ov.implementation = function (host, session) {
            try { state.hosts.add(String(host)); } catch (_) {}
            state.hostBypassed = true;
            state.hookedModules.add('OkHttp.HostnameVerifier');
            log("[OK] [HOSTNAME_VERIFIER_BYPASS] Host: " + host + " -> VERIFICATION_OVERRIDDEN");
            return true;
          };
        });
        log("[HOOK_STATUS: " + STATUS.SUCCESS + "] OkHttp HostnameVerifier hook installed");
      }
    } catch (e) {
      state.failedHooks.add('OkHostnameVerifier');
      log("[HOOK_STATUS: " + STATUS.FAILED + "] OkHttp HostnameVerifier hook failed");
    }

    // 3) Global TrustManager via SSLContext.init
    try {
      var X509TM = Java.use('javax.net.ssl.X509TrustManager');
      var SSLContext = Java.use('javax.net.ssl.SSLContext');

      var TrustAll;
      try {
        TrustAll = Java.use('org.frida.TrustAllManager');
      } catch (_) {
        TrustAll = Java.registerClass({
          name: 'org.frida.TrustAllManager',
          implements: [X509TM],
          methods: {
            checkClientTrusted: function (chain, authType) {
              log("[OK] [TRUST_MANAGER_BYPASS] Client certificate check -> ALLOWED");
            },
            checkServerTrusted: function (chain, authType) {
              log("[OK] [TRUST_MANAGER_BYPASS] Server certificate check -> ALLOWED");
            },
            getAcceptedIssuers: function () {
              return Java.array('Ljava.security.cert.X509Certificate;', []);
            }
          }
        });
      }

      SSLContext.init.overloads.forEach(function (ov) {
        if (ov.__frida_hooked) return;
        ov.__frida_hooked = true;
        ov.implementation = function (km, tm, sr) {
          if (repinState.buildingSocket) {
            return ov.call(this, km, tm, sr);
          }
          state.hookedModules.add('SSLContext.init');
          var tmArray = ensureCustomTrustManagers();
          if (tmArray) {
            log("[OK] [SSL_CONTEXT_REPIN] Replacing TrustManagers with custom CA bundle");
            return ov.call(this, km, tmArray, sr);
          }
          log("[OK] [SSL_CONTEXT_BYPASS] TrustManager replaced with TrustAllManager");
          var TMArray = Java.array('Ljavax.net.ssl.TrustManager;', [TrustAll.$new()]);
          return ov.call(this, km, TMArray, sr);
        };
      });
      log("[HOOK_STATUS: " + STATUS.SUCCESS + "] SSLContext TrustManager hooks installed: " + SSLContext.init.overloads.length);
    } catch (e) {
      state.failedHooks.add('SSLContext.TrustManager');
      log("[HOOK_STATUS: " + STATUS.FAILED + "] SSLContext TrustManager hook failed");
    }

    // 4) HttpsURLConnection fallback
    try {
      var HUC = Java.use('javax.net.ssl.HttpsURLConnection');
      try {
        var customFactory = ensureCustomSocketFactory(SSLContext);
        if (customFactory) {
          HUC.setDefaultSSLSocketFactory(customFactory);
          log("[OK] [REPIN] HttpsURLConnection default SSLSocketFactory set to custom CA");
        }
      } catch (e) {
        log("[WARN] [REPIN] Unable to set default SSLSocketFactory: " + e);
      }
      if (HUC.setDefaultHostnameVerifier && !HUC.setDefaultHostnameVerifier.__frida_hooked) {
        HUC.setDefaultHostnameVerifier.__frida_hooked = true;
        HUC.setDefaultHostnameVerifier.implementation = function (verifier) {
          state.hookedModules.add('HttpsURLConnection.setDefaultHostnameVerifier');
          log("[OK] [HTTPS_URL_CONNECTION_BYPASS] setDefaultHostnameVerifier -> PREVENTED");
          return; // drop
        };
      }
      if (HUC.setHostnameVerifier && !HUC.setHostnameVerifier.__frida_hooked) {
        HUC.setHostnameVerifier.__frida_hooked = true;
        HUC.setHostnameVerifier.implementation = function (verifier) {
          state.hookedModules.add('HttpsURLConnection.setHostnameVerifier');
          log("[OK] [HTTPS_URL_CONNECTION_BYPASS] setHostnameVerifier -> PREVENTED");
          return; // drop
        };
      }
      log("[HOOK_STATUS: " + STATUS.SUCCESS + "] HttpsURLConnection hooks installed");
    } catch (e) {
      state.failedHooks.add('HttpsURLConnection');
      log("[HOOK_STATUS: " + STATUS.FAILED + "] HttpsURLConnection hook failed");
    }

    // 5) Apache HttpClient (log only)
    try {
      var ApacheSSLSocketFactory = Java.use('org.apache.http.conn.ssl.SSLSocketFactory');
      var apacheHooks = 0;
      ApacheSSLSocketFactory.$init.overloads.forEach(function (ov) {
        if (ov.__frida_hooked) return;
        ov.__frida_hooked = true;
        ov.implementation = function () {
          state.hookedModules.add('Apache.SSLSocketFactory');
          log("[OK] [APACHE_BYPASS] SSLSocketFactory init intercepted");
          return ov.apply(this, arguments);
        };
        apacheHooks++;
      });
      if (apacheHooks > 0) log("[HOOK_STATUS: " + STATUS.SUCCESS + "] Apache HttpClient hooks installed: " + apacheHooks);
    } catch (e) {
      state.failedHooks.add('Apache.HttpClient');
      log("[HOOK_STATUS: " + STATUS.FAILED + "] Apache HttpClient hook failed (library may not be used)");
    }

    // 6) X509TrustManagerExtensions - FIX return type to List (avoid crash)
    try {
      var X509TrustManagerExtensions = Java.use('android.net.http.X509TrustManagerExtensions');
      var Arrays = Java.use('java.util.Arrays');
      // signature: List<X509Certificate> checkServerTrusted(X509Certificate[] chain, String authType, String host)
      var checkServerTrusted = X509TrustManagerExtensions.checkServerTrusted.overload(
        '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String'
      );
      if (!checkServerTrusted.__frida_hooked) {
        checkServerTrusted.__frida_hooked = true;
        checkServerTrusted.implementation = function (chain, authType, host) {
          state.hookedModules.add('X509TrustManagerExtensions');
          log("[OK] [SYSTEM_TRUST_MANAGER_BYPASS] allow host: " + host);
          // MUST return java.util.List, not array
          return Arrays.asList(chain);
        };
        log("[HOOK_STATUS: " + STATUS.SUCCESS + "] X509TrustManagerExtensions hook installed");
      }
    } catch (e) {
      state.failedHooks.add('X509TrustManagerExtensions');
      log("[HOOK_STATUS: " + STATUS.FAILED + "] X509TrustManagerExtensions hook failed");
    }

    // 7) TrustKit (if present)
    try {
      var TrustKit = Java.use('com.datatheorem.security.TrustKit');
      if (TrustKit && TrustKit.checkServerTrusted) {
        var tk = TrustKit.checkServerTrusted.overload(
          '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String'
        );
        if (!tk.__frida_hooked) {
          tk.__frida_hooked = true;
          tk.implementation = function (chain, hostname, authType) {
            state.hookedModules.add('TrustKit');
            log("[OK] [TRUSTKIT_BYPASS] allow host: " + hostname);
            return; // swallow
          };
          log("[HOOK_STATUS: " + STATUS.SUCCESS + "] TrustKit hook installed");
        }
      }
    } catch (e) {
      state.failedHooks.add('TrustKit');
      log("[HOOK_STATUS: " + STATUS.FAILED + "] TrustKit hook failed (library may not be used)");
    }

    // 8) WebViewClient SSL errors -> proceed
    try {
      var WebViewClient = Java.use('android.webkit.WebViewClient');
      var onReceivedSslError = WebViewClient.onReceivedSslError.overload(
        'android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError'
      );
      if (!onReceivedSslError.__frida_hooked) {
        onReceivedSslError.__frida_hooked = true;
        onReceivedSslError.implementation = function (view, handler, error) {
          state.hookedModules.add('WebViewClient.onReceivedSslError');
          log("[OK] [WEBVIEW_BYPASS] SSL error -> PROCEED");
          handler.proceed();
        };
        log("[HOOK_STATUS: " + STATUS.SUCCESS + "] WebViewClient SSL error handler hook installed");
      }
    } catch (e) {
      state.failedHooks.add('WebViewClient');
      log("[HOOK_STATUS: " + STATUS.FAILED + "] WebViewClient hook failed");
    }

    // 9) Optional: Conscrypt TrustManagerImpl (return List when method expects List)
    (function tryHookConscrypt() {
      var candidates = [
        'com.android.org.conscrypt.TrustManagerImpl',
        'org.conscrypt.TrustManagerImpl'
      ];
      var Arrays = null;
      try { Arrays = Java.use('java.util.Arrays'); } catch (_) {}

      candidates.forEach(function (name) {
        try {
          var Cls = Java.use(name);
          var done = 0;

          ['checkServerTrusted', 'checkTrusted'].forEach(function (m) {
            if (!Cls[m]) return;
            Cls[m].overloads.forEach(function (ov) {
              // Only override when the method RETURN TYPE is java.util.List (avoid type mismatch)
              if (String(ov.returnType) === 'java.util.List' && Arrays) {
                if (ov.__frida_hooked) return;
                ov.__frida_hooked = true;
                ov.implementation = function () {
                  try {
                    var chain = arguments[0]; // X509Certificate[]
                    var host = (arguments.length >= 3) ? ("" + arguments[2]) : "(unknown)";
                    state.hookedModules.add(name + '.' + m);
                    log("[OK] [" + name + "." + m + "] allow host: " + host + " -> return List(chain)");
                    return Arrays.asList(chain);
                  } catch (e) {
                    log("[WARN] " + name + "." + m + " fallback due to: " + e);
                    return ov.apply(this, arguments);
                  }
                };
                done++;
              }
            });
          });
          if (done > 0) log("[HOOK_STATUS: " + STATUS.SUCCESS + "] Conscrypt hooks on " + name + ": " + done);
        } catch (_) {}
      });
    })();

    // Initial status
    setTimeout(function () {
      var activeHooks = state.hookedModules.size;
      var hosts = Array.from(state.hosts.values()).join(", ") || "NO_HOSTS_OBSERVED";
      if (activeHooks > 0) {
        log("[INFO] [INITIAL_STATUS: BYPASS_ACTIVE]");
        log("[OK] Active hooks: " + activeHooks);
        log("[ACTIVE_MODULES] " + Array.from(state.hookedModules.values()).join(", "));
        log("[OBSERVED_HOSTS] " + hosts);
      } else {
        log("[INFO] [INITIAL_STATUS: BYPASS_MISSING]");
        log("[WARN] No bypass hooks activated yet");
        log("[ADVICE] Trigger HTTPS requests in the app or wait longer");
      }
      if (repinState.enabled) {
        if (repinState.loaded) {
          log("[INFO] [REPIN] Custom CA in use: " + (repinState.subject || repinState.path));
        } else if (repinState.error) {
          log("[WARN] [REPIN] Custom CA load failed: " + repinState.error);
        } else {
          log("[WARN] [REPIN] Custom CA not yet applied");
        }
      }
      if (state.handshakeError) {
        log("[WARN] SSL handshake errors detected - this may indicate system trust issues");
      }
    }, 3000);

    // Final summary
    function printFinalSummary() {
      var duration = (Date.now() - state.startTime) / 1000;
      var hosts = Array.from(state.hosts.values()).join(", ") || "NO_HOSTS_OBSERVED";
      var successfulHooks = Array.from(state.hookedModules.values());
      var failedHooks = Array.from(state.failedHooks.values());

      log("================================================");
      log("=== FINAL BYPASS SUMMARY ===");
      log("================================================");
      log("[DURATION] Monitoring time: " + duration + " seconds");
      log("[HOSTS] Observed hosts: " + hosts);

      if (successfulHooks.length > 0) {
        log("[OK] [BYPASS_STATUS: SUCCESS]");
        log("[OK] Active hooks: " + successfulHooks.join(", "));
        log("[RESULT] SSL pinning bypass appears to be working");
      } else {
        log("[FAIL] [BYPASS_STATUS: FAILED]");
        log("[FAIL] No SSL hooks were activated");
      }

      if (failedHooks.length > 0) {
        log("[WARN] Failed to hook: " + failedHooks.join(", "));
      }

      if (state.handshakeError) {
        log("[WARN] SSL_HANDSHAKE_ERROR observed");
        log("[ISSUE] SSL handshake failures detected");
        log("[POSSIBLE_CAUSES] System trust issues, wrong device time, proxy CA problems");
      }

      if (successfulHooks.length === 0) {
        log("================================================");
        log("[TROUBLESHOOTING] Possible reasons for failure:");
        log("1. App uses Cronet/native TLS path (not Java)");
        log("2. Native certificate pinning via JNI/so");
        log("3. Unconventional network library");
        log("4. Root detection / anti-Frida");
        log("[SOLUTION] Enable native hooks (included), trust proxy CA at system level, or use Xposed/objection");
        log("================================================");
      }
      if (repinState.enabled) {
        if (repinState.loaded) {
          log("[INFO] [REPIN SUMMARY] Custom CA subject: " + (repinState.subject || repinState.path));
        } else {
          log("[WARN] [REPIN SUMMARY] Custom CA unusable: " + (repinState.error || "unknown error"));
        }
      }
    }

    setTimeout(printFinalSummary, 8000);
    setTimeout(function () {
      if (state.hookedModules.size === 0) {
        log("================================================");
        log("[FAIL] [FINAL_STATUS: BYPASS_FAILED]");
        log("[CRITICAL] No SSL bypass methods were successful");
        log("[RECOMMENDATION] Try:");
        log("1) Magisk: move user CA to system store");
        log("2) Xposed: JustTrustMe / TrustMeAlready");
        log("3) objection: android sslpinning disable");
        log("4) Native hooks for Cronet (enabled below)");
        log("================================================");
      }
    }, 15000);

  }); // end Java.perform

  // --------------------------- Native Layer (Cronet / BoringSSL) ---------------------------
  // Try to bypass at libssl / boringssl / cronet level
  (function tryNativeBypass() {
    try {
      var modules = [
        'libssl.so',
        'libboringssl.so',
        'libcronet.so',
        'libsscronet.so',
        'libconscrypt_jni.so'
      ];

      function hookReplace(modName, symName, retType, argTypes, impl) {
        try {
          var addr = Module.findExportByName(modName, symName);
          if (!addr) return false;
          var cb = new NativeCallback(impl, retType, argTypes);
          __native_keep.callbacks.push(cb);
          Interceptor.replace(addr, cb);
          log("[OK] [NATIVE_BYPASS] replace " + symName + " in " + modName + " @ " + addr);
          return true;
        } catch (e) {
          log("[WARN] native replace " + symName + " in " + modName + " failed: " + e);
          return false;
        }
      }

      function hookAttach(modName, symName, onEnterFn) {
        try {
          var addr = Module.findExportByName(modName, symName);
          if (!addr) return false;
          Interceptor.attach(addr, { onEnter: onEnterFn });
          log("[OK] [NATIVE_BYPASS] attach " + symName + " in " + modName + " @ " + addr);
          return true;
        } catch (e) {
          log("[WARN] native attach " + symName + " in " + modName + " failed: " + e);
          return false;
        }
      }

      var installed = 0;

      // X509_verify_cert(X509_STORE_CTX*) -> int (1 = OK)
      modules.forEach(function (m) {
        if (hookReplace(m, 'X509_verify_cert', 'int', ['pointer'], function (ctxPtr) { return 1; })) installed++;
      });

      // SSL_get_verify_result(SSL*) -> int (0 = X509_V_OK)
      modules.forEach(function (m) {
        if (hookReplace(m, 'SSL_get_verify_result', 'int', ['pointer'], function (sslPtr) { return 0; })) installed++;
      });

      // SSL_set_custom_verify(SSL*, int, cb)
      modules.forEach(function (m) {
        var addr = Module.findExportByName(m, 'SSL_set_custom_verify');
        if (addr) {
          var passCb = new NativeCallback(function () { return 1; }, 'int', ['pointer', 'pointer']);
          __native_keep.callbacks.push(passCb);
          Interceptor.attach(addr, {
            onEnter: function (args) {
              // args[0]=SSL*, args[1]=mode(int), args[2]=cb
              args[2] = passCb;
              log("[OK] [NATIVE_BYPASS] SSL_set_custom_verify -> force pass callback in " + m);
            }
          });
          installed++;
        }
      });

      // SSL_CTX_set_custom_verify(SSL_CTX*, int, cb)
      modules.forEach(function (m) {
        var addr = Module.findExportByName(m, 'SSL_CTX_set_custom_verify');
        if (addr) {
          var passCb2 = new NativeCallback(function () { return 1; }, 'int', ['pointer', 'pointer']);
          __native_keep.callbacks.push(passCb2);
          Interceptor.attach(addr, {
            onEnter: function (args) {
              // args[0]=SSL_CTX*, args[1]=mode(int), args[2]=cb
              args[2] = passCb2;
              log("[OK] [NATIVE_BYPASS] SSL_CTX_set_custom_verify -> force pass callback in " + m);
            }
          });
          installed++;
        }
      });

      // Fallback: if exports not found (hidden), try local symbols by name
      if (installed === 0) {
        Process.enumerateModules().forEach(function (mod) {
          if (!/cronet|ssl|boring|conscrypt/i.test(mod.name)) return;
          try {
            var syms = Module.enumerateSymbolsSync(mod.name);
            syms.forEach(function (s) {
              if (/X509_verify_cert$/.test(s.name)) {
                var cb = new NativeCallback(function () { return 1; }, 'int', ['pointer']);
                __native_keep.callbacks.push(cb);
                Interceptor.replace(s.address, cb);
                log("[OK] [NATIVE_BYPASS] replace local " + s.name + " in " + mod.name);
                installed++;
              } else if (/SSL_get_verify_result$/.test(s.name)) {
                var cb2 = new NativeCallback(function () { return 0; }, 'int', ['pointer']);
                __native_keep.callbacks.push(cb2);
                Interceptor.replace(s.address, cb2);
                log("[OK] [NATIVE_BYPASS] replace local " + s.name + " in " + mod.name);
                installed++;
              } else if (/SSL_set_custom_verify$/.test(s.name)) {
                var passCb = new NativeCallback(function () { return 1; }, 'int', ['pointer', 'pointer']);
                __native_keep.callbacks.push(passCb);
                Interceptor.attach(s.address, {
                  onEnter: function (args) { args[2] = passCb; log("[OK] [NATIVE_BYPASS] local SSL_set_custom_verify in " + mod.name); }
                });
                installed++;
              } else if (/SSL_CTX_set_custom_verify$/.test(s.name)) {
                var passCb3 = new NativeCallback(function () { return 1; }, 'int', ['pointer', 'pointer']);
                __native_keep.callbacks.push(passCb3);
                Interceptor.attach(s.address, {
                  onEnter: function (args) { args[2] = passCb3; log("[OK] [NATIVE_BYPASS] local SSL_CTX_set_custom_verify in " + mod.name); }
                });
                installed++;
              }
            });
          } catch (e) {}
        });
      }

      log("[INFO] native hooks installed count: " + installed);
      if (installed === 0) {
        log("[WARN] No native hooks installed (symbols may be hidden/stripped)");
      }
    } catch (e) {
      log("[WARN] native bypass setup failed: " + e);
    }
  })();

});

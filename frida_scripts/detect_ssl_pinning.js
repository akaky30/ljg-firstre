// Detect SSL Pinning (monitor-only) + ASCII summary + idempotent
setImmediate(function () {
  if (globalThis.__frida_detect_pinning_installed) {
    try { send({__frida_console:true, args:["[detect] already installed"]}); } catch(_) {}
    return;
  }
  globalThis.__frida_detect_pinning_installed = true;

  function log() { try { send({ __frida_console:true, args: Array.prototype.slice.call(arguments) }); } catch(e){} }

  var S = {
    configPinner: false,
    configPinnerPatterns: [],
    runtimePinnerCheck: false,
    hostnameVerifierSet: false,
    hostnameVerifiedHosts: new Set(),
    trustManagersSeen: new Set(),
    handshakeError: false,
    handshakeMsgs: []
  };
  function addTM(n){ try{ if(n) S.trustManagersSeen.add(String(n)); }catch(_){ } }

  Java.perform(function () {
    log("[detect] installing hooks...");

    // (0) SSLContext / TrustManagerFactory
    try {
      var SSLContext = Java.use('javax.net.ssl.SSLContext');
      SSLContext.init.overloads.forEach(function(ov){
        ov.implementation = function(km, tm, sr){
          try {
            var tmInfo = [];
            if (tm && tm.length) for (var i=0;i<tm.length;i++) {
              var t = null;
              try { t = tm[i] ? (tm[i].$className || tm[i].toString()) : "null"; } catch(_) {}
              tmInfo.push(t); addTM(t);
            }
            log("[detect] SSLContext.init trustManagers=", tmInfo.join(","));
          } catch(_) {}
          return ov.apply(this, arguments);
        };
      });

      var TMF = Java.use('javax.net.ssl.TrustManagerFactory');
      if (TMF.getTrustManagers) {
        TMF.getTrustManagers.implementation = function(){
          var tms = this.getTrustManagers();
          try {
            var arr=[]; if (tms && tms.length) for (var i=0;i<tms.length;i++){
              var t = null;
              try { t = tms[i] ? (tms[i].$className || tms[i].toString()) : "null"; } catch(_) {}
              arr.push(t); addTM(t);
            }
            log("[detect] TrustManagerFactory.getTrustManagers ->", arr.join(","));
          } catch(_) {}
          return tms;
        };
      }
    } catch(e){ log("[detect] early hooks fail:", e); }

    // Monitor SSLHandshakeException
    try {
      var HEx = Java.use('javax.net.ssl.SSLHandshakeException');
      HEx.$init.overloads.forEach(function(ov){
        ov.implementation = function(){
          try {
            S.handshakeError = true;
            var msg = null;
            try { msg = arguments.length ? (""+arguments[0]) : ""; } catch(_){}
            if (msg) S.handshakeMsgs.push(msg);
            log("[detect][SSLHandshakeException]", msg || "(no message)");
          } catch(_){}
          return ov.apply(this, arguments);
        };
      });
    } catch(e) { log("[detect] hook SSLHandshakeException fail:", e); }

    // (A) OkHttp config
    try {
      var PinnerBuilder = Java.use('okhttp3.CertificatePinner$Builder');
      if (PinnerBuilder.add) {
        PinnerBuilder.add.overloads.forEach(function(ov){
          ov.implementation = function(pattern, pins){
            try {
              S.configPinner = true;
              var list=[]; if(pins&&pins.length) for(var i=0;i<pins.length;i++) list.push(""+pins[i]);
              S.configPinnerPatterns.push(""+pattern);
              log("[detect][config] Pinner.Builder.add pattern=", ""+pattern, " pins=", list.join(","), " | HINT: Certificate pinning configured.");
            } catch(_) {}
            return ov.apply(this, arguments);
          };
        });
      }
      var OkB = Java.use('okhttp3.OkHttpClient$Builder');
      if (OkB.certificatePinner) {
        OkB.certificatePinner.overloads.forEach(function(ov){
          ov.implementation = function(pinner){
            if (pinner) S.configPinner = true;
            log("[detect][config] OkHttpClient.Builder.certificatePinner ->", pinner ? pinner.$className : "null",
                pinner ? " | HINT: CertificatePinner is set." : "");
            return ov.apply(this, arguments);
          };
        });
      }
      if (OkB.hostnameVerifier) {
        OkB.hostnameVerifier.overloads.forEach(function(ov){
          ov.implementation = function(verifier){
            S.hostnameVerifierSet = true;
            log("[detect][config] OkHttpClient.Builder.hostnameVerifier ->", verifier ? verifier.$className : "null",
                " | HINT: Custom HostnameVerifier.");
            return ov.apply(this, arguments);
          };
        });
      }
    } catch(e){ log("[detect] config hooks fail:", e); }

    // (B) OkHttp runtime
    try {
      var CertPinner = Java.use('okhttp3.CertificatePinner');
      if (CertPinner.check) {
        CertPinner.check.overloads.forEach(function(ov, idx){
          ov.implementation = function(){
            S.runtimePinnerCheck = true;
            log("[detect] CertificatePinner.check#"+idx+" CALLED | HINT: runtime pinning check fired.");
            return ov.apply(this, arguments);
          };
        });
      }
      if (CertPinner['check$okhttp']) {
        CertPinner['check$okhttp'].overloads.forEach(function(ov, idx){
          ov.implementation = function(){
            S.runtimePinnerCheck = true;
            log("[detect] CertificatePinner.check$okhttp#"+idx+" CALLED | HINT: runtime pinning check fired.");
            return ov.apply(this, arguments);
          };
        });
      }
    } catch(e){ log("[detect] hook CertPinner failed:", e); }

    try {
      var OHV = Java.use('okhttp3.internal.tls.OkHostnameVerifier');
      if (OHV.verify) {
        OHV.verify.overloads.forEach(function(ov){
          ov.implementation = function(host, session){
            try { S.hostnameVerifiedHosts.add(String(host)); } catch(_){}
            log("[detect] OkHostnameVerifier.verify host=", ""+host);
            return ov.apply(this, arguments);
          };
        });
      }
    } catch(e){ log("[detect] hook OkHostnameVerifier failed:", e); }

    // (C) TrustManagerImpl
    function hookTM(name) {
      try {
        var Cls = Java.use(name);
        if (Cls && Cls.checkServerTrusted) {
          Cls.checkServerTrusted.overloads.forEach(function(ov){
            ov.implementation = function(chain, authType){
              log("[detect] "+name+".checkServerTrusted authType=", ""+authType, " chain_len=", (chain?chain.length:0));
              return ov.apply(this, arguments);
            };
          });
          log("[detect] hooked:", name);
        }
      } catch(_) {}
    }
    hookTM('com.android.org.conscrypt.TrustManagerImpl');
    hookTM('org.conscrypt.TrustManagerImpl');

    // (D) HttpsURLConnection
    try {
      var HUC = Java.use('javax.net.ssl.HttpsURLConnection');
      if (HUC.setDefaultHostnameVerifier) {
        HUC.setDefaultHostnameVerifier.implementation = function(v){
          S.hostnameVerifierSet = true;
          log("[detect] HUC.setDefaultHostnameVerifier ->", v? v.$className : "null", " | HINT: custom HostnameVerifier.");
          return this.setDefaultHostnameVerifier(v);
        };
      }
      if (HUC.setHostnameVerifier) {
        HUC.setHostnameVerifier.implementation = function(v){
          S.hostnameVerifierSet = true;
          log("[detect] HUC.setHostnameVerifier ->", v? v.$className : "null", " | HINT: custom HostnameVerifier.");
          return this.setHostnameVerifier(v);
        };
      }
    } catch(e){}

    // Summary (once)
    var firedOnce = false;
    function emitSummary(tag){
      if (firedOnce) return; firedOnce = true;
      var hasPin = S.runtimePinnerCheck || S.configPinner;
      var tmList = Array.from(S.trustManagersSeen.values()).join(",") || "(none)";
      var hosts  = Array.from(S.hostnameVerifiedHosts.values()).join(",") || "(none)";

      var en = hasPin ? "SSL pinning detected (CertificatePinner configured and/or runtime check observed)."
                      : "No strong evidence of SSL pinning so far.";
      if (S.handshakeError) {
        en += " SSLHandshakeException observed; likely system trust/time/proxy issue.";
      }

      log("[detect][summary]["+tag+"]", en,
          " TM(seen)=", tmList,
          " HostnameVerifierSet=", S.hostnameVerifierSet,
          " VerifiedHosts=", hosts);
    }
    setTimeout(function(){ emitSummary("timeout"); }, 12000);
    log("[detect] hooks installed (broad, monitor-only)");
  });
});

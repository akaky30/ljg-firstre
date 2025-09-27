Java.perform(function() {
  function log(){ try{ send({__frida_console:true, args:[].map.call(arguments, function(x){return ''+x;})}); }catch(e){} }

  // 1) OkHttp CertificatePinner.check
  try {
    var CertPinner = Java.use('okhttp3.CertificatePinner');
    if (CertPinner.check) {
      CertPinner.check.overloads.forEach(function(ov, idx){
        ov.implementation = function(){ log('[bypass] CertificatePinner.check #'+idx+' -> bypass'); return; };
      });
    }
    if (CertPinner['check$okhttp']) {
      CertPinner['check$okhttp'].overloads.forEach(function(ov, idx){
        ov.implementation = function(){ log('[bypass] CertificatePinner.check$okhttp #'+idx+' -> bypass'); return; };
      });
    }
  } catch(e){ log('[bypass] CertPinner hook failed:', e); }

  // 2) Hostname 验证
  try {
    var OkHostnameVerifier = Java.use('okhttp3.internal.tls.OkHostnameVerifier');
    if (OkHostnameVerifier && OkHostnameVerifier.verify) {
      OkHostnameVerifier.verify.overloads.forEach(function(ov){
        ov.implementation = function(host, session){ log('[bypass] OkHostnameVerifier.verify host='+host+' -> true'); return true; };
      });
    }
  } catch(e){ log('[bypass] OkHostnameVerifier hook failed:', e); }

  // 3) 全局 TrustManager（替换 SSLContext.init）
  try {
    var X509TM = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    var TrustAll = Java.registerClass({
      name: 'org.frida.TrustAllManager',
      implements: [X509TM],
      methods: {
        checkClientTrusted: function(chain, authType) {},
        checkServerTrusted: function(chain, authType) {},
        getAcceptedIssuers: function() { return []; }
      }
    });

    var initOver = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;','[Ljavax.net.ssl.TrustManager;','java.security.SecureRandom');
    initOver.implementation = function(km, tm, sr){
      log('[bypass] SSLContext.init -> replace TrustManager');
      return initOver.call(this, km, [TrustAll.$new()], sr);
    };
  } catch(e){ log('[bypass] SSLContext hook failed:', e); }

  // 4) HttpsURLConnection 兜底
  try {
    var HUC = Java.use('javax.net.ssl.HttpsURLConnection');
    HUC.setDefaultHostnameVerifier.implementation = function(verifier){
      log('[bypass] HttpsURLConnection.setDefaultHostnameVerifier ignored');
      return; // 丢弃外部设置
    };
  } catch(e){}
});

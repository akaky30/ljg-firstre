脚本输出：

```
[14:20:57] [run_template] started pid=14900 template=ssl_pinning_bypass
[14:20:57]      ____
[14:20:57]     / _  |   Frida 17.2.17 - A world-class dynamic instrumentation toolkit
[14:20:57]    | (_| |
[14:20:57]     > _  |   Commands:
[14:20:57]    /_/ |_|       help      -> Displays the help system
[14:20:57]    . . . .       object?   -> Display information about 'object'
[14:20:57]    . . . .       exit/quit -> Exit
[14:20:57]    . . . .
[14:20:57]    . . . .   More info at https://frida.re/docs/home/
[14:20:58]    . . . .
[14:20:58]    . . . .   Connected to RMX1931 (id=127.0.0.1:5555)
[14:20:58] Attaching...
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[WRAP] console wrapper loaded']}} data:[RMX1931::Demo ]->  None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[INFO] [REPIN] Loading custom CA from /data/local/tmp/cert-der.crt']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[INFO] [REPIN] Custom CA subject: O=mitmproxy, CN=mitmproxy']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[OK] [REPIN] TrustManager initialized with custom CA']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['================================================']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['=== SSL PINNING BYPASS SCRIPT INITIALIZED ===']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['================================================']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[STATUS] Script loaded successfully']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[INFO] Monitoring SSL/TLS operations...']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[HOOK_STATUS: SUCCESS] SSLHandshakeException monitoring active']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[HOOK_STATUS: SUCCESS] OkHttp CertificatePinner hooks installed: 3']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[HOOK_STATUS: SUCCESS] OkHttp HostnameVerifier hook installed']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[HOOK_STATUS: SUCCESS] SSLContext TrustManager hooks installed: 1']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[OK] [REPIN] Custom SSLSocketFactory constructed']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[OK] [REPIN] HttpsURLConnection default SSLSocketFactory set to custom CA']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[HOOK_STATUS: SUCCESS] HttpsURLConnection hooks installed']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[HOOK_STATUS: SUCCESS] Apache HttpClient hooks installed: 7']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[HOOK_STATUS: SUCCESS] X509TrustManagerExtensions hook installed']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[HOOK_STATUS: FAILED] TrustKit hook failed (library may not be used)']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[HOOK_STATUS: SUCCESS] WebViewClient SSL error handler hook installed']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[WARN] native replace X509_verify_cert in libssl.so failed: TypeError: not a function']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[WARN] native replace X509_verify_cert in libboringssl.so failed: TypeError: not a function']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[WARN] native replace X509_verify_cert in libcronet.so failed: TypeError: not a function']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[WARN] native replace X509_verify_cert in libsscronet.so failed: TypeError: not a function']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[WARN] native replace X509_verify_cert in libconscrypt_jni.so failed: TypeError: not a function']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[WARN] native replace SSL_get_verify_result in libssl.so failed: TypeError: not a function']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[WARN] native replace SSL_get_verify_result in libboringssl.so failed: TypeError: not a function']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[WARN] native replace SSL_get_verify_result in libcronet.so failed: TypeError: not a function']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[WARN] native replace SSL_get_verify_result in libsscronet.so failed: TypeError: not a function']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[WARN] native replace SSL_get_verify_result in libconscrypt_jni.so failed: TypeError: not a function']}} data: None
[14:20:59] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[WARN] native bypass setup failed: TypeError: not a function']}} data: None
[14:21:02] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[INFO] [INITIAL_STATUS: BYPASS_MISSING]']}} data: None
[14:21:02] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[WARN] No bypass hooks activated yet']}} data: None
[14:21:02] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[ADVICE] Trigger HTTPS requests in the app or wait longer']}} data: None
[14:21:02] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[INFO] [REPIN] Custom CA in use: O=mitmproxy, CN=mitmproxy']}} data: None
[14:21:06] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[OK] [SSL_CONTEXT_REPIN] Replacing TrustManagers with custom CA bundle']}} data: None
[14:21:07] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[OK] [HOSTNAME_VERIFIER_BYPASS] Host: www.bing.com -> VERIFICATION_OVERRIDDEN']}} data: None
[14:21:07] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[OK] [CERTIFICATE_PINNER_BYPASS] Method check$okhttp #0 -> BYPASSED']}} data: None
[14:21:07] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[OK] [HOSTNAME_VERIFIER_BYPASS] Host: www.bing.com -> VERIFICATION_OVERRIDDEN']}} data: None
[14:21:07] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[OK] [CERTIFICATE_PINNER_BYPASS] Method check$okhttp #0 -> BYPASSED']}} data: None
[14:21:07] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['================================================']}} data: None
[14:21:07] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['=== FINAL BYPASS SUMMARY ===']}} data: None
[14:21:07] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['================================================']}} data: None
[14:21:07] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[DURATION] Monitoring time: 8.141 seconds']}} data: None
[14:21:07] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[HOSTS] Observed hosts: www.bing.com']}} data: None
[14:21:07] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[OK] [BYPASS_STATUS: SUCCESS]']}} data: None
[14:21:07] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[OK] Active hooks: SSLContext.init, OkHttp.HostnameVerifier, OkHttp.CertificatePinner']}} data: None
[14:21:07] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[RESULT] SSL pinning bypass appears to be working']}} data: None
[14:21:07] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[WARN] Failed to hook: TrustKit']}} data: None
[14:21:07] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[INFO] [REPIN SUMMARY] Custom CA subject: O=mitmproxy, CN=mitmproxy']}} data: None
[14:21:07] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[OK] [HOSTNAME_VERIFIER_BYPASS] Host: cn.bing.com -> VERIFICATION_OVERRIDDEN']}} data: None
[14:21:07] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[OK] [CERTIFICATE_PINNER_BYPASS] Method check$okhttp #0 -> BYPASSED']}} data: None
[14:21:07] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[OK] [HOSTNAME_VERIFIER_BYPASS] Host: cn.bing.com -> VERIFICATION_OVERRIDDEN']}} data: None
[14:21:07] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[OK] [CERTIFICATE_PINNER_BYPASS] Method check$okhttp #0 -> BYPASSED']}} data: None
```





![](C:\Users\李建国\Desktop\bs2\关键截图\ssl绕过成功关键截图.png)



**Assessment**

- Demo 的网络层只在 Demo/app/src/main/java/com/example/demo/NetworkActivity.java (lines 41-105) 使用 OkHttp 创建带错误指纹的 CertificatePinner 并发起 https://httpbin.org/{get,post} 请求；未绕过时应抛出 SSLPeerUnverifiedException。
- 本次注入输出显示脚本成功加载自定义 CA、挂钩 CertificatePinner.check$okhttp 以及 OkHttp HostnameVerifier，并在后续请求 www.bing.com / cn.bing.com 时强制返回成功，最终给出 [BYPASS_STATUS: SUCCESS]，说明 SSL pinning 已被绕过。

**用于判断的关键输出**

- [INFO] [REPIN] Loading custom CA from /data/local/tmp/cert-der.crt
- [HOOK_STATUS: SUCCESS] OkHttp CertificatePinner hooks installed: 3
- [HOOK_STATUS: SUCCESS] OkHttp HostnameVerifier hook installed
- [OK] [CERTIFICATE_PINNER_BYPASS] Method check$okhttp #0 -> BYPASSED
- [OK] [HOSTNAME_VERIFIER_BYPASS] Host: www.bing.com -> VERIFICATION_OVERRIDDEN（随后对 cn.bing.com 也同样输出）
- [OK] [BYPASS_STATUS: SUCCESS] 与 [RESULT] SSL pinning bypass appears to be working

这些日志表明脚本不仅替换了 OkHttp 的证书校验，还把主机名验证恒定返回 true，使得原本错误的指纹不再阻断握手。截图中 MITM 平台捕获到 GET/POST 明文也印证了绕过成功。

**脚本如何实现绕过**

- 在 frida_scripts/ssl_pinning_bypass.js (lines 41-115) 中加载自定义 DER 证书，构造新的 TrustManager 与 SSLSocketFactory，并设置默认 HttpsURLConnection 工厂，确保客户端信任 mitmproxy 证书。
- frida_scripts/ssl_pinning_bypass.js (lines 162-188) 遍历并覆写 okhttp3.CertificatePinner 的 check/check$okhttp 重载，直接返回而不做校验，从而消除指纹比对。
- frida_scripts/ssl_pinning_bypass.js (lines 191-206) 将 okhttp3.internal.tls.OkHostnameVerifier.verify 始终返回 true，并记录被绕过的主机名，防止主机名校验失败。
- frida_scripts/ssl_pinning_bypass.js (lines 213-275) 钩住 javax.net.ssl.SSLContext.init 及 HttpsURLConnection 相关方法，把自定义 TrustManager 注入所有新建的 TLS 上下文并拦截后续替换操作。
- 其余段落尝试挂钩 Apache HttpClient、WebView、X509TrustManagerExtensions 及原生 libssl/boringssl，即使部分 native hook 因符号不存在失败（TypeError: not a function），也不影响针对 OkHttp 的核心绕过路径。
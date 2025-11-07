它的核心思路是**“多路径兜底”**：优先在 Java 层拦/改常见框架（OkHttp、系统 SSL、WebView、TrustKit、Conscrypt），必要时在 \**Cronet / BoringSSL / Conscrypt JNI\** 等 \**Native\** 层替换验证函数，使证书校验恒通过。同时提供“\**可选重钉（re-pinning）\**”能力，把你自己的代理 CA（mitm/burp 的 DER 证书）注入为受信根，从而既能过 Pinning，又能**正常 MITM 抓包**。

# 总览：运行期保护 & 日志

- **幂等**：用 `globalThis.__frida_bypass_pinning_installed` 防二次注入；各 overload 上也有 `__frida_hooked` 标记。
- **日志**：通过 `send({ __frida_console: true, args: [...] })` 输出 ASCII 友好日志，记录已装钩子、观测到的 Host、失败的 Hook、握手异常等。
- **状态追踪**：`state` 里统计 `hookedModules/failedHooks/hosts/handshakeError` 等，并在 3s/8s/15s 打印初始/最终总结与故障建议。

# 可选“重钉”能力（re-pinning）

目的：不仅关闭 Pinning，还把你自备的 CA 变成 App 的信任根，保证 **MITM 代理能“真信任”**，避免应用仍报证书错误。
 流程：

1. 读取 `CUSTOM_CA_PATH`（DER 格式），用 `CertificateFactory("X.509")` 生成 CA；
2. 创建内存 `KeyStore`，放入 `frida-custom-ca` 条目；
3. 用默认算法 `TrustManagerFactory` 初始化出 **自定义 TrustManagers**；
4. 用 `SSLContext("TLS")` + 上述 TM 构建 **自定义 SSLSocketFactory**；
5. 通过多处 Hook（见下）把系统/框架用到的 TM/SocketFactory **替换为自定义版本**；若加载失败，退化为“**信任所有**”。

> 关键细节：在 `SSLContext.init` 的 Hook 里有 `repinState.buildingSocket` 旗标，避免在**搭建自定义 SSLSocketFactory**时又被自己 Hook 递归干扰。

# Java 层策略（主战场）

1. **握手异常监控**
    Hook `javax.net.ssl.SSLHandshakeException` 的构造，若触发则设 `handshakeError=true` 并日志提示。
2. **OkHttp 证书钉扎**
    Hook `okhttp3.CertificatePinner` 的 `check` / `check$okhttp`：**直接吞掉**（return；不抛异常），标记 `pinnerBypassed=true`。
3. **主机名校验**
   - Hook `okhttp3.internal.tls.OkHostnameVerifier.verify(...)`：**恒返回 true**，并记录 Host。
   - 同时拦截 `HttpsURLConnection.set(Default)HostnameVerifier`：让应用无法设置“更严格”的校验器（直接丢弃传入的 verifier）。
4. **全局 TrustManager 注入**
    Hook `javax.net.ssl.SSLContext.init(km, tm, sr)`：
   - 如果已成功加载自定义 CA：**替换 tm 为自定义 TrustManagers（重钉）**；
   - 否则：注入 `TrustAllManager`（`checkServerTrusted/ClientTrusted` 空实现，`getAcceptedIssuers` 返回空数组）实现**信任所有**。
5. **HttpsURLConnection**
    若重钉成功，调用 `HttpsURLConnection.setDefaultSSLSocketFactory(customFactory)`，让**未显式配置的网络栈也用自定义 CA**。
6. **Apache HttpClient（老库）**
    Hook `org.apache.http.conn.ssl.SSLSocketFactory` 构造器（主要**记录**，不强改）。
7. **系统扩展：返回类型安全**
   - `android.net.http.X509TrustManagerExtensions.checkServerTrusted(...)` 期望返回 **List<X509Certificate>**，脚本用 `Arrays.asList(chain)` 保证类型匹配，避免因返回数组而崩溃。
   - 这也是此脚本“更稳”的关键之一（不少脚本易在此处因返回类型不符而闪退）。
8. **TrustKit**
    若集成 `com.datatheorem.security.TrustKit`：Hook 其 `checkServerTrusted(...)` 并**吞掉**，防 TrustKit 级别的钉扎。
9. **WebView**
    Hook `WebViewClient.onReceivedSslError(...)`：直接 `handler.proceed()`，**忽略 WebView 的 SSL 错误**。
10. **Conscrypt（AOSP/独立包）**
     尝试 Hook `com.android.org.conscrypt.TrustManagerImpl` 或 `org.conscrypt.TrustManagerImpl` 的 `checkServerTrusted/checkTrusted`：
    - **仅在返回类型是 `java.util.List` 的 overload 上下手**（再次避免类型不符崩溃）；
    - 返回 `Arrays.asList(chain)`，表示“验证通过，且把原链条作为已验证链返回”。

# Native 层策略（Cronet / BoringSSL / Conscrypt JNI）

针对很多 App 使用的 **Cronet**（或直接走 BoringSSL/OpenSSL 的 JNI）路径，Java 层 Hook 可能**完全不起作用**。脚本因此对若干常见 .so **导出符号/本地符号**做“兜底替换”：

- 目标模块：`libssl.so`、`libboringssl.so`、`libcronet.so`、`libsscronet.so`、`libconscrypt_jni.so`（并带正则兜底扫描 `cronet|ssl|boring|conscrypt`）。
- 关键函数替换/挂钩：
  - `X509_verify_cert(X509_STORE_CTX*) -> int`：替换为**恒返回 1（验证成功）**。
  - `SSL_get_verify_result(SSL*) -> int`：替换为**恒返回 0（X509_V_OK）**。
  - `SSL_set_custom_verify(SSL*, int, cb)` / `SSL_CTX_set_custom_verify(SSL_CTX*, int, cb)`：强行把回调 `cb` 改成**返回 1 的“放行”回调**。
- 若导出符号不可见（隐藏/裁剪）：遍历模块**本地符号表**，按名称后缀匹配并替换。
- 用 `__native_keep.callbacks` **保存 NativeCallback 引用**，防止被 GC 回收导致崩溃。

# 稳定性/健壮性设计亮点

- **类型匹配**：对 `X509TrustManagerExtensions` / `Conscrypt` 等“**要求返回 List**”的方法，统一用 `Arrays.asList(chain)`，避免常见 “返回数组导致的类型崩溃”。
- **构建期自保**：`repinState.buildingSocket` 防递归 Hook。
- **覆盖面广**：从 OkHttp→系统 SSLContext→URLConnection→TrustKit→WebView→Conscrypt，再到 Native（ssl/cronet/boringssl/conscrypt_jni）。
- **失败回退**：重钉失败则退回到“信任所有”；Native 导出不存在则尝试本地符号扫描。
- **可观测性**：分阶段打印 **ACTIVE_MODULES / OBSERVED_HOSTS / FAILED_HOOKS**，并给出**故障清单**（Cronet/Native、JNI 钉扎、反 Frida、系统信任等）。

# 可能失效的典型场景 & 脚本的对应措施

- **仅走 Cronet/Native 路径** → 提供了上面的 Native 级别替换；若模块名/符号被进一步混淆/隐藏，脚本有枚举兜底，但仍可能失败。
- **App 自带强反调试/反 Frida** → 本脚本未专门对抗，需要配合其他手段。
- **证书链/时间异常、系统不信任代理 CA** → 日志会提示 `SSLHandshakeError`；开启“重钉”并正确放置 DER 证书可缓解。
- **静态链接/符号裁剪严重** → `Module.enumerateSymbolsSync` 也可能找不到目标；这类需定制化定位符号或改走更上游 Hook 点。

# 一句话总结

这份脚本通过**“Java 多框架 Hook + 系统 SSL 重钉/信任所有 + Cronet/BoringSSL Native 兜底”**的组合拳，最大化覆盖 Android App 的 TLS 验证路径，并以**返回类型安全**与**幂等防护**提升稳定性；在可观测性与排障信息上也做了完善的工程化处理，方便你在真机联调 MITM 抓包时快速判断“钉扎是否被有效绕过/重钉是否生效”。
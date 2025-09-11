## 1️⃣ **Probe（探测）**

**作用：**

- Probe 就是扫描或探测目标设备/应用的进程、包名、类名等信息。
- 在你发起 `Probe` 操作时，Frida 会尝试枚举设备上的进程或应用，并返回匹配的目标信息。
- 通常用于：
  - 确认目标应用是否在运行。
  - 获取应用的进程 ID (PID)，便于后续注入。
  - 获取类或模块信息，为后续 Hook 做准备。

**原理：**

- Frida 会通过 `frida-ps` 或 `Java.enumerateLoadedClasses()` 等 API 获取信息。
- 如果没有 Probe，直接注入可能失败，因为你可能不知道正确的包名或 PID。

------

## 2️⃣ **Dump class string fields（导出类字符串字段）**

**作用：**

- 从 Java / Android 应用中的特定类（Class）里导出所有 **字符串类型字段** 的值。
- 常用于：
  - 找敏感数据，如 token、API key、用户名等。
  - 快速分析某个类中存储的核心信息。

**为什么需要类名：**

- Java 应用有成千上万个类和对象，Frida 无法无差别扫描每一个类。
- 需要你指定 `com.example.app.LoginManager` 之类的类名，Frida 才能定位并导出该类的字符串字段。
- 这是 **静态数据导出**，只针对你指定的类。

**原理：**

- Frida 使用 `Java.use("类名")` 获取类对象。
- 遍历其字段 `field`，筛选字符串类型 `String`。
- 返回字段名称和值。

------

## 3️⃣ **Search JWT in static strings（静态字符串中搜索 JWT）**

**作用：**

- 扫描应用内 **所有已加载的静态字符串**，查找类似 JWT 的内容。
- 常用于：
  - 发现硬编码 token 或加密 key。
  - 分析应用授权逻辑或安全漏洞。

**原理：**

- Frida 遍历 `Java.enumerateLoadedClasses()` 或字符串池。
- 对每个字符串使用正则匹配 JWT 特征（通常 `xxxxx.yyyyy.zzzzz`）。
- 输出匹配结果到控制台。

------

## 4️⃣ **SSL Pinning Bypass（SSL 钉扎绕过）**

**作用：**

- 绕过应用对服务器证书的验证（SSL Pinning）。
- 目标：允许你在 MITM（中间人攻击/抓包）环境下抓取 HTTPS 流量。

**为什么需要：**

- 现代应用经常开启 SSL Pinning，阻止你抓包 HTTPS。
- 如果不绕过，Frida / Charles / mitmproxy 无法查看加密流量。

**原理：**

- Frida Hook 相关类或方法：
  - Android: `javax.net.ssl.X509TrustManager`, `HostnameVerifier`, `OkHttpClient` 的验证方法。
  - iOS: `NSURLSession`, `SecTrustEvaluate` 等。
- 强制方法返回 `true` 或跳过证书校验。

------

## 5️⃣ **Dump SharedPreferences（导出 SharedPreferences 数据）**

**作用：**

- 导出 Android 应用存储在本地的 **SharedPreferences** 数据。
- SharedPreferences 是 Android 中存储 key-value 配置的常用方式，常存放：
  - 用户配置
  - Token / Session
  - 小量敏感数据

**原理：**

- Frida Hook `getSharedPreferences()` 或直接遍历 `Context` 的存储文件。
- 读取 `.xml` 中的内容，输出 key-value 对。
- 通常和 Dump class / JWT 配合使用，分析应用的敏感信息存储。

------

### ⚡ 小结

| 功能                             | 作用                   | 原理/注意                                |
| -------------------------------- | ---------------------- | ---------------------------------------- |
| **Probe**                        | 枚举进程/类/包         | 获取 PID/包名/类，为注入做准备           |
| **Dump class string fields**     | 导出指定类的字符串字段 | 需要类名，遍历字段获取字符串             |
| **Search JWT in static strings** | 搜索静态字符串中的 JWT | 遍历加载类/字符串池，正则匹配 JWT        |
| **SSL Pinning Bypass**           | 绕过 HTTPS Pinning     | Hook 证书验证方法，强制返回 true         |
| **Dump SharedPreferences**       | 导出应用本地存储       | Hook `getSharedPreferences()` 或读取 XML |
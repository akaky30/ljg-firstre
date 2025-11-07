脚本输出：

```
[13:09:24] [run_template] started pid=11200 template=search_jwt_in_static_strings
[13:09:24]      ____
[13:09:24]     / _  |   Frida 17.2.17 - A world-class dynamic instrumentation toolkit
[13:09:24]    | (_| |
[13:09:24]     > _  |   Commands:
[13:09:24]    /_/ |_|       help      -> Displays the help system
[13:09:24]    . . . .       object?   -> Display information about 'object'
[13:09:24]    . . . .       exit/quit -> Exit
[13:09:24]    . . . .
[13:09:24]    . . . .   More info at https://frida.re/docs/home/
[13:09:24]    . . . .
[13:09:24]    . . . .   Connected to RMX1931 (id=127.0.0.1:5555)
[13:09:25] Attaching...
[13:09:25] message: [RMX1931::Demo ]-> {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[WRAP] console wrapper loaded']}} data: None
[13:09:25] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[search_jwt] loaded classes:', 11257, 'prefix:', 'com.example.demo', 'limit:', 3000]}} data: None
[13:09:25] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[search_jwt][batch]', '[JWT static] class=com.example.demo.TokenManager field=JWT value=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZW1vVXNlciIsImV4cCI6MTk5OTk5OTk5OX0.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']}} data: None
[13:09:25] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[search_jwt] done. scanned_classes=', 11, 'real_hits=', 1, 'sub_hits=', 0, 'prefix=', 'com.example.demo']}} data: None
```







- 启动后脚本会归一化外部参数，默认只扫描指定包前缀并限制最多 3000 个类（frida_scripts/search_jwt_in_static_strings.js:30-34,129-134），同时为了减少 IPC 开销采用批量缓冲输出（frida_scripts/search_jwt_in_static_strings.js (lines 40-50)）。
- 通过 Java.enumerateLoadedClassesSync() 遍历类，过滤出静态并且类型为 java.lang.String 的字段，利用 setAccessible(true) 可访问私有字段（frida_scripts/search_jwt_in_static_strings.js (lines 143-162)），因此能够读到 TokenManager.JWT。
- 对候选字符串先做长度/字符集的三段式预筛，再尝试 URL_SAFE 和 DEFAULT 两种 Base64 解码头、载荷，确认 header.typ 为 JWT 且存在 alg 才算真实命中（frida_scripts/search_jwt_in_static_strings.js (lines 71-99)），这正好匹配硬编码 token 的头部 {"alg":"HS256","typ":"JWT"}。
- 若开启 include_sub，同一字段中嵌入的子串也会匹配，但本次默认关闭所以 sub_hits=0（frida_scripts/search_jwt_in_static_strings.js (lines 102-178)）。
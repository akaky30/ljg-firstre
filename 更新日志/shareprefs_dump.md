

脚本输出：

```
[15:04:24] [run_template] started pid=7700 template=sharedprefs_dump
[15:04:24]      ____
[15:04:24]     / _  |   Frida 17.2.17 - A world-class dynamic instrumentation toolkit
[15:04:24]    | (_| |
[15:04:24]     > _  |   Commands:
[15:04:24]    /_/ |_|       help      -> Displays the help system
[15:04:24]    . . . .       object?   -> Display information about 'object'
[15:04:24]    . . . .       exit/quit -> Exit
[15:04:24]    . . . .
[15:04:24]    . . . .   More info at https://frida.re/docs/home/
[15:04:24]    . . . .
[15:04:24]    . . . .   Connected to RMX1931 (id=127.0.0.1:5555)
[15:04:25] Failed to spawn: unable to find process with name 'Demo'
[15:04:51] [run_template] started pid=26280 template=sharedprefs_dump
[15:04:51]      ____
[15:04:51]     / _  |   Frida 17.2.17 - A world-class dynamic instrumentation toolkit
[15:04:51]    | (_| |
[15:04:51]     > _  |   Commands:
[15:04:51]    /_/ |_|       help      -> Displays the help system
[15:04:51]    . . . .       object?   -> Display information about 'object'
[15:04:51]    . . . .       exit/quit -> Exit
[15:04:51]    . . . .
[15:04:51]    . . . .   More info at https://frida.re/docs/home/
[15:04:52]    . . . .
[15:04:52]    . . . .   Connected to RMX1931 (id=127.0.0.1:5555)
[15:04:52] Attaching...
[15:04:52] message: [RMX1931::Demo ]-> {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[WRAP] console wrapper loaded']}} data: None
[15:04:52] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[SharedPreferences] hooks installed']}} data: None
[15:05:04] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[SharedPreferences][Editor.putString]', 'username', '=', 'demo_user']}} data: None
[15:05:04] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[SharedPreferences][Editor.putString]', 'token', '=', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZW1vVXNlciIsImV4cCI6MTk5OTk5OTk5OX0.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']}} data: None
[15:05:04] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[SharedPreferences][Editor.putBoolean]', 'isPremium', '=', 'true']}} data: None
[15:05:04] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[SharedPreferences][Editor.apply]']}} data: None
[15:05:11] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[SharedPreferences][getString] file=', '(unknown-file)', ' ', 'username', ' = ', 'demo_user']}} data: None
[15:05:11] message: {'type': 'send', 'payload': {'__frida_console': True, 'args': ['[SharedPreferences][getString] file=', '(unknown-file)', ' ', 'token', ' = ', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZW1vVXNlciIsImV4cCI6MTk5OTk5OTk5OX0.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']}} data: None
```









- Demo 里 PrefsActivity.writePrefs() 把 username=demo_user、token=TokenManager.getJwt()、isPremium=true 写入 SharedPreferences（Demo/app/src/main/java/com/example/demo/PrefsActivity.java (lines 32-37)）。
- sharedprefs_dump.js 钩住 SharedPreferencesImpl$EditorImpl.putString/putBoolean/apply，因此按钮“写入示例数据”后应该打印出对应键值，这正是日志 [SharedPreferences][Editor.putString] username = demo_user、token = ...、[SharedPreferences][Editor.putBoolean] isPremium = true、[SharedPreferences][Editor.apply]。
- “读取并显示”按钮调用 getString 读取 username、token，日志中出现 [SharedPreferences][getString] ... username = demo_user 与 token = ...，与应用界面显示一致，说明脚本正确拦截了读取操作。
- 唯一的小差异是文件路径显示 (unknown-file)，这是因为脚本里 whichFile 通过反射字段 mFile 获取路径；如果反射失败就返回 (unknown-file)，并不影响内容判断。

**关键输出**

1. [SharedPreferences] hooks installed（脚本注入成功）。
2. [SharedPreferences][Editor.putString] username = demo_user
   [SharedPreferences][Editor.putString] token = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   [SharedPreferences][Editor.putBoolean] isPremium = true
   [SharedPreferences][Editor.apply]
3. [SharedPreferences][getString] file= (unknown-file) username = demo_user
   [SharedPreferences][getString] file= (unknown-file) token = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

这些输出与 Demo 写入、读取的键值完全吻合，验证脚本工作正常。

**脚本实现方式**

- 脚本运行在 Java.perform 上下文，先 Java.use 目标类 android.app.SharedPreferencesImpl 和它的 EditorImpl（frida_scripts/sharedprefs_dump.js (lines 3-6)）。
- 函数 whichFile 反射 mFile 字段尝试拿到 SharedPreferences 实际 XML 路径（frida_scripts/sharedprefs_dump.js (lines 8-15)）。
- Hook getAll、getString 方法，在读操作时调用原始实现后用 log 打印键值与文件路径（frida_scripts/sharedprefs_dump.js (lines 17-33)）。
- 对编辑器 putString/putBoolean 等方法，覆写实现，通过 arguments 捕获传入键值，然后调用原方法写回存储（frida_scripts/sharedprefs_dump.js (lines 35-63)）。
- Hook apply/commit/remove/clear 记录对应动作，并在最后输出 [SharedPreferences] hooks installed 作为状态提示。

因此，当 Demo 活动执行写入和读取时，脚本同步捕获到所有键值对并打印，确认 SharedPreferences 内容已被成功截获。
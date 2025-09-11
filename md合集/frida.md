# <center>`frida`详情</center>

## 一、什么是`frida`

`Frida` 是一个动态代码插桩工具，用于在移动设备和桌面系统上进行动态分析和调试。它允许用户在运行时动态地修改和监控程序的行为，而无需重新编译或修改原始代码。以下是 `Frida` 的一些关键特点和用途：

### 关键特点

- **跨平台支持**：`Frida` 支持多种操作系统，包括 `Windows、macOS、Linux、iOS` 和 `Android`。
- **动态分析**：可以在程序运行时动态地插入自定义代码，用于监控函数调用、变量值、内存操作等。
- **脚本化操作**：支持使用 `JavaScript` 编写脚本，方便快速实现复杂的分析逻辑。
- **远程控制**：可以通过 `USB` 或网络连接到目标设备，进行远程调试和分析。
- **社区和生态系统**：拥有活跃的社区和丰富的文档，提供了大量的示例和工具。

### 常见用途

- **逆向工程**：帮助分析应用程序的内部逻辑和行为。
- **安全研究**：用于检测和分析应用程序中的安全漏洞。
- **漏洞挖掘**：通过动态监控程序执行，发现潜在的安全问题。
- **自动化测试**：可以用于自动化测试和模拟用户操作。
- **性能分析**：监控程序的性能指标，如函数调用频率、执行时间等。

## 二、`frida`常见参数及作用

#### **常用参数：**

- **`-U`**: 连接到 USB 设备（Android/iOS 设备）。
- **`-l <script.js>`**: 加载指定的 JavaScript 脚本。
- **`-f <package>`**: 启动目标应用（通过包名或二进制路径）。
- **`-n <process-name>`**: 按进程名附加到已运行的进程。
- **`-p <pid>`**: 按进程 ID 附加到进程。
- **`--no-pause`**: 启动应用后不暂停，直接执行脚本。
- **`-o <file>`**: 将输出重定向到文件。
- **`--runtime <v8|duk>`**: 指定 JavaScript 引擎（默认 `v8`）。

```bash
# 附加到 Android 的 Chrome 进程并注入脚本
frida -U -l hijack.js -n com.android.chrome

# 启动 iOS 的 Telegram 并注入脚本（无需暂停）
frida -U -l script.js -f org.telegram.telegram --no-pause

# 附加到进程 ID 1234，使用 Duktape 引擎
frida -U -p 1234 --runtime=duk

# 启动应用并将输出保存到文件
frida -U -l script.js -f com.example.app -o output.log
```

### **2. `frida-trace` 命令**

快速跟踪函数或方法的调用，自动生成桩代码（Stub）。

#### **常用参数：**

- **`-U`**: 连接到 USB 设备。
- **`-m <method>`**: 跟踪 Objective-C 方法（如 `[ClassName method*]`）。
- **`-i <function>`**: 跟踪导出函数（支持通配符 `*`）。
- **`-I <module>`**: 包含指定模块（默认排除系统库）。
- **`-X <module>`**: 排除指定模块。
- **`-p <pid>`**: 附加到进程 ID。

```bash
# 跟踪 iOS SpringBoard 的所有 openURL 方法
frida-trace -U -n SpringBoard -m "-[SpringBoard openURL:]"

# 跟踪 Android 应用的 libnative.so 中所有以 'encrypt' 开头的函数
frida-trace -U -n com.example.app -i "encrypt*" -I libnative.so

# 跟踪进程 ID 456 的所有 HTTP 相关函数（通配符）
frida-trace -U -p 456 -i "*http*"
```

### **3. `frida-ps` 命令**

列出设备或主机的进程信息。

#### **常用参数：**

- **`-U`**: 显示 USB 设备上的进程。
- **`-a`**: 显示所有进程（包括应用和系统进程）。
- **`-i`**: 显示安装的应用（仅 Android/iOS）。

```bash
# 列出 USB 设备上的所有进程
frida-ps -Ua

# 列出 Android 设备上安装的应用
frida-ps -Ui
```

### **4. `frida-discover` 命令**

自动发现应用的内部函数和模块，生成桩代码。

#### **常用参数：**

- **`-U`**: 连接到 USB 设备。
- **`-f <package>`**: 启动目标应用并注入发现脚本。
- **`-o <file.js>`**: 输出发现的函数到文件。

```bash
# 发现 iOS 应用 com.example.app 的内部函数
frida-discover -U -f com.example.app -o discovered.js
```

### **5. `frida-ls-devices` 命令**

列出所有连接的设备（USB、本地、远程）。

```bash
frida-ls-devices
```

### **6. 通用高级参数**

- **`--debug`**: 启用调试模式（输出更多日志）。
- **`--codeshare <user/script>`**: 直接从 [Frida Codeshare](https://codeshare.frida.re/) 加载脚本。
- **`--exit-on-error`**: 脚本出错时立即退出。

```bash
# 从 Codeshare 运行知名脚本（如 anti-root-detection）
frida -U -f com.example.app --codeshare dzonerzy/anti-root-detection
```

### **完整示例场景**

#### **场景：Hook Android 应用的加密函数**

1. **找到目标函数**：

```bash
frida-discover -U -n com.example.app -o crypto.js
```

2. **编写 Hook 脚本**（`hook_crypto.js`）：

```js
Interceptor.attach(Module.findExportByName("libcrypto.so", "AES_encrypt"), {
  onEnter: function (args) {
    console.log("AES Key:", args[0].readByteArray(32));
  }
});
```

3. **注入脚本**：

```bash
frida -U -l hook_crypto.js -n com.example.app
```


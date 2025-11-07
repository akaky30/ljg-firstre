# 🛡️ Android 流量分析 & 动态 Hook 平台

## 📌 项目简介

本项目基于 **Flask + mitmproxy + Frida**，实现了一套集 **流量分析、敏感信息检测、动态 Hook** 于一体的可视化平台。
 既能贴合 **真实渗透测试场景**，也能用于 **CTF 题目环境演示**。

功能覆盖 **网络流量抓取 → 敏感数据检测 → Frida 动态分析 → 前端实时可视化** 的完整流程。

------

## 🚀 功能亮点

### 🔍 1. HTTP(S) 流量抓取

- 使用 **mitmproxy** 作为代理，自动拦截模拟器/手机所有请求。
- 抓取请求信息：
  - `URL`
  - `Method`
  - `Headers`
  - `Body`
- **前端实时展示**，无需刷新。

------

### 🧩 2. 敏感信息检测

内置正则自动检测以下字段，并在前端高亮显示：

- 手机号
- 邮箱
- 身份证号
- Token / Access Token
- Password

------

### 📊 3. 会话管理

- `GET /api/sessions` → 查看全部会话
- `GET /api/session/<id>` → 查看详情
- `DELETE /api/sessions/clear` → 一键清空
- `GET /api/export` → 导出 CSV（可直接分析）

------

### 🛰️ 4. Frida 动态 Hook

内置常见 **Frida Hook 模板**，可一键运行：

- `okhttp_log_url` → 打印请求 URL
- `requestbody_dump` → Dump 请求体
- `ssl_pinning_bypass` → 绕过 SSL Pinning
- `sharedprefs_dump` → Dump SharedPreferences

运行方式：

1. 前端点击按钮（例如「绕过 SSL Pinning」）。
2. 输入目标 App 包名。
3. 后端自动调用 `frida -U -n <包名> -s <脚本>`。
4. Hook 输出通过 **WebSocket 实时推送**到前端 Console。

------

### ⚡ 5. 前端可视化

- **会话列表**：实时更新、敏感字段标红。
- **会话详情**：请求体、Header 格式化显示。
- **实时 Console**：绿色终端风格，展示 Frida stdout。
- **一键操作**：清除会话、运行 Hook 模板。

------

### 🔐 6. 安全与扩展

- **权限校验**：支持 `ADMIN_TOKEN`，保护敏感 API。
- **日志记录**：所有请求与错误写入 `server_debug.log`。
- **可扩展性强**：模板化 Frida 脚本，可随时增加新 Hook。

------

## 📂 项目结构

```
.
├── app.py              # Flask + SocketIO 后端
├── mitm_to_flask.py    # mitmproxy 插件，推送流量到 Flask
├── sessions.db         # SQLite 数据库（会话存储）
├── frida_out/          # 自动生成/运行的 Frida 脚本
└── server_debug.log    # 后端日志
```

------

## 🛠️ 使用方法

### 1. 启动代理

```
mitmdump -s mitm_to_flask.py --listen-host 0.0.0.0 -p 8080
```

### 2. 启动后端

```
python app.py
```

### 3. 配置手机/模拟器代理

- WiFi 代理 → 指向 PC 的 IP:8080
- 浏览器访问 `http://mitm.it` → 安装证书

### 4. 打开前端

访问 [http://127.0.0.1:5000](http://127.0.0.1:5000?utm_source=chatgpt.com)，即可看到会话。

### 5. 一键 Hook

- 点击「绕过 SSL Pinning」按钮
- 输入目标 App 包名
- Frida stdout 会实时显示在 Console

------

## 🎯 典型演示场景

✅ **渗透测试模拟**：拦截 HTTPS 请求 + 自动绕过 SSL Pinning
 ✅ **CTF 题目复现**：通过 Hook Dump SharedPreferences，找出密钥 / Token
 ✅ **安全审计**：检测是否泄露敏感字段（手机号、密码、Token）
 ✅ **教学展示**：完整的流量分析 → 动态 Hook → 数据解密流程

------

## 📌 后续扩展方向

-  增加 **内存 Dump 模板**（提取内存变量，如 JWT、密码明文）。
-  增加 **流量搜索与过滤功能**（按 URL、关键字过滤）。
-  增加 **自动化分析报告**（PDF 一键导出）。
-  增加 **安卓 APK Demo**，配合演示完整破解流程。

------

✨ **一句话总结**：
 这是一个集 **流量分析 + 敏感检测 + 动态 Hook + 可视化展示** 于一体的安全研究工具，兼顾 **实战渗透** 与 **CTF 教学**。
# DemoApp

一个 Android APK Demo，用于配合演示完整破解流程。

## 功能
- 登录页面，输入账号密码
- 请求 Flask Mock Server
- 返回 token 和用户信息（模拟敏感数据）

## 使用方法
1. 启动 Flask mock server: `python server.py`
2. 使用 Android Studio 打开 app 目录，运行 DemoApp（或导入为 Gradle 项目）
3. 配置模拟器走 mitmproxy，抓取请求
4. 查看 Flask API 接收到的敏感数据

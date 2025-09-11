@echo off
cd /d %~dp0
echo [*] Cleaning project...
gradlew.bat clean

echo [*] Building debug APK...
gradlew.bat assembleDebug

echo [*] Done! APK should be here:
echo %cd%\app\build\outputs\apk\debug\app-debug.apk
pause

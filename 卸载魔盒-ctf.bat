@echo off
chcp 936 >nul
cd /d "%~dp0"
title 魔盒-CTF v4.1.0 卸载
echo ============================================================
echo            魔盒-CTF v4.1.0 卸载
echo  将删除本目录全部内容：%~dp0
echo  （_internal / tools / models / runtime / scripts / samples
echo   workspace / reports / exports 以及本卸载脚本本身）
echo  注意：models、runtime 为内置 AI 运行的模型与推理运行时。
echo  请先关闭 Ghidra、x64dbg、dnSpy、MobaXterm 等外部工具。
echo ============================================================
set /p CONFIRM=确认卸载？输入 Y 继续，其他键取消：
if /i not "%CONFIRM%"=="Y" (
  echo 已取消，未删除任何内容。
  pause
  exit /b 0
)
echo.
echo [1/2] 正在关闭 魔盒-CTF、AI 推理与转码进程 ...
taskkill /F /IM 魔盒-CTFv4.1.0.exe /T >nul 2>&1
taskkill /F /IM 魔盒-CTF.exe /T >nul 2>&1
taskkill /F /IM CTFToolbox.exe /T >nul 2>&1
taskkill /F /IM llama-server.exe /T >nul 2>&1
taskkill /F /IM ffplay.exe /T >nul 2>&1
taskkill /F /IM ffmpeg.exe /T >nul 2>&1
taskkill /F /IM ffprobe.exe /T >nul 2>&1
echo [2/2] 正在删除当前目录（窗口会自动关闭）...
set "TARGET=%~dp0"
if "%TARGET:~-1%"=="\" set "TARGET=%TARGET:~0,-1%"
powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 2; Remove-Item -LiteralPath '%TARGET%' -Recurse -Force -ErrorAction SilentlyContinue"
exit /b 0

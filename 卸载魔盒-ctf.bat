@echo off
chcp 936 >/dev/null
cd /d "%~dp0"
title 魔盒-ctf v3.7.0 卸载
echo ============================================================
echo            魔盒-ctf v3.7.0 卸载
echo  将删除本目录全部内容：%~dp0
echo  程序 / _internal / tools / models / runtime / scripts / samples
echo  workspace / reports / exports 以及本卸载脚本自身
echo  其中 models、runtime 为本地 AI 裁判的模型与推理运行时。
echo  请先关闭 Ghidra、x64dbg、dnSpy、MobaXterm 等外部工具。
echo ============================================================
set /p CONFIRM=确认卸载请输入 Y，其他键取消：
if /i not "%CONFIRM%"=="Y" (
  echo 已取消，未删除任何内容。
  pause
  exit /b 0
)
echo.
echo [1/2] 正在关闭 魔盒-ctf、AI 推理与转码进程 ...
taskkill /F /IM 魔盒-ctf.exe /T >/dev/null 2>&1
taskkill /F /IM CTFToolbox.exe /T >/dev/null 2>&1
taskkill /F /IM llama-server.exe /T >/dev/null 2>&1
taskkill /F /IM ffplay.exe /T >/dev/null 2>&1
taskkill /F /IM ffmpeg.exe /T >/dev/null 2>&1
taskkill /F /IM ffprobe.exe /T >/dev/null 2>&1
echo [2/2] 正在删除当前目录（窗口消失即完成）...
set "TARGET=%~dp0"
if "%TARGET:~-1%"=="" set "TARGET=%TARGET:~0,-1%"
start "" powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 2; Remove-Item -LiteralPath '%TARGET%' -Recurse -Force -ErrorAction SilentlyContinue"
exit /b 0

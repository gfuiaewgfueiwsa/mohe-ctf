@echo off
chcp 936 >nul
setlocal
cd /d "%~dp0"
title 魔盒-CTF 打包

rem 优先使用本机固定 Python，否则回退 PATH 中的 python
if exist "D:/PY/python.exe" (set "PY=D:/PY/python.exe") else (set "PY=python")
"%PY%" -c "import PyInstaller, ctfbox" >nul 2>&1
if errorlevel 1 (
  echo [x] 缺少 PyInstaller 或 ctfbox，请先安装依赖。
  pause
  exit /b 1
)

rem 版本号取自 ctfbox.__version__，避免脚本里再手写一份
"%PY%" -c "import ctfbox;open('.build_version','w',encoding='utf-8').write(ctfbox.__version__)"
set /p VER=<.build_version
del /F /Q .build_version >nul 2>&1
if "%VER%"=="" (
  echo [x] 读取版本号失败。
  pause
  exit /b 1
)
echo ====== 魔盒-CTF v%VER% build start ======

rem 结束可能占用 dist 的旧进程
taskkill /F /IM CTFToolbox.exe >nul 2>&1
taskkill /F /IM 魔盒-CTF.exe >nul 2>&1
taskkill /F /IM 魔盒-CTFv%VER%.exe >nul 2>&1
if exist dist rmdir /S /Q dist 2>nul

"%PY%" -m PyInstaller --noconfirm --clean CTFToolbox.spec
if errorlevel 1 goto fail

set "D=dist\CTFToolbox"
if not exist "%D%\CTFToolbox.exe" goto fail

rem PyInstaller 6.x 把资源放进 _internal，移到 exe 同级
if exist "%D%\_internal\tools"   move /Y "%D%\_internal\tools"   "%D%\tools"   >nul
if exist "%D%\_internal\samples" move /Y "%D%\_internal\samples" "%D%\samples" >nul
if exist "%D%\_internal\scripts" move /Y "%D%\_internal\scripts" "%D%\scripts" >nul

rem 便携工具链约 3.4GB；robocopy 退出码 0-7 为成功，>=8 失败
robocopy tools "%D%\tools" /E /NFL /NDL /NJH /NJS /NP >nul
if errorlevel 8 goto fail

copy /Y "使用说明.md" "%D%\使用说明.md" >nul
copy /Y "卸载魔盒-CTF.bat" "%D%\卸载魔盒-CTF.bat" >nul

rem 成品命名：魔盒-CTFv<版本>.exe，并建立兼容硬链接 魔盒-CTF.exe
set "EXE=%D%\魔盒-CTFv%VER%.exe"
if exist "%EXE%" del /F /Q "%EXE%"
move /Y "%D%\CTFToolbox.exe" "%EXE%" >nul
if errorlevel 1 goto fail
if exist "%D%\魔盒-CTF.exe" del /F /Q "%D%\魔盒-CTF.exe"
mklink /H "%D%\魔盒-CTF.exe" "%EXE%" >nul
if errorlevel 1 goto fail

if not exist "%D%\workspace" mkdir "%D%\workspace"
if not exist "%D%\reports"   mkdir "%D%\reports"
if not exist "%D%\exports"   mkdir "%D%\exports"

echo ====== build OK: %EXE% ======
echo ====== 部署：robocopy "%D%" "..\魔盒-CTF" /MIR ======
pause
exit /b 0

:fail
echo ====== build FAILED, see log above ======
pause
exit /b 1

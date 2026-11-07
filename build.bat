@echo off
cd /d %~dp0
echo ====== 魔盒-ctf build start ======
REM 关闭正在运行的旧实例，避免 --clean 删除 dist 时 crash.log 等文件被占用(WinError 5/32)
taskkill /F /IM CTFToolbox.exe >nul 2>&1
D:\PY\python.exe -m PyInstaller --noconfirm --clean CTFToolbox.spec
if errorlevel 1 goto fail

REM PyInstaller 6.x puts data files under _internal; move them next to the exe
set D=dist\CTFToolbox
if exist "%D%\_internal\tools"   move /Y "%D%\_internal\tools"   "%D%\tools"   >nul
if exist "%D%\_internal\samples" move /Y "%D%\_internal\samples" "%D%\samples" >nul
if exist "%D%\_internal\scripts" move /Y "%D%\_internal\scripts" "%D%\scripts" >nul

REM 镜像便携工具与运行时（约3GB，robocopy 增量；退出码 0-7 均为成功，>=8 才失败）
robocopy tools "%D%\tools" /E /NFL /NDL /NJH /NJS /NP >nul
if errorlevel 8 goto fail

copy /Y 使用说明.md "%D%\使用说明.md" >nul
copy /Y 卸载魔盒-ctf.bat "%D%\卸载魔盒-ctf.bat" >nul
if not exist "%D%\workspace" mkdir "%D%\workspace"
if not exist "%D%\reports"   mkdir "%D%\reports"
if not exist "%D%\exports"   mkdir "%D%\exports"

echo ====== build OK: %D%\CTFToolbox.exe ======
pause
exit /b 0
:fail
echo ====== build FAILED, see log above ======
pause
exit /b 1
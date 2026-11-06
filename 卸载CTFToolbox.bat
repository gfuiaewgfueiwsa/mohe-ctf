@echo off
cd /d "%~dp0"
title 魔盒-ctf Uninstall
echo ============================================================
echo            魔盒-ctf  Զжس
echo  ɾļڵݣжس
echo    %~dp0
echo   魔盒-ctf.exe_internaltoolsworkspacereportsexportssamples
echo  ȹر Ghidra / x64dbg / dnSpy / MobaXterm Ѵ򿪵Ĺߡ
echo ============================================================
set /p CONFIRM=ȷϳж Y سȡ
if /i not "%CONFIRM%"=="Y" (
  echo ȡδɾκݡ
  pause
  exit /b 0
)
echo.
echo [1/2] ڹر 魔盒-ctf /ת ...
taskkill /F /IM 魔盒-ctf.exe /T >nul 2>&1
taskkill /F /IM ffplay.exe /T >nul 2>&1
taskkill /F /IM ffmpeg.exe /T >nul 2>&1
taskkill /F /IM ffprobe.exe /T >nul 2>&1
echo [2/2] ѰžĬɾڼرգκβ
set "TARGET=%~dp0"
if "%TARGET:~-1%"=="\" set "TARGET=%TARGET:~0,-1%"
set "VBS=%TEMP%\ctfuninst_%RANDOM%.vbs"
> "%VBS%" echo Set sh = CreateObject("WScript.Shell")
>> "%VBS%" echo Set fso = CreateObject("Scripting.FileSystemObject")
>> "%VBS%" echo WScript.Sleep 800
>> "%VBS%" echo For i = 1 To 30
>> "%VBS%" echo   sh.Run "cmd /c cd /d %SystemRoot% && rd /s /q ""%TARGET%""", 0, True
>> "%VBS%" echo   If Not fso.FolderExists("%TARGET%") Then Exit For
>> "%VBS%" echo   WScript.Sleep 700
>> "%VBS%" echo Next
>> "%VBS%" echo On Error Resume Next
>> "%VBS%" echo fso.DeleteFile WScript.ScriptFullName, True
rem  TEMP ΪĿ¼ wscriptռôɾĿ¼¸Ŀ¼޷ɾ
start "" /d "%TEMP%" wscript.exe "%VBS%"
exit /b 0

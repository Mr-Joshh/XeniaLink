@echo off
rem Builds XeniaLink.xex as a DashLaunch system plugin. Usage: build.bat [Release|Debug]
set CONFIG=%1
if "%CONFIG%"=="" set CONFIG=Release
set OUT=%~dp0%CONFIG%
set IMAGEXEX="C:\Program Files (x86)\Microsoft Xbox 360 SDK\bin\win32\imagexex.exe"
call "C:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\vcvarsall.bat" x86 >nul

rem 0. BearSSL static library (HTTPS client). Incremental, so it's only compiled once.
"%WINDIR%\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe" "%~dp0bearssl.vcxproj" /nologo /v:minimal /t:Build /p:Configuration=%CONFIG% /p:Platform="Xbox 360"
if errorlevel 1 exit /b 1

rem 1. Compile + link the DLL (MSBuild also makes a throwaway title XEX).
"%WINDIR%\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe" "%~dp0XeniaLink.vcxproj" /nologo /v:minimal /t:Rebuild /p:Configuration=%CONFIG% /p:Platform="Xbox 360"
if errorlevel 1 exit /b 1

rem 2. Mark the DLL 4 KB-aligned so imagexex can place it in system memory.
python "%~dp0..\tools\pe_4k_align.py" "%OUT%\XeniaLink.dll"
if errorlevel 1 exit /b 1

rem 3. Build the system-DLL XEX (sysdll, 0x91E00000, 4 KB pages; see xex.xml).
%IMAGEXEX% /NOLOGO /IN:"%OUT%\XeniaLink.dll" /OUT:"%OUT%\XeniaLink.xex" /CONFIG:"%~dp0xex.xml"
if errorlevel 1 exit /b 1

rem Leave it encrypted with the dev-kit key, exactly as imagexex writes it: working
rem plugins (Proto, JRPC2) ship that way, and editing the file breaks its header hash.

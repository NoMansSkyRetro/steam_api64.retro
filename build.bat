@echo off
setlocal
if defined VCINSTALLDIR goto build
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%SystemDrive%\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" echo Visual Studio not found & exit /b 1
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -all -sort -products * -property installationPath`) do (
    if not defined VCVARS if exist "%%i\VC\Auxiliary\Build\vcvarsall.bat" set "VCVARS=%%i\VC\Auxiliary\Build\vcvars64.bat"
)
if not defined VCVARS echo Visual Studio with the C++ toolset not found & exit /b 1
call "%VCVARS%" >nul || exit /b 1

:build
cd /d "%~dp0"
if not exist build mkdir build
cl /nologo /O2 /W3 /EHsc /MT /std:c++17 /D_CRT_SECURE_NO_WARNINGS /LD src\steam_api64.cpp src\steamstub.cpp /Fo:build\ /Fe:build\steam_api64.dll /link user32.lib bcrypt.lib /NOLOGO || exit /b 1
del build\steam_api64.exp build\steam_api64.lib build\*.obj 2>nul
echo built build\steam_api64.dll

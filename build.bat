@echo off
setlocal enabledelayedexpansion

rem  Winverse Compiler Build Script
rem  Long-path aware, no hardcoded drive letters
rem  VS 2026 (version 18) required
rem
rem  Usage:
rem    build.bat           Debug build    -> build\Debug\winversec.exe
rem    build.bat Release   Release build  -> build\Release\winversec.exe
rem    build.bat Clean     Remove all build artifacts
rem
rem  Each configuration owns its own output dir for .obj/.ifc/.log, so Debug
rem  and Release coexist and switching configurations can never link objects
rem  built against a different CRT (/MDd vs /MD).

set "BUILD_TYPE=Debug"
if /I "%~1"=="Release" set "BUILD_TYPE=Release"
if /I "%~1"=="Clean" goto :clean

rem  Locate vcvarsall.bat by scanning all drives
set "VCVARS="
for %%s in (C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    for %%v in (Community Professional Enterprise) do (
        set "VP=%%s:\Program Files\Microsoft Visual Studio\18\%%v\VC\Auxiliary\Build\vcvarsall.bat"
        if exist "!VP!" set "VCVARS=!VP!"& goto :found_vc
        set "VP=%%s:\Program Files (x86)\Microsoft Visual Studio\18\%%v\VC\Auxiliary\Build\vcvarsall.bat"
        if exist "!VP!" set "VCVARS=!VP!"& goto :found_vc
    )
)
echo ERROR: Visual Studio 2026 not found on any drive.
exit /b 1

:found_vc
call "%VCVARS%" x64 >nul 2>&1
if errorlevel 1 (
    echo ERROR: vcvarsall.bat failed.
    exit /b 1
)

cd /d "%~dp0"

set "OUTDIR=build\%BUILD_TYPE%"
if not exist "%OUTDIR%" mkdir "%OUTDIR%"

echo Winverse Compiler Build [%BUILD_TYPE%]

rem  Per-configuration optimization/CRT flags, then the shared command line.
rem  Release adds /GL here to pair with /LTCG at link; Debug keeps /Zi + /DEBUG
rem  so the exe is steppable. /RTC1 is deliberately absent from Debug: runtime
rem  error checks are incompatible with the /EHa async EH model this project uses.
if "%BUILD_TYPE%"=="Release" (
    set "CFG=/MD /O2 /DNDEBUG /GL"
    set "LKF=/nologo /LTCG /OPT:REF /OPT:ICF /RELEASE"
) else (
    set "CFG=/MDd /Od /Zi /D_DEBUG"
    set "LKF=/nologo /DEBUG /INCREMENTAL:NO"
)
set "CLF=/nologo /std:c++latest /EHa %CFG% /bigobj /utf-8 /c /interface /ifcSearchDir %OUTDIR% /ifcOutput %OUTDIR% /Fo%OUTDIR%/"

set "PARTITIONS=types.ixx attributes.ixx sal.ixx preprocessor.ixx parser.ixx resolver.ixx enrich.ixx emit.ixx validate.ixx driver.ixx"
set "AGGREGATOR=winversec.ixx"

echo Compiling partitions...
for %%f in (%PARTITIONS%) do (
    echo   %%f
    cl %CLF% "%%f" > "%OUTDIR%\%%~nf.log" 2>&1
    if errorlevel 1 (
        echo FAIL: %%f
        type "%OUTDIR%\%%~nf.log"
        exit /b 1
    )
    echo   OK
)

echo Compiling aggregator...
cl %CLF% %AGGREGATOR% > "%OUTDIR%\winversec.log" 2>&1
if errorlevel 1 (
    echo FAIL: %AGGREGATOR%
    type "%OUTDIR%\winversec.log"
    exit /b 1
)
echo   OK

echo Compiling main.cpp...
cl /nologo /std:c++latest /EHa %CFG% /bigobj /utf-8 /c /ifcSearchDir %OUTDIR% /Fo%OUTDIR%/main.obj main.cpp > "%OUTDIR%\main.log" 2>&1
if errorlevel 1 (
    echo FAIL: main.cpp
    type "%OUTDIR%\main.log"
    exit /b 1
)
echo   OK

echo Linking...
link %LKF% /OUT:"%OUTDIR%\winversec.exe" /SUBSYSTEM:CONSOLE ^
    /MANIFEST:EMBED /MANIFESTINPUT:winversec.manifest ^
    "%OUTDIR%\types.obj" "%OUTDIR%\attributes.obj" "%OUTDIR%\sal.obj" ^
    "%OUTDIR%\preprocessor.obj" "%OUTDIR%\parser.obj" "%OUTDIR%\resolver.obj" ^
    "%OUTDIR%\enrich.obj" "%OUTDIR%\emit.obj" "%OUTDIR%\validate.obj" ^
    "%OUTDIR%\driver.obj" "%OUTDIR%\winversec.obj" "%OUTDIR%\main.obj" ^
    > "%OUTDIR%\link.log" 2>&1
if errorlevel 1 (
    echo FAIL: link
    type "%OUTDIR%\link.log"
    exit /b 1
)

echo.
echo BUILD SUCCEEDED [%BUILD_TYPE%]: %OUTDIR%\winversec.exe
goto :end

:clean
echo Cleaning build artifacts...
if exist "build" rmdir /s /q "build"
echo Done.
goto :end

:end
endlocal

@echo off
setlocal enabledelayedexpansion

rem  Winverse Compiler Build Script
rem  Long-path aware, no hardcoded drive letters
rem  VS 2026 (version 18) required

set "BUILD_TYPE=Debug"
if "%~1"=="Release" set "BUILD_TYPE=Release"
if "%~1"=="Clean" goto :clean

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

if not exist "build" mkdir "build"

echo Winverse Compiler Build [%BUILD_TYPE%]

rem  Compiler flags
set "CLF=/nologo /std:c++latest /EHa /MD /O2 /bigobj /utf-8 /c /interface /ifcSearchDir build /ifcOutput build /Fobuild/"

set "PARTITIONS=types.ixx attributes.ixx sal.ixx preprocessor.ixx parser.ixx resolver.ixx enrich.ixx emit.ixx validate.ixx driver.ixx"
set "AGGREGATOR=winversec.ixx"

echo Compiling partitions...
for %%f in (%PARTITIONS%) do (
    echo   %%f
    cl %CLF% "%%f" > "build\%%~nf.log" 2>&1
    if errorlevel 1 (
        echo FAIL: %%f
        type "build\%%~nf.log"
        exit /b 1
    )
    echo   OK
)

echo Compiling aggregator...
cl %CLF% %AGGREGATOR% > "build\winversec.log" 2>&1
if errorlevel 1 (
    echo FAIL: %AGGREGATOR%
    type "build\winversec.log"
    exit /b 1
)
echo   OK

echo Compiling main.cpp...
cl /nologo /std:c++latest /EHa /MD /O2 /bigobj /utf-8 /c /ifcSearchDir build /Fobuild\main.obj main.cpp > build\main.log 2>&1
if errorlevel 1 (
    echo FAIL: main.cpp
    type build\main.log
    exit /b 1
)
echo   OK

echo Linking...
link /nologo /LTCG /OUT:"build\winversec.exe" /SUBSYSTEM:CONSOLE ^
    /MANIFEST:EMBED /MANIFESTINPUT:winversec.manifest ^
    "build\types.obj" "build\attributes.obj" "build\sal.obj" ^
    "build\preprocessor.obj" "build\parser.obj" "build\resolver.obj" ^
    "build\enrich.obj" "build\emit.obj" "build\validate.obj" ^
    "build\driver.obj" "build\winversec.obj" "build\main.obj" ^
    > build\link.log 2>&1
if errorlevel 1 (
    echo FAIL: link
    type build\link.log
    exit /b 1
)

echo.
echo BUILD SUCCEEDED: build\winversec.exe
goto :end

:clean
echo Cleaning build artifacts...
if exist "build" rmdir /s /q "build"
echo Done.
goto :end

:end
endlocal

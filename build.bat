@echo off
REM Build inside "x64 Native Tools Command Prompt for VS".
setlocal
REM Remove previous object files from current directory
del /Q *.obj 2>nul
set CFLAGS=/nologo /O2 /std:c++17 /EHsc /D_CRT_SECURE_NO_WARNINGS
set MHINC=/I third_party\minhook\include
set MHSRC=third_party\minhook\src\buffer.c third_party\minhook\src\hook.c third_party\minhook\src\trampoline.c third_party\minhook\src\hde\hde64.c

ml64 /nologo /c /FoWorldKeyStub.obj src\dll\WorldKeyStub.asm
if errorlevel 1 goto err

cl %CFLAGS% /LD %MHINC% src\dll\*.cpp WorldKeyStub.obj %MHSRC% /Fe:UnrealOpenAzeroth.dll /link ws2_32.lib
if errorlevel 1 goto err

cl %CFLAGS% src\patcher\Patcher.cpp /Fe:patcher.exe
if errorlevel 1 goto err

echo.
echo === OK: UnrealOpenAzeroth.dll + patcher.exe ===
goto :eof

:err
echo.
echo === BUILD FAILED (are you in the x64 Native Tools prompt?) ===
endlocal
@echo off
setlocal enabledelayedexpansion

:lable
cls
set "OUT=main.bc"
set "OUT_LL=main.ll"
set "CLANG=clang"
set "LLVM_LINK=llvm-link"
set "LLVM_DIS=llvm-dis"

set "SRCS="
for /r %%f in (*.cpp *.c) do (
    set "SRCS=!SRCS! "%%f""
)

if "!SRCS!"=="" (
    echo 未找到 .c / .cpp 文件
    pause & goto lable
)

set "BCS="
for %%f in (%SRCS%) do (
    set "BC=%%~pf%%~nf.bc"
    set "BCS=!BCS! "%%~pf%%~nf.bc""
    start /b /wait %CLANG% -O3 -mavx2 -emit-llvm -fno-rtti -c "%%f" -o "%%~pf%%~nf.bc"
)

%LLVM_LINK% %BCS% -o %OUT%
if errorlevel 1 (
    echo llvm-link 失败
    pause & goto lable
)

%LLVM_DIS% %OUT% -o %OUT_LL%
echo 编译完成%OUT%
pause
goto lable
@echo off
REM Sentinel-X Build Script for Windows

echo ========================================
echo Building Sentinel-X WAF
echo ========================================

REM Set variables
set BINARY_NAME=sentinel-x.exe
set WASM_NAME=solver.wasm
set VERSION=1.0.0

REM Build the main server
echo.
echo [1/3] Building server binary...
go build -ldflags="-w -s -X main.Version=%VERSION%" -o %BINARY_NAME% ./cmd/server
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to build server
    exit /b 1
)
echo      Success: %BINARY_NAME%

REM Build the WASM module
echo.
echo [2/3] Building WASM module...
set GOOS=js
set GOARCH=wasm
go build -o static/%WASM_NAME% ./pkg/wasm
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to build WASM
    exit /b 1
)
echo      Success: static/%WASM_NAME%

REM Copy WASM exec helper
echo.
echo [3/3] Copying WASM helper...
for /f "tokens=*" %%i in ('go env GOROOT') do set GOROOT=%%i
copy "%GOROOT%\misc\wasm\wasm_exec.js" static\wasm_exec.js >nul
if %ERRORLEVEL% NEQ 0 (
    echo WARNING: Could not copy wasm_exec.js
)
echo      Success: static/wasm_exec.js

REM Reset environment
set GOOS=
set GOARCH=

echo.
echo ========================================
echo Build Complete!
echo ========================================
echo.
echo To run: %BINARY_NAME%
echo.

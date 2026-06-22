@echo off
REM ===========================================================
REM  NetJump -- self-elevate, then launch the unified HUD.
REM ===========================================================

net session >nul 2>&1
if %errorlevel% NEQ 0 (
    powershell -WindowStyle Hidden -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

start "" powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0NetJump-Dashboard.ps1"
exit /b

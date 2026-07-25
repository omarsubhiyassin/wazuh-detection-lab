@echo off
REM Double-click me to open the Detection Lab SOC dashboard.
REM Starts Docker + the stack if needed, then opens the dashboard in its own window.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Detection-Lab.ps1"

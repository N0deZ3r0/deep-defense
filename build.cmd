@echo off
REM Convenience wrapper so the project builds from a plain double-click or cmd.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1" %*

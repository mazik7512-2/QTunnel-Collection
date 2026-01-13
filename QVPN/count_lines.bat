@echo off
FOR /F %%i in ('powershell.exe -executionpolicy remotesigned -File count_lines.ps1') DO SET lines=%%i
echo Lines count = %lines%

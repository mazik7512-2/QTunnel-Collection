@ECHO off
ECHO Building for linux...
ECHO Clearing "build" directory...
SET build_dir=build
DEL "%build_dir%\*" /F /Q /A
FOR /F "eol=| delims=" %%I in ('dir "%build_dir%\*" /AD /B 2^>nul') do RMDIR /Q /S "%build_dir%\%%I"
"cmake" -Bbuild -DCMAKE_SYSTEM_NAME=Linux
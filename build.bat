@echo off
echo ========================
echo Building Hello...
echo ========================

REM Clean previous build
rmdir /s /q build
rmdir /s /q dist
del /q Hello.spec

REM Run PyInstaller
pyinstaller hello.py ^
    --name Hello ^
    --noconfirm ^
    --windowed ^
    --clean ^
    --onedir ^
    --icon=assets\icon.ico ^
    --add-data "assets;assets" ^
    

echo ========================
echo Build Complete!
echo ========================
pause

@echo off
echo ========================
echo Building Hello...
echo ========================

REM Clean previous build
rmdir /s /q build
rmdir /s /q dist
del /q hello.spec

REM Run PyInstaller
pyinstaller hello_v1.2.1.py ^
    --name hello ^
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

@echo off
REM Temporarily bypass execution policy for the process
powershell -Command "Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force"

REM Activate the virtual environment
call venv\Scripts\activate

REM Add the current directory to PYTHONPATH
set PYTHONPATH=%PYTHONPATH%;%CD%

REM Run the Python script
python node\main.py --port 65435 --appdata appdata_side_b --window-title-suffix "Side B"
@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" goto install
where py >nul 2>nul
if errorlevel 1 goto pythonfallback
py -3 -m venv .venv
goto install
:pythonfallback
python -m venv .venv
:install
if not exist ".venv\Scripts\python.exe" goto fail
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto fail
".venv\Scripts\python.exe" run_gemini.py
exit /b %errorlevel%
:fail
echo Setup failed. See README.md and the error above.
pause
exit /b 1

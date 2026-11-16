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
".venv\Scripts\python.exe" -m pip install -r requirements.txt -r requirements-ai.txt
if errorlevel 1 goto fail
".venv\Scripts\python.exe" setup_local_ai.py
if errorlevel 1 goto fail
echo Free local AI is ready. Run start.bat to open the dashboard.
pause
exit /b 0
:fail
echo Local AI setup failed. See LOCAL_AI.md and the error above.
pause
exit /b 1

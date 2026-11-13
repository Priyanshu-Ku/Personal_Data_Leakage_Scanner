@echo off
cd /d "%~dp0"
echo Installing dashboard dependency if required...
py -m pip install -r requirements.txt
if errorlevel 1 goto error
echo Starting Personal Data Leakage Scanner dashboard...
py -m streamlit run app.py
if errorlevel 1 goto error
goto end
:error
echo.
echo Dashboard could not start. Check the error shown above.
:end
pause

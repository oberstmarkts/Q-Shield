@echo off
python -m venv .venv
call .venv\Scripts\activate
pip install -r requirements.txt
python -m app.main --mode offline
python run_web.py

@echo off
python -m app.main --mode offline
pytest -q

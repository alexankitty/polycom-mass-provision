python -m venv .\venv
.\venv\Scripts\activate.bat
pip install -r requirements.txt
python main.py %*
deactivate
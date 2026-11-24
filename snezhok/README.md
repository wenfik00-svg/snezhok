# Снежок ❄ — новогодняя соцсеть
Запуск: pip install -r requirements.txt && python app.py  → http://127.0.0.1:5000
В интернет: gunicorn app:app (Procfile уже есть). Переменные: SECRET_KEY, DB_PATH, BEHIND_PROXY=1, HTTPS=1

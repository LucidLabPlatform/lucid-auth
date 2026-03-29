FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY auth_client.py api.py manage.py ./
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "4000"]

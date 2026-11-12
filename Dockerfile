FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py ./
COPY icons ./icons
RUN mkdir -p /data
# single worker: sessions and live subscribers are kept in memory; every open chat tab holds one thread (SSE)
CMD ["gunicorn", "-w", "1", "-k", "gthread", "--threads", "128", "-t", "0", "-b", "0.0.0.0:8000", "app:app"]

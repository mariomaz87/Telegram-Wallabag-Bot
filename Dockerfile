FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install "python-telegram-bot[job-queue]"

COPY . .

CMD ["python", "bot.py"]

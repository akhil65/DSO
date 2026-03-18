FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

ENV OLLAMA_BASE=http://ollama:11434
ENV OLLAMA_MODEL=llama3.2:1b
ENV MOCK_MODE=false

EXPOSE 5000

CMD ["python", "app.py"]

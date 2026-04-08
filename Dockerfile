FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dpc_to_nac.py .
COPY templates/ templates/

EXPOSE 5001

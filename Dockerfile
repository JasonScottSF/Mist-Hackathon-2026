FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dpc_to_nac.py .
COPY templates/ templates/

EXPOSE 5001

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5001/login')" || exit 1

# Single worker + threads keeps the in-memory _sessions dict coherent.
# Raise -w only if you move session state to Redis/DB.
CMD ["gunicorn", "-b", "0.0.0.0:5001", "-w", "1", "--threads", "4", "--timeout", "60", "dpc_to_nac:app"]

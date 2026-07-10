FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml requirements.lock ./
RUN pip install --no-cache-dir --constraint requirements.lock .

COPY tracehawk_api ./tracehawk_api

EXPOSE 8000
CMD ["uvicorn", "tracehawk_api.main:app", "--host", "0.0.0.0", "--port", "8000"]

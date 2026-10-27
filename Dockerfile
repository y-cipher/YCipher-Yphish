FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --create-home --uid 10001 app \
    && mkdir -p /app/private_artifacts \
    && mkdir -p /app/model_artifacts \
    && mkdir -p /app/staticfiles \
    && chown app:app /app/private_artifacts /app/model_artifacts /app/staticfiles \
    && chmod 700 /app/private_artifacts /app/model_artifacts

EXPOSE 8000
USER app
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

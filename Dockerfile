FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --create-home grantly && mkdir /data && chown grantly /data
USER grantly
ENV UPLOAD_DIR=/data/uploads
CMD ["sh", "-c", "alembic -c alembic.ini upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]

FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOST=0.0.0.0 PORT=10000 MIS_BIND_ALL=1
COPY . .
RUN mkdir -p data uploads data/backups data/pdf_cache
EXPOSE 10000
CMD ["python", "server.py"]
